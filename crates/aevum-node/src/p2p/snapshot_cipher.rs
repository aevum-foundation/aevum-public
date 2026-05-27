use tokio::net::TcpStream;
use crate::p2p::noise::AtpCipher;
use crate::p2p::sync::AtpMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::Mutex as TokioMutex;
use tokio::sync::Semaphore;

const SNAPSHOT_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SNAPSHOT_SIZE: usize = 10 * 1024 * 1024; // 10 MB — достаточно для UTXO-сета
const MAX_CONCURRENT_RECV: usize = 8; // Ограничение одновременных приёмов

static SNAPSHOT_SENT_COUNT: AtomicU64 = AtomicU64::new(0);
static SNAPSHOT_RECEIVED_COUNT: AtomicU64 = AtomicU64::new(0);
static SNAPSHOT_REJECTED_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn snapshot_metrics() -> (u64, u64, u64) {
    (SNAPSHOT_SENT_COUNT.load(Ordering::Relaxed),
     SNAPSHOT_RECEIVED_COUNT.load(Ordering::Relaxed),
     SNAPSHOT_REJECTED_COUNT.load(Ordering::Relaxed))
}

// Глобальный семафор для ограничения одновременных приёмов
static RECV_SEMAPHORE: Semaphore = Semaphore::const_new(MAX_CONCURRENT_RECV);

/// Шифрованный канал для передачи снапшотов.
/// Использует РАЗДЕЛЬНЫЕ send/recv cipher с независимыми nonce.
pub struct SnapshotCipher {
    send_cipher: Arc<TokioMutex<AtpCipher>>,
    recv_cipher: Arc<TokioMutex<AtpCipher>>,
    session_id: u64,
}

impl SnapshotCipher {
    /// Создать с раздельными send/recv состояниями (БЕЗОПАСНО)
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        // Два НЕЗАВИСИМЫХ объекта AtpCipher — никакого разделения nonce
        let send_cipher = Arc::new(TokioMutex::new(AtpCipher::new(shared_secret)));
        let recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(shared_secret)));
        Self { send_cipher, recv_cipher, session_id: rand::random() }
    }

    /// Создать с РАЗДЕЛЬНЫМИ send/recv из одного ключа (атомарно)
    /// send_cipher и recv_cipher — клоны Arc, но указывают на РАЗНЫЕ объекты внутри
    pub fn new_with_ciphers(
        send_cipher: Arc<TokioMutex<AtpCipher>>,
        recv_cipher: Arc<TokioMutex<AtpCipher>>,
    ) -> Self {
        Self { send_cipher, recv_cipher, session_id: rand::random() }
    }

    pub fn recv_cipher_clone(&self) -> Arc<TokioMutex<AtpCipher>> {
        self.recv_cipher.clone()
    }

    /// Отправить зашифрованное сообщение
    async fn send_encrypted(&self, writer: &mut WriteHalf<TcpStream>, msg: &AtpMessage) -> Result<(), String> {
        let data = bincode::serialize(msg).map_err(|e| format!("ser: {:?}", e))?;
        let data_len = data.len();

        // Шифруем
        let encrypted = {
            let encrypted = self.send_cipher.lock().await.encrypt(&data);
            drop(data); // Освобождаем память после сериализации
            encrypted
        };

        let len = (encrypted.len() as u32).to_be_bytes();
        let mut packet = Vec::with_capacity(4 + encrypted.len());
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted);

        timeout(SNAPSHOT_IO_TIMEOUT, writer.write_all(&packet))
            .await.map_err(|_| "write timeout".to_string())?
            .map_err(|e| format!("write: {}", e))?;
        timeout(SNAPSHOT_IO_TIMEOUT, writer.flush())
            .await.map_err(|_| "flush timeout".to_string())?
            .map_err(|e| format!("flush: {}", e))?;

        SNAPSHOT_SENT_COUNT.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("[SNAPSHOT] Sent {} bytes (raw={}), session={}", encrypted.len(), data_len, self.session_id);
        Ok(())
    }

    /// Принять и расшифровать сообщение
    async fn recv_encrypted(&self, reader: &mut ReadHalf<TcpStream>) -> Result<AtpMessage, String> {
        // Захватываем семафор — ограничиваем одновременные приёмы
        let _permit = RECV_SEMAPHORE.acquire().await.map_err(|_| "recv semaphore closed".to_string())?;

        let mut len_buf = [0u8; 4];
        timeout(SNAPSHOT_IO_TIMEOUT, reader.read_exact(&mut len_buf))
            .await.map_err(|_| "read len timeout".to_string())?
            .map_err(|e| format!("read len: {}", e))?;

        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 {
            SNAPSHOT_REJECTED_COUNT.fetch_add(1, Ordering::Relaxed);
            return Err("zero-length snapshot".into());
        }
        if len > MAX_SNAPSHOT_SIZE {
            SNAPSHOT_REJECTED_COUNT.fetch_add(1, Ordering::Relaxed);
            return Err(format!("snapshot too large: {} > {}", len, MAX_SNAPSHOT_SIZE));
        }

        let mut encrypted = vec![0u8; len];
        timeout(SNAPSHOT_IO_TIMEOUT, reader.read_exact(&mut encrypted))
            .await.map_err(|_| "read body timeout".to_string())?
            .map_err(|e| format!("read body: {}", e))?;

        // Расшифровываем
        let plain = self.recv_cipher.lock().await.decrypt(&encrypted)
            .ok_or_else(|| {
                SNAPSHOT_REJECTED_COUNT.fetch_add(1, Ordering::Relaxed);
                "decrypt failed".to_string()
            })?;
        drop(encrypted); // Освобождаем память

        // Десериализуем
        let msg: AtpMessage = bincode::deserialize(&plain)
            .map_err(|e| {
                SNAPSHOT_REJECTED_COUNT.fetch_add(1, Ordering::Relaxed);
                format!("deser: {:?}", e)
            })?;
        drop(plain);

        // Проверяем тип сразу — только SnapshotResponse допустим
        if !matches!(msg, AtpMessage::SnapshotResponse { .. }) {
            SNAPSHOT_REJECTED_COUNT.fetch_add(1, Ordering::Relaxed);
            return Err(format!("unexpected message type: {:?}", std::mem::discriminant(&msg)));
        }

        SNAPSHOT_RECEIVED_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(msg)
    }

    /// Получить SnapshotResponse (клиентская сторона)
    pub async fn receive_response(&self, reader: &mut ReadHalf<TcpStream>) -> Result<(u64, Vec<u8>, [u8; 32], [u8; 32]), String> {
        let msg = self.recv_encrypted(reader).await?;
        match msg {
            AtpMessage::SnapshotResponse { height, utxo_data, block_hash, state_root } => {
                tracing::info!("[SNAPSHOT] SnapshotResponse received: h={}, session={}", height, self.session_id);
                Ok((height, utxo_data, block_hash, state_root))
            }
            _ => unreachable!(), // Уже проверено в recv_encrypted
        }
    }

    /// Отправить SnapshotResponse (серверная сторона)
    pub async fn send_snapshot_response(
        &self,
        writer: &mut WriteHalf<TcpStream>,
        height: u64,
        utxo_data: Vec<u8>,
        block_hash: [u8; 32],
        state_root: [u8; 32],
    ) -> Result<(), String> {
        let resp = AtpMessage::SnapshotResponse { height, utxo_data, block_hash, state_root };
        self.send_encrypted(writer, &resp).await
    }
}
