use tokio::net::TcpStream;
use crate::p2p::noise::AtpCipher;
use crate::p2p::sync::AtpMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex as TokioMutex;

const SNAPSHOT_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SNAPSHOT_SIZE: usize = 100 * 1024 * 1024;

static SNAPSHOT_SENT_COUNT: AtomicU64 = AtomicU64::new(0);
static SNAPSHOT_RECEIVED_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn snapshot_metrics() -> (u64, u64) {
    (SNAPSHOT_SENT_COUNT.load(Ordering::Relaxed), SNAPSHOT_RECEIVED_COUNT.load(Ordering::Relaxed))
}

pub struct SnapshotCipher {
    send_cipher: Arc<TokioMutex<AtpCipher>>,
    recv_cipher: Arc<TokioMutex<AtpCipher>>,
    session_id: u64,
}

impl SnapshotCipher {
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let send_cipher = Arc::new(TokioMutex::new(AtpCipher::new(shared_secret)));
        let recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(shared_secret)));
        Self { send_cipher, recv_cipher, session_id: rand::random() }
    }

    pub fn new_with_cipher(cipher: &Arc<TokioMutex<AtpCipher>>) -> Self {
        Self { send_cipher: cipher.clone(), recv_cipher: cipher.clone(), session_id: rand::random() }
    }

    pub fn recv_cipher_clone(&self) -> Arc<TokioMutex<AtpCipher>> {
        self.recv_cipher.clone()
    }

    async fn send_encrypted(&self, writer: &mut WriteHalf<TcpStream>, msg: &AtpMessage) -> Result<(), String> {
        let data = bincode::serialize(msg).map_err(|e| format!("ser: {:?}", e))?;
        let encrypted = self.send_cipher.lock().await.encrypt(&data);
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
        tracing::debug!("[SNAPSHOT] SnapshotResponse sent (session={})", self.session_id);
        Ok(())
    }

    async fn recv_encrypted(&self, reader: &mut ReadHalf<TcpStream>) -> Result<AtpMessage, String> {
        let mut len_buf = [0u8; 4];
        timeout(SNAPSHOT_IO_TIMEOUT, reader.read_exact(&mut len_buf))
            .await.map_err(|_| "read timeout".to_string())?
            .map_err(|e| format!("read len: {}", e))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_SNAPSHOT_SIZE { return Err("snapshot too large".into()); }
        let mut encrypted = vec![0u8; len];
        timeout(SNAPSHOT_IO_TIMEOUT, reader.read_exact(&mut encrypted))
            .await.map_err(|_| "read body timeout".to_string())?
            .map_err(|e| format!("read body: {}", e))?;
        let plain = self.recv_cipher.lock().await.decrypt(&encrypted).ok_or("decrypt failed")?;
        let msg = bincode::deserialize(&plain).map_err(|e| format!("deser: {:?}", e))?;
        SNAPSHOT_RECEIVED_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(msg)
    }

    pub async fn receive_response(&self, reader: &mut ReadHalf<TcpStream>) -> Result<(u64, Vec<u8>, [u8; 32]), String> {
        let msg = self.recv_encrypted(reader).await?;
        match msg {
            AtpMessage::SnapshotResponse { height, utxo_data, block_hash } => {
                tracing::debug!("[SNAPSHOT] SnapshotResponse received: h={}, session={}", height, self.session_id);
                Ok((height, utxo_data, block_hash))
            }
            other => Err(format!("Expected SnapshotResponse, got {:?}", std::mem::discriminant(&other))),
        }
    }

    pub async fn send_snapshot_response(
        &self,
        writer: &mut WriteHalf<TcpStream>,
        height: u64,
        utxo_data: Vec<u8>,
        block_hash: [u8; 32],
    ) -> Result<(), String> {
        let resp = AtpMessage::SnapshotResponse { height, utxo_data, block_hash };
        self.send_encrypted(writer, &resp).await
    }
}
