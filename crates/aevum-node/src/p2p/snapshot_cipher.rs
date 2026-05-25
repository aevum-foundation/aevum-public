use crate::p2p::noise::AtpCipher;
use crate::p2p::sync::AtpMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

pub struct SnapshotCipher {
    send_cipher: Arc<TokioMutex<AtpCipher>>,
    pub(crate) recv_cipher: Arc<TokioMutex<AtpCipher>>,
}

impl SnapshotCipher {
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let send_cipher = Arc::new(TokioMutex::new(AtpCipher::new(shared_secret)));
        let recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(shared_secret)));
        Self { send_cipher, recv_cipher }
    }

    /// Получить SnapshotResponse (клиентская сторона)
    pub async fn receive_response(
        &self,
        reader: &mut ReadHalf<TcpStream>,
    ) -> Result<(u64, Vec<u8>, [u8; 32]), String> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await.map_err(|e| format!("read len: {}", e))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 100 * 1024 * 1024 { return Err("too large".into()); }
        let mut encrypted = vec![0u8; len];
        reader.read_exact(&mut encrypted).await.map_err(|e| format!("read body: {}", e))?;
        let plain = self.recv_cipher.lock().await.decrypt(&encrypted).ok_or("decrypt failed")?;
        let msg: AtpMessage = bincode::deserialize(&plain).map_err(|e| format!("deser: {:?}", e))?;
        match msg {
            AtpMessage::SnapshotResponse { height, utxo_data, block_hash } => {
                tracing::info!("[SNAPSHOT] SnapshotResponse received: h={}", height);
                Ok((height, utxo_data, block_hash))
            }
            other => Err(format!("Expected SnapshotResponse, got {:?}", std::mem::discriminant(&other))),
        }
    }

    /// Отправить SnapshotResponse (серверная сторона)
    pub async fn send_snapshot_response(
        &self,
        writer: &mut WriteHalf<TcpStream>,
        height: u64,
        utxo_data: Vec<u8>,
        block_hash: [u8; 32],
    ) -> Result<(), String> {
        let resp = AtpMessage::SnapshotResponse { height, utxo_data, block_hash };
        let data = bincode::serialize(&resp).map_err(|e| format!("ser: {:?}", e))?;
        let encrypted = self.send_cipher.lock().await.encrypt(&data);
        let len = (encrypted.len() as u32).to_be_bytes();
        let mut packet = Vec::with_capacity(4 + encrypted.len());
        packet.extend_from_slice(&len);
        packet.extend_from_slice(&encrypted);
        writer.write_all(&packet).await.map_err(|e| format!("write: {}", e))?;
        writer.flush().await.map_err(|e| format!("flush: {}", e))?;
        tracing::info!("[SNAPSHOT] SnapshotResponse sent");
        Ok(())
    }
}
