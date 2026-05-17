use aevum::core::block::Block;
use aevum::core::transaction::Transaction;
use crate::mempool::Mempool;
use crate::storage::Storage;
use crate::sync::ChainSync;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, handle_atp_message};
use crate::p2p::noise::NoiseCipher;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn handle_connection(
    stream: TcpStream,
    cipher: Arc<StdMutex<NoiseCipher>>,
    rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    peer_id: [u8; 20],
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let cipher_send = cipher.clone();
    let cipher_recv = cipher.clone();

    let mut rx = rx;
    let send_handle = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            let encrypted = cipher_send.lock().unwrap().encrypt(&data);
            let len = (encrypted.len() as u32).to_be_bytes();
            if writer.write_all(&len).await.is_err() { break; }
            if writer.write_all(&encrypted).await.is_err() { break; }
        }
    });

    let recv_peers = peers.clone();
    let recv_ctx = ctx.clone();
    let recv_handle = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            if reader.read_exact(&mut len_buf).await.is_err() { break; }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 10 * 1024 * 1024 { break; }
            let mut encrypted = vec![0u8; len];
            if reader.read_exact(&mut encrypted).await.is_err() { break; }
            if let Some(plaintext) = cipher_recv.lock().unwrap().decrypt(&encrypted) {
                if let Ok(msg) = bincode::deserialize::<AtpMessage>(&plaintext) {
                    handle_atp_message(msg, &recv_ctx, &peer_id, &recv_peers);
                }
            }
        }
    });

    let _ = tokio::join!(send_handle, recv_handle);
    peers.remove_peer(&peer_id);
    tracing::info!("Disconnected from {}", hex::encode(&peer_id));
}
