use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, create_status, handle_atp_message};
use crate::p2p::noise::AtpCipher;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState { Handshaking, Active, Dead }

#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub connected_at: Option<Instant>,
    pub messages_sent: u64, pub messages_received: u64,
    pub bytes_sent: u64, pub bytes_received: u64,
    pub score: i32,
}

pub struct AtpConnection {
    pub peer_id: [u8; 20], pub addr: SocketAddr,
    pub state: ConnState, pub stats: PeerStats,
    is_server: bool,
    send_cipher: Arc<StdMutex<AtpCipher>>,
    recv_cipher: Arc<StdMutex<AtpCipher>>,
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
}

impl AtpConnection {
    pub fn new(
        cipher: AtpCipher, peer_id: [u8; 20],
        addr: SocketAddr, peers: Arc<PeersManager>, ctx: Arc<SyncContext>, is_server: bool,
    ) -> Self {
        let send_cipher = Arc::new(StdMutex::new(cipher));
        let recv_secret = send_cipher.lock().unwrap().shared_secret_bytes();
        let recv_cipher = Arc::new(StdMutex::new(AtpCipher::new(&recv_secret)));
        Self {
            peer_id, addr, is_server, peers, ctx,
            state: ConnState::Handshaking,
            stats: PeerStats { connected_at: Some(Instant::now()), ..Default::default() },
            send_cipher, recv_cipher,
        }
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        tracing::info!("[ATP] run() START — is_server={}", self.is_server);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        self.peers.register_peer(self.peer_id, self.addr, tx);

        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;
        let is_server = self.is_server;

        // HANDSHAKE
        if is_server {
            tracing::info!("[ATP] SERVER: waiting for client status...");
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    tracing::info!("[ATP] SERVER: read_msg OK ({} bytes)", encrypted.len());
                    match recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        Some(p) => {
                            tracing::info!("[ATP] SERVER: decrypt OK ({} bytes)", p.len());
                            match bincode::deserialize::<AtpMessage>(&p) {
                                Ok(msg) => {
                                    tracing::info!("[ATP] SERVER: deserialize OK");
                                    tracing::info!("📊 Peer status received from {}", hex::encode(&peer_id));
                                    let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                                    tokio::spawn(async move { handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                                }
                                Err(e) => tracing::warn!("[ATP] SERVER: deserialize FAILED: {}", e),
                            }
                        }
                        None => tracing::warn!("[ATP] SERVER: decrypt FAILED (returned None)"),
                    }
                }
                Err(e) => tracing::warn!("[ATP] SERVER: read_msg FAILED: {}", e),
            }
            tracing::info!("[ATP] SERVER: sending status...");
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
        } else {
            tracing::info!("[ATP] CLIENT: sending status...");
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
            tracing::info!("[ATP] CLIENT: waiting for server status...");
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    tracing::info!("[ATP] CLIENT: read_msg OK ({} bytes)", encrypted.len());
                    match recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        Some(p) => {
                            tracing::info!("[ATP] CLIENT: decrypt OK ({} bytes)", p.len());
                            match bincode::deserialize::<AtpMessage>(&p) {
                                Ok(msg) => {
                                    tracing::info!("[ATP] CLIENT: deserialize OK");
                                    tracing::info!("📊 Peer status received from {}", hex::encode(&peer_id));
                                    let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                                    tokio::spawn(async move { handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                                }
                                Err(e) => tracing::warn!("[ATP] CLIENT: deserialize FAILED: {}", e),
                            }
                        }
                        None => tracing::warn!("[ATP] CLIENT: decrypt FAILED (returned None)"),
                    }
                }
                Err(e) => tracing::warn!("[ATP] CLIENT: read_msg FAILED: {}", e),
            }
        }

        tracing::info!("[ATP] Handshake done, entering active loop");

        // ACTIVE LOOP
        loop {
            tokio::select! {
                data = rx.recv() => {
                    match data {
                        Some(d) => {
                            let encrypted = send_cipher.lock().unwrap().encrypt(&d);
                            let len = (encrypted.len() as u32).to_be_bytes();
                            let mut packet = Vec::with_capacity(4 + encrypted.len());
                            packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
                            if writer.write_all(&packet).await.is_err() { tracing::warn!("[ATP] write_all failed"); break; }
                            let _ = writer.flush().await;
                        }
                        None => { tracing::info!("[ATP] rx closed"); break; }
                    }
                }
                result = Self::read_msg(&mut reader) => {
                    match result {
                        Ok(encrypted) => {
                            match recv_cipher.lock().unwrap().decrypt(&encrypted) {
                                Some(plaintext) => {
                                    if let Ok(msg) = bincode::deserialize::<AtpMessage>(&plaintext) {
                                        handle_atp_message(msg, &ctx, &peer_id, &peers);
                                    }
                                }
                                None => tracing::warn!("[ATP] active decrypt failed"),
                            }
                        }
                        Err(e) => { tracing::warn!("[ATP] active read_msg failed: {}", e); break; }
                    }
                }
            }
        }

        self.peers.remove_peer(&peer_id);
        tracing::info!("❌ Disconnected from {}", hex::encode(&peer_id));
    }

    async fn send_status(
        send_cipher: &Arc<StdMutex<AtpCipher>>, ctx: &Arc<SyncContext>,
        writer: &mut WriteHalf<TcpStream>, peer_id: &[u8; 20],
    ) -> bool {
        let ctx2 = ctx.clone();
        let my_status = match tokio::task::spawn_blocking(move || create_status(&ctx2)).await {
            Ok(s) => s, Err(e) => { tracing::warn!("create_status: {}", e); return false; }
        };
        let data = match bincode::serialize(&my_status) {
            Ok(d) => d, Err(e) => { tracing::warn!("serialize: {}", e); return false; }
        };
        let encrypted = send_cipher.lock().unwrap().encrypt(&data);
        let len = (encrypted.len() as u32).to_be_bytes();
        let mut packet = Vec::with_capacity(4 + encrypted.len());
        packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
        if writer.write_all(&packet).await.is_err() {
            tracing::warn!("write_all failed for {}", hex::encode(peer_id)); return false;
        }
        if writer.flush().await.is_err() {
            tracing::warn!("flush failed for {}", hex::encode(peer_id)); return false;
        }
        tracing::info!("📤 Status sent to {}", hex::encode(peer_id));
        true
    }

    async fn read_msg(reader: &mut ReadHalf<TcpStream>) -> Result<Vec<u8>, std::io::Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        tracing::info!("[ATP] read_msg: len={}", len);
        if len > 10 * 1024 * 1024 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too large")); }
        let mut encrypted = vec![0u8; len];
        reader.read_exact(&mut encrypted).await?;
        Ok(encrypted)
    }
}
