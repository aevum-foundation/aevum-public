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
    /// Буфер исходящих до полной готовности
    pending_outgoing: Vec<Vec<u8>>,
    /// Пир прислал ReadySignal?
    peer_ready: bool,
    /// Мы отправили ReadySignal?
    we_sent_ready: bool,
    /// Канал отправки (заполняется в run)
    outgoing_tx: Option<mpsc::Sender<Vec<u8>>>,
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
            pending_outgoing: Vec::new(),
            peer_ready: false,
            we_sent_ready: false,
            outgoing_tx: None,
        }
    }

    /// Отправить или буферизовать (Thread-safe через outgoing_tx)
    pub fn send_or_buffer(&mut self, data: Vec<u8>) {
        if self.peer_ready && self.we_sent_ready {
            if let Some(ref tx) = self.outgoing_tx {
                let _ = tx.try_send(data);
                return;
            }
        }
        self.pending_outgoing.push(data);
    }

    /// Пир прислал ReadySignal — разблокируем буфер
    pub fn on_peer_ready(&mut self) {
        self.peer_ready = true;
        self.flush_buffer();
    }

    /// Отправляем ReadySignal пиру
    pub fn send_ready_signal(&mut self) {
        self.we_sent_ready = true;
        if let Some(ref tx) = self.outgoing_tx {
            if let Ok(data) = bincode::serialize(&AtpMessage::ReadySignal) {
                let _ = tx.try_send(data);
            }
        }
        self.flush_buffer();
    }

    fn flush_buffer(&mut self) {
        if self.peer_ready && self.we_sent_ready {
            if let Some(ref tx) = self.outgoing_tx {
                for data in self.pending_outgoing.drain(..) {
                    let _ = tx.try_send(data);
                }
            }
        }
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        tracing::info!("[ATP] run() START — is_server={}", self.is_server);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        self.outgoing_tx = Some(tx.clone());
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
                    match recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        Some(p) => {
                            if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                                tokio::spawn(async move { handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                            }
                        }
                        None => tracing::warn!("[ATP] SERVER: decrypt FAILED"),
                    }
                }
                Err(e) => tracing::warn!("[ATP] SERVER: read_msg FAILED: {}", e),
            }
            tracing::info!("[ATP] SERVER: sending status + ReadySignal");
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
            // Отправляем ReadySignal после статуса
            // Отправляем ReadySignal напрямую в writer
            let ready_data = bincode::serialize(&AtpMessage::ReadySignal).unwrap_or_default();
            let encrypted = send_cipher.lock().unwrap().encrypt(&ready_data);
            let len = (encrypted.len() as u32).to_be_bytes();
            let mut packet = Vec::with_capacity(4 + encrypted.len());
            packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
            let _ = writer.write_all(&packet).await;
            let _ = writer.flush().await;
            tracing::info!("[ATP] ReadySignal sent directly");
            self.we_sent_ready = true;
        } else {
            tracing::info!("[ATP] CLIENT: sending status + ReadySignal");
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
            // Отправляем ReadySignal напрямую в writer
            let ready_data = bincode::serialize(&AtpMessage::ReadySignal).unwrap_or_default();
            let encrypted = send_cipher.lock().unwrap().encrypt(&ready_data);
            let len = (encrypted.len() as u32).to_be_bytes();
            let mut packet = Vec::with_capacity(4 + encrypted.len());
            packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
            let _ = writer.write_all(&packet).await;
            let _ = writer.flush().await;
            tracing::info!("[ATP] ReadySignal sent directly");
            self.we_sent_ready = true;
            tracing::info!("[ATP] CLIENT: waiting for server status...");
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    match recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        Some(p) => {
                            if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                                tokio::spawn(async move { handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                            }
                        }
                        None => tracing::warn!("[ATP] CLIENT: decrypt FAILED"),
                    }
                }
                Err(e) => tracing::warn!("[ATP] CLIENT: read_msg FAILED: {}", e),
            }
        }

        // Ждём ReadySignal от пира (если ещё не получили)
        if !self.peer_ready {
            tracing::info!("[ATP] Waiting for peer ReadySignal...");
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    if let Some(p) = recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        if let Ok(AtpMessage::ReadySignal) = bincode::deserialize(&p) {
                            tracing::info!("[ATP] Peer ReadySignal received");
                            self.on_peer_ready();
                        }
                    }
                }
                Err(e) => tracing::warn!("[ATP] ReadySignal wait failed: {}", e),
            }
        }

        tracing::info!("[ATP] Handshake done, entering active loop");
        // Запрашиваем список пиров у соседа (PEX)

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
                                        if matches!(msg, AtpMessage::ReadySignal) {
                                            tracing::info!("[ATP] ReadySignal in active loop");
                                            self.on_peer_ready();
                                        } else {
                                            handle_atp_message(msg, &ctx, &peer_id, &peers);
                                        }
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
        if writer.write_all(&packet).await.is_err() { return false; }
        if writer.flush().await.is_err() { return false; }
        tracing::info!("📤 Status sent to {}", hex::encode(peer_id));
        true
    }

    async fn read_msg(reader: &mut ReadHalf<TcpStream>) -> Result<Vec<u8>, std::io::Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 10 * 1024 * 1024 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too large")); }
        let mut encrypted = vec![0u8; len];
        reader.read_exact(&mut encrypted).await?;
        Ok(encrypted)
    }
}
