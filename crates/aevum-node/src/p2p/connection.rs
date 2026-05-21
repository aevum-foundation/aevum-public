use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, create_status, handle_atp_message};
use crate::p2p::noise::AtpCipher;
use crate::p2p::pex::PeerExchange;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::time::Duration;
use std::sync::Arc;
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
    send_cipher: Arc<TokioMutex<AtpCipher>>,
    recv_cipher: Arc<TokioMutex<AtpCipher>>,
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
    pending_outgoing: Vec<Vec<u8>>,
    outgoing_tx: Option<mpsc::Sender<Vec<u8>>>,
    peer_height: u64,
    last_alive: Instant,
}

impl AtpConnection {
    pub fn new(cipher: AtpCipher, peer_id: [u8; 20], addr: SocketAddr, peers: Arc<PeersManager>, ctx: Arc<SyncContext>, is_server: bool) -> Self {
        let send_cipher = Arc::new(TokioMutex::new(cipher));
        let recv_secret = send_cipher.try_lock().unwrap().shared_secret_bytes();
        let recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(&recv_secret)));
        tracing::info!("[ATP] new() is_server={}", is_server);
        Self { peer_id, addr, is_server, peers, ctx, state: ConnState::Handshaking,
            stats: PeerStats { connected_at: Some(Instant::now()), ..Default::default() },
            send_cipher, recv_cipher, pending_outgoing: Vec::new(), outgoing_tx: None,
            peer_height: 0, last_alive: Instant::now() }
    }

    fn start_sync(&mut self) {
        let our_height = self.ctx.validator.lock().unwrap().last_block_height();
        tracing::info!("[ATP] start_sync: our={}, peer={}", our_height, self.peer_height);
        let status = create_status(&self.ctx);
        if let Ok(data) = bincode::serialize(&status) { self.pending_outgoing.push(data); }
        let pex_msg = PeerExchange::create_peer_list(&self.peers, 20);
        if let Ok(data) = bincode::serialize(&pex_msg) { self.pending_outgoing.push(data); }
        if self.peer_height > our_height {
            let from = if our_height == 0 { 1 } else { our_height + 1 };
            tracing::info!("[ATP] start_sync: requesting headers {}-{}", from, self.peer_height);
            let req = AtpMessage::HeaderRequest { from, to: self.peer_height };
            if let Ok(data) = bincode::serialize(&req) { self.pending_outgoing.push(data); }
        }
        let dht = &self.ctx.dht;
        let mut node_id = [0u8; 32];
        let hash = blake3::hash(self.addr.to_string().as_bytes());
        node_id.copy_from_slice(&hash.as_bytes()[..32]);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        dht.lock().unwrap().add_or_update(node_id, self.addr, now);
        self.flush();
    }

    fn flush(&mut self) {
        let count = self.pending_outgoing.len();
        tracing::info!("[ATP] flush: {} messages", count);
        if let Some(ref tx) = self.outgoing_tx {
            for data in self.pending_outgoing.drain(..) { let _ = tx.try_send(data); }
        } else { tracing::warn!("[ATP] flush: NO outgoing_tx!"); }
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        tracing::info!("[ATP] run() START is_server={}", self.is_server);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        self.outgoing_tx = Some(tx.clone());
        self.peers.register_peer(self.peer_id, self.addr, self.outgoing_tx.as_ref().unwrap().clone());
        tracing::info!("[ATP] run() channel registered, peer_id={}", hex::encode(&self.peer_id));

        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;

        if self.is_server {
            tracing::info!("[ATP] SERVER: waiting for client status...");
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    tracing::info!("[ATP] SERVER: received {} bytes", encrypted.len());
                    if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                        if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                            tracing::info!("[ATP] SERVER: got {:?}", std::mem::discriminant(&msg));
                            if let AtpMessage::Status { height, .. } = &msg { self.peer_height = *height; tracing::info!("[ATP] SERVER: peer_height={}", height); }
                            let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                            tokio::spawn(async move { tracing::info!("[ATP] SERVER: spawning handle_atp_message"); handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                        } else { tracing::warn!("[ATP] SERVER: deserialize FAILED"); }
                    } else { tracing::warn!("[ATP] SERVER: decrypt FAILED"); }
                }
                Err(e) => { tracing::warn!("[ATP] SERVER: read_msg FAILED: {}", e); return; }
            }
            tracing::info!("[ATP] SERVER: sending status");
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
            tracing::info!("[ATP] SERVER: status sent");
        } else {
            tracing::info!("[ATP] CLIENT: sending status");
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
            tracing::info!("[ATP] CLIENT: status sent, waiting for server status...");
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    tracing::info!("[ATP] CLIENT: received {} bytes", encrypted.len());
                    if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                        if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                            tracing::info!("[ATP] CLIENT: got {:?}", std::mem::discriminant(&msg));
                            if let AtpMessage::Status { height, .. } = &msg { self.peer_height = *height; tracing::info!("[ATP] CLIENT: peer_height={}", height); }
                            let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                            tokio::spawn(async move { tracing::info!("[ATP] CLIENT: spawning handle_atp_message"); handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                        } else { tracing::warn!("[ATP] CLIENT: deserialize FAILED"); }
                    } else { tracing::warn!("[ATP] CLIENT: decrypt FAILED"); }
                }
                Err(e) => { tracing::warn!("[ATP] CLIENT: read_msg FAILED: {}", e); return; }
            }
        }

        tracing::info!("[ATP] Handshake done, calling start_sync");
        self.start_sync();
        self.state = ConnState::Active;

        let writer = Arc::new(TokioMutex::new(writer));
        tracing::info!("[ATP] Entering active loop");

        let kp_writer = writer.clone();
        let kp_send = send_cipher.clone();
        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let ping = AtpMessage::Ping { nonce: rand::random() };
                if let Ok(data) = bincode::serialize(&ping) {
                    let encrypted = kp_send.lock().await.encrypt(&data);
                    let len = (encrypted.len() as u32).to_be_bytes();
                    let mut packet = Vec::with_capacity(4 + encrypted.len());
                    packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
                    let mut w = kp_writer.lock().await;
                    if w.write_all(&packet).await.is_err() { break; }
                    let _ = w.flush().await;
                }
            }
        });

        let sync_tx = tx.clone();
        let sync_ctx = ctx.clone();
        let sync_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let our_h = sync_ctx.validator.lock().unwrap().last_block_height();
                let req = AtpMessage::HeaderRequest { from: our_h + 1, to: our_h + 500 };
                if let Ok(data) = bincode::serialize(&req) { let _ = sync_tx.try_send(data); }
            }
        });

        loop {
            tokio::select! {
                data = rx.recv() => {
                    tracing::info!("[ATP] select! rx.recv() woke up");
                    match data {
                        Some(d) => {
                            let encrypted = send_cipher.lock().await.encrypt(&d);
                            let len = (encrypted.len() as u32).to_be_bytes();
                            let mut packet = Vec::with_capacity(4 + encrypted.len());
                            packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
                            let mut w = writer.lock().await;
                            if w.write_all(&packet).await.is_err() { break; }
                            let _ = w.flush().await;
                        }
                        None => break,
                    }
                }
                result = Self::read_msg(&mut reader) => {
                    tracing::info!("[ATP] select! read_msg() woke up");
                    match result {
                        Ok(encrypted) => {
                            self.last_alive = Instant::now();
                            if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                                if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                    let disc = std::mem::discriminant(&msg);
                                    tracing::info!("[ATP] active loop got {:?}", disc);
                                    if let AtpMessage::Status { height, .. } = &msg { self.peer_height = *height; tracing::info!("[ATP] Status update: peer_height={}", height); }
                                    if let AtpMessage::BlockResponse { blocks, .. } = &msg { tracing::info!("[ATP] BlockResponse: {} blocks", blocks.len()); }
                                    if let AtpMessage::HeaderResponse { headers } = &msg { tracing::info!("[ATP] HeaderResponse: {} headers", headers.len()); }
                                    if let AtpMessage::Pong { .. } = &msg { continue; }
                                    if let AtpMessage::Ping { nonce } = &msg {
                                        let pong = AtpMessage::Pong { nonce: *nonce };
                                        if let Ok(data) = bincode::serialize(&pong) { let _ = tx.try_send(data); }
                                        continue;
                                    }
                                    if let AtpMessage::PeerList { ref addrs } = msg {
                                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                        PeerExchange::process_peer_list(addrs, &peers, now);
                                    }
                                    tracing::info!("[ATP] calling handle_atp_message for {:?}", disc);
                                    handle_atp_message(msg, &ctx, &peer_id, &peers);
                                } else { tracing::warn!("[ATP] deserialize FAILED in active loop"); }
                            } else { tracing::warn!("[ATP] decrypt FAILED in active loop"); }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        keepalive_handle.abort();
        sync_handle.abort();
        self.peers.remove_peer(&peer_id);
        tracing::info!("[ATP] Disconnected: {}", hex::encode(&peer_id));
    }

    async fn send_status(send_cipher: &Arc<TokioMutex<AtpCipher>>, ctx: &Arc<SyncContext>, writer: &mut WriteHalf<TcpStream>, _peer_id: &[u8; 20]) {
        let ctx2 = ctx.clone();
        let my_status = tokio::task::spawn_blocking(move || create_status(&ctx2)).await.unwrap();
        let data = bincode::serialize(&my_status).unwrap_or_default();
        let encrypted = send_cipher.lock().await.encrypt(&data);
        let len = (encrypted.len() as u32).to_be_bytes();
        let mut packet = Vec::with_capacity(4 + encrypted.len());
        packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
        let _ = writer.write_all(&packet).await; let _ = writer.flush().await;
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
