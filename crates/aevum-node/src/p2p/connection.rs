use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, SyncPhase, create_status, handle_atp_message, BlockHeader};
use crate::p2p::noise::AtpCipher;
use crate::p2p::pex::PeerExchange;
use crate::p2p::snapshot_cipher::SnapshotCipher;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as TokioMutex, Notify};
use tokio::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use std::net::SocketAddr;

const MAX_SOLO_CHAIN_BLOCKS: usize = 1000;
const MAX_HEADERS_PER_REQUEST: u64 = 2000;
const HANDSHAKE_MAX_SIZE: usize = 1024;
const SNAPSHOT_RATE_LIMIT_SECS: u64 = 60;
const PONG_TIMEOUT_SECS: u64 = 90;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState { Handshaking, Active, Dead }

#[derive(Debug)]
pub struct ConnectionHealth {
    pub last_pong: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub score: i32,
}

pub struct AtpConnection {
    pub peer_id: [u8; 20],
    pub addr: SocketAddr,
    pub state: ConnState,
    is_server: bool,
    send_cipher: Arc<TokioMutex<AtpCipher>>,
    recv_cipher: Arc<TokioMutex<AtpCipher>>,
    snap: Arc<SnapshotCipher>,
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
    outgoing_tx: Option<mpsc::Sender<Vec<u8>>>,
    peer_height: u64,
    last_snapshot_sent: Instant,
    snapshot_requests_in_window: u64,
    health: Arc<TokioMutex<ConnectionHealth>>,
}

impl AtpConnection {
    pub fn new(cipher: AtpCipher, peer_id: [u8; 20], addr: SocketAddr, peers: Arc<PeersManager>, ctx: Arc<SyncContext>, is_server: bool) -> Self {
        let shared_secret = cipher.shared_secret_bytes();
        let send_cipher = Arc::new(TokioMutex::new(cipher));
        let recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(&shared_secret)));
        let snap = Arc::new(SnapshotCipher::new(&shared_secret));
        Self {
            peer_id, addr, is_server, peers, ctx,
            state: ConnState::Handshaking,
            send_cipher, recv_cipher, snap,
            outgoing_tx: None, peer_height: 0,
            last_snapshot_sent: Instant::now(), snapshot_requests_in_window: 0,
            health: Arc::new(TokioMutex::new(ConnectionHealth { last_pong: Instant::now(), messages_sent: 0, messages_received: 0, bytes_sent: 0, bytes_received: 0, score: 0 })),
        }
    }

    fn enqueue_msg(&self, msg: &AtpMessage) {
        if let Ok(data) = bincode::serialize(msg) {
            if let Some(ref tx) = self.outgoing_tx {
                match tx.try_send(data) {
                    Ok(_) => {},
                    Err(e) => tracing::warn!("[CONN] enqueue_msg FAILED: {:?}", e),
                }
            }
        }
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        tracing::info!("[CONN] START peer={} server={}", hex::encode(&self.peer_id), self.is_server);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(65536);
        self.outgoing_tx = Some(tx.clone());
        self.peers.register_peer(self.peer_id, self.addr, tx, !self.is_server);

        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;
        let health = self.health.clone();
        let shutdown_signal = Arc::new(Notify::new());
        let shutdown_signal_kp = shutdown_signal.clone();

        // HANDSHAKE
        if self.is_server {
            if let Ok(encrypted) = Self::read_handshake_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                    }
                }
            } else { self.peers.remove_peer(&peer_id); return; }
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
        } else {
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
            if let Ok(encrypted) = Self::read_handshake_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                    }
                }
            } else { self.peers.remove_peer(&peer_id); return; }
        }

        tracing::info!("[CONN] Handshake done. our_h={} peer_h={}", ctx.validator.lock().unwrap().last_block_height(), self.peer_height);

        let pex_msg = PeerExchange::create_peer_list(&self.peers, 20);
        self.enqueue_msg(&pex_msg);

        let mut node_id = [0u8; 32];
        let hash = blake3::hash(self.addr.to_string().as_bytes());
        node_id.copy_from_slice(&hash.as_bytes()[..32]);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        { ctx.dht.lock().unwrap().add_or_update(node_id, self.addr, now); }

        let peer_status = AtpMessage::Status { height: self.peer_height, poh_tick: 0, state_root: [0u8; 32], total_supply: 0, version: 1, capabilities: 0x01 };
        handle_atp_message(peer_status, &ctx, &peer_id, &peers);

        self.state = ConnState::Active;
        let writer = Arc::new(TokioMutex::new(writer));

        // Keepalive
        let kp_tx = self.outgoing_tx.clone().unwrap();
        let kp_health = health.clone();
        let kp_peer_id = peer_id;
        let kp_shutdown = shutdown_signal_kp;
        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let elapsed = kp_health.lock().await.last_pong.elapsed();
                if elapsed > Duration::from_secs(PONG_TIMEOUT_SECS) {
                    tracing::warn!("[CONN] Peer {} pong timeout", hex::encode(&kp_peer_id));
                    kp_shutdown.notify_one();
                    break;
                }
                let ping = AtpMessage::Ping { nonce: rand::random() };
                if let Ok(data) = bincode::serialize(&ping) {
                    if kp_tx.try_send(data).is_err() { break; }
                }
            }
        });

        // Main loop
        tracing::info!("[CONN] Main loop START peer={}", hex::encode(&peer_id));
        loop {
            tokio::select! {
                _ = shutdown_signal.notified() => {
                    tracing::info!("[CONN] Shutdown signal");
                    break;
                }
                data = rx.recv() => {
                    match data {
                        Some(d) => {
                            let len = d.len();
                            let encrypted = send_cipher.lock().await.encrypt(&d);
                            let pkt_len = (encrypted.len() as u32).to_be_bytes();
                            let mut packet = Vec::with_capacity(4 + encrypted.len());
                            packet.extend_from_slice(&pkt_len); packet.extend_from_slice(&encrypted);
                            let mut w = writer.lock().await;
                            if w.write_all(&packet).await.is_err() { break; }
                            let _ = w.flush().await;
                            health.lock().await.messages_sent += 1;
                            health.lock().await.bytes_sent += len as u64;
                        }
                        None => break,
                    }
                }
                result = Self::read_msg(&mut reader) => {
                    match result {
                        Ok((encrypted, raw_len)) => {
                            if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                                if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                    health.lock().await.messages_received += 1;
                                    health.lock().await.bytes_received += raw_len as u64;
                                    self.process_msg(msg, &ctx, &peers, &peer_id, &writer, &health).await;
                                    continue;
                                }
                            }
                            match self.snap.decrypt_incoming(&encrypted) {
                                Some(p) => {
                                    if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                        health.lock().await.messages_received += 1;
                                        health.lock().await.bytes_received += raw_len as u64;
                                        self.process_msg(msg, &ctx, &peers, &peer_id, &writer, &health).await;
                                        continue;
                                    }
                                }
                                None => {}
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        tracing::info!("[CONN] Main loop END peer={}", hex::encode(&peer_id));
        keepalive_handle.abort();
        self.peers.remove_peer(&peer_id);
    }

    async fn process_msg(
        &mut self, msg: AtpMessage, ctx: &Arc<SyncContext>, peers: &Arc<PeersManager>,
        peer_id: &[u8; 20], writer: &Arc<TokioMutex<WriteHalf<TcpStream>>>,
        health: &Arc<TokioMutex<ConnectionHealth>>,
    ) {
        match &msg {
            AtpMessage::SnapshotRequest => {
                // Rate-limit: макс 1 снапшот в минуту
                let elapsed = self.last_snapshot_sent.elapsed().as_secs();
                if elapsed < SNAPSHOT_RATE_LIMIT_SECS && self.snapshot_requests_in_window >= 1 {
                    tracing::debug!("[CONN] SnapshotRequest rate-limited");
                    return;
                }
                if elapsed >= SNAPSHOT_RATE_LIMIT_SECS {
                    self.snapshot_requests_in_window = 0;
                }
                self.last_snapshot_sent = Instant::now();
                self.snapshot_requests_in_window += 1;

                let snap = Arc::clone(&self.snap);
                let ctx_clone = ctx.clone();
                let writer_clone = writer.clone();
                let peer_id_copy = *peer_id;
                let health_clone = health.clone();
                // Отправка снапшота в отдельном таске — не блокирует главный цикл
                tokio::spawn(async move {
                    let (height, utxo_data, block_hash, state_root) = {
                        let val = ctx_clone.validator.lock().unwrap();
                        let utxo = val.utxo_set();
                        (val.last_block_height(), bincode::serialize(&utxo.clone()).unwrap_or_default(), val.last_block_hash().0, utxo.get_state_root().0)
                    };
                    tracing::info!("[CONN] Sending SnapshotResponse h={} to {}", height, hex::encode(&peer_id_copy[..8]));
                    let mut w = writer_clone.lock().await;
                    match snap.send_snapshot_response(&mut *w, height, utxo_data, block_hash, state_root).await {
                        Ok(_) => {
                            tracing::info!("[CONN] SnapshotResponse SENT h={}", height);
                            health_clone.lock().await.messages_sent += 1;
                        }
                        Err(e) => tracing::warn!("[CONN] SnapshotResponse failed: {}", e),
                    }
                });
            }
            AtpMessage::SnapshotResponse { .. } => {
                handle_atp_message(msg, ctx, peer_id, peers);
            }
            AtpMessage::Status { height, .. } => {
                self.peer_height = *height;
                peers.update_peer_height(peer_id, *height);
                handle_atp_message(msg, ctx, peer_id, peers);
            }
            AtpMessage::Pong { .. } => {
                health.lock().await.last_pong = Instant::now();
            }
            AtpMessage::Ping { nonce } => {
                self.enqueue_msg(&AtpMessage::Pong { nonce: *nonce });
            }
            AtpMessage::PeerList { ref addrs } => {
                let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                PeerExchange::process_peer_list(addrs, peers, n);
            }
            AtpMessage::HeaderRequest { from, to } => self.handle_header_request(ctx, *from, *to),
            _ => {
                handle_atp_message(msg, ctx, peer_id, peers);
            }
        }
    }

    fn handle_header_request(&self, ctx: &Arc<SyncContext>, from: u64, to: u64) {
        let actual_to = to.min(from + MAX_HEADERS_PER_REQUEST);
        let resp = {
            let st = ctx.storage.lock().unwrap();
            let mut headers = Vec::new();
            for h in from..=actual_to {
                if let Ok(Some(block)) = st.load_genesis_block(h) {
                    headers.push(BlockHeader {
                        height: block.height, block_hash: block.block_hash.0,
                        prev_hash: block.prev_hash.0, poh_tick_start: block.poh_tick_start,
                        poh_tick_end: block.poh_tick_end, state_root: block.state_root.0,
                        total_supply: block.total_supply,
                    });
                }
            }
            drop(st);
            AtpMessage::HeaderResponse { headers }
        };
        self.enqueue_msg(&resp);
    }

    async fn send_msg(send_cipher: &Arc<TokioMutex<AtpCipher>>, msg: &AtpMessage, writer: &mut WriteHalf<TcpStream>) {
        let data = bincode::serialize(msg).unwrap_or_default();
        let encrypted = send_cipher.lock().await.encrypt(&data);
        let len = (encrypted.len() as u32).to_be_bytes();
        let mut packet = Vec::with_capacity(4 + encrypted.len());
        packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
        let _ = writer.write_all(&packet).await;
        let _ = writer.flush().await;
    }

    async fn read_handshake_msg(reader: &mut ReadHalf<TcpStream>) -> Result<Vec<u8>, std::io::Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > HANDSHAKE_MAX_SIZE {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "handshake too large"));
        }
        let mut encrypted = vec![0u8; len];
        reader.read_exact(&mut encrypted).await?;
        Ok(encrypted)
    }

    async fn read_msg(reader: &mut ReadHalf<TcpStream>) -> Result<(Vec<u8>, usize), std::io::Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 10 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too large"));
        }
        let mut encrypted = vec![0u8; len];
        reader.read_exact(&mut encrypted).await?;
        Ok((encrypted, len))
    }
}
