use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, SyncPhase, create_status, handle_atp_message, BlockHeader};
use crate::p2p::noise::AtpCipher;
use crate::p2p::pex::PeerExchange;
use crate::p2p::snapshot_cipher::SnapshotCipher;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use std::net::SocketAddr;

// ── Константы ────────────────────────────────────────────────
const MAX_SOLO_CHAIN_BLOCKS: usize = 1000;
const MAX_HEADERS_PER_REQUEST: u64 = 2000;
const HANDSHAKE_MAX_SIZE: usize = 1024;
const SNAPSHOT_RATE_LIMIT_SECS: u64 = 5;
const PONG_TIMEOUT_SECS: u64 = 90;
const MAX_INBOUND_MSG_RATE: u64 = 100;
const MIN_SOLO_REQUEST_INTERVAL: Duration = Duration::from_secs(60);

// ── Метрики ──────────────────────────────────────────────────
static METRIC_TOTAL_CONNECTIONS: AtomicU64 = AtomicU64::new(0);
static METRIC_RATE_LIMITED_DROPS: AtomicU64 = AtomicU64::new(0);
static METRIC_PONG_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static METRIC_PEER_ID_MISMATCHES: AtomicU64 = AtomicU64::new(0);

pub fn connection_metrics() -> (u64, u64, u64, u64) {
    (METRIC_TOTAL_CONNECTIONS.load(Ordering::Relaxed),
     METRIC_RATE_LIMITED_DROPS.load(Ordering::Relaxed),
     METRIC_PONG_TIMEOUTS.load(Ordering::Relaxed),
     METRIC_PEER_ID_MISMATCHES.load(Ordering::Relaxed))
}

// ── Структуры ────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct ConnectionHealth {
    pub connected_at: Instant,
    pub last_pong: Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub score: i32,
    msg_count: u64,
    msg_window_start: Instant,
    last_solo_request: Instant,
}

impl Default for ConnectionHealth {
    fn default() -> Self {
        let now = Instant::now();
        Self { connected_at: now, last_pong: now, messages_sent: 0, messages_received: 0,
            bytes_sent: 0, bytes_received: 0, score: 0, msg_count: 0, msg_window_start: now,
            last_solo_request: now - MIN_SOLO_REQUEST_INTERVAL }
    }
}

impl ConnectionHealth {
    fn check_rate(&mut self) -> bool {
        if self.msg_window_start.elapsed() >= Duration::from_secs(1) { self.msg_count = 0; self.msg_window_start = Instant::now(); }
        self.msg_count += 1;
        if self.msg_count > MAX_INBOUND_MSG_RATE { METRIC_RATE_LIMITED_DROPS.fetch_add(1, Ordering::Relaxed); false } else { true }
    }
    fn check_pong_timeout(&self) -> bool {
        let alive = self.last_pong.elapsed().as_secs() < PONG_TIMEOUT_SECS;
        if !alive { METRIC_PONG_TIMEOUTS.fetch_add(1, Ordering::Relaxed); }
        alive
    }
    fn can_request_solo(&mut self) -> bool {
        if self.last_solo_request.elapsed() >= MIN_SOLO_REQUEST_INTERVAL { self.last_solo_request = Instant::now(); true } else { false }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState { Handshaking, Active, Dead }

pub struct AtpConnection {
    pub peer_id: [u8; 20],
    pub addr: SocketAddr,
    pub state: ConnState,
    is_server: bool,
    send_cipher: Arc<TokioMutex<AtpCipher>>,
    recv_cipher: Arc<TokioMutex<AtpCipher>>,
    shared_secret: [u8; 32],
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
    outgoing_tx: Option<mpsc::Sender<Vec<u8>>>,
    peer_height: u64,
    last_snapshot_sent: Instant,
}

impl AtpConnection {
    pub fn verify_peer_id(cipher: &AtpCipher, claimed_peer_id: &[u8; 20]) -> bool {
        let remote_pubkey = cipher.remote_static();
        let computed = blake3::hash(&remote_pubkey);
        let computed_id: [u8; 20] = computed.as_bytes()[..20].try_into().unwrap();
        if computed_id != *claimed_peer_id {
            METRIC_PEER_ID_MISMATCHES.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("[CONN] Peer ID mismatch: claimed={}, computed={}", hex::encode(claimed_peer_id), hex::encode(&computed_id));
            false
        } else { true }
    }

    pub fn new(cipher: AtpCipher, peer_id: [u8; 20], addr: SocketAddr, peers: Arc<PeersManager>, ctx: Arc<SyncContext>, is_server: bool) -> Self {
        tracing::info!("[CONN] new: peer={} addr={} is_server={}", hex::encode(&peer_id), addr, is_server);
        if !Self::verify_peer_id(&cipher, &peer_id) {
            tracing::warn!("[CONN] Peer ID mismatch for {} — rejecting", addr);
        }
        let shared_secret = cipher.shared_secret_bytes();
        let send_cipher = Arc::new(TokioMutex::new(cipher));
        let recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(&shared_secret)));
        METRIC_TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Self {
            peer_id, addr, is_server, peers, ctx,
            state: ConnState::Handshaking,
            send_cipher, recv_cipher, shared_secret,
            outgoing_tx: None, peer_height: 0,
            last_snapshot_sent: Instant::now() - Duration::from_secs(60),
        }
    }

    fn enqueue_msg(&self, msg: &AtpMessage) {
        if let Ok(data) = bincode::serialize(msg) { if let Some(ref tx) = self.outgoing_tx { let _ = tx.try_send(data); } }
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        tracing::info!("[CONN] run START: peer={} addr={}", hex::encode(&self.peer_id), self.addr);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
        self.outgoing_tx = Some(tx.clone());
        self.peers.register_peer(self.peer_id, self.addr, tx);

        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let shared_secret = self.shared_secret;
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;
        let health = Arc::new(TokioMutex::new(ConnectionHealth::default()));

        // ── HANDSHAKE ──────────────────────────────────
        tracing::info!("[CONN] HANDSHAKE START: is_server={}", self.is_server);
        if self.is_server {
            if let Ok(encrypted) = Self::read_handshake_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                        tracing::info!("[CONN] HANDSHAKE server: received Status height={}", height);
                    }
                }
            } else { tracing::warn!("[CONN] HANDSHAKE server: read failed"); return; }
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
            tracing::info!("[CONN] HANDSHAKE server: Status sent");
        } else {
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
            tracing::info!("[CONN] HANDSHAKE client: Status sent, waiting for response");
            if let Ok(encrypted) = Self::read_handshake_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                        tracing::info!("[CONN] HANDSHAKE client: received Status height={}", height);
                    }
                }
            } else { tracing::warn!("[CONN] HANDSHAKE client: read failed"); return; }
        }

        let our_h = { ctx.validator.lock().unwrap().last_block_height() };
        tracing::info!("[CONN] POST-HANDSHAKE: our_h={} peer_h={}", our_h, self.peer_height);

        let pex_msg = PeerExchange::create_peer_list(&self.peers, 20);
        self.enqueue_msg(&pex_msg);

        let mut node_id = [0u8; 32];
        let hash = blake3::hash(self.addr.to_string().as_bytes());
        node_id.copy_from_slice(&hash.as_bytes()[..32]);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        { ctx.dht.lock().unwrap().add_or_update(node_id, self.addr, now); }

        if our_h > 0 && self.peer_height > 0 && self.peer_height < our_h && health.lock().await.can_request_solo() {
            tracing::info!("[CONN] Requesting solo blocks from peer {} (peer_h={}, our_h={})", hex::encode(&peer_id), self.peer_height, our_h);
            let req = AtpMessage::SoloChainRequest;
            if let Ok(data) = bincode::serialize(&req) { let _ = self.outgoing_tx.as_ref().map(|tx| tx.try_send(data)); }
        }

        let peer_status = AtpMessage::Status { height: self.peer_height, poh_tick: 0, state_root: [0u8; 32], total_supply: 0, version: 1, capabilities: 0x01 };
        handle_atp_message(peer_status, &ctx, &peer_id, &peers);

        self.state = ConnState::Active;
        let writer = Arc::new(TokioMutex::new(writer));

        // ── Keepalive ──────────────────────────────────
        let kp_tx = self.outgoing_tx.clone().unwrap();
        let kp_health = health.clone();
        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if !kp_health.lock().await.check_pong_timeout() {
                    tracing::warn!("[CONN] Pong timeout — closing connection");
                    break;
                }
                let ping = AtpMessage::Ping { nonce: rand::random() };
                if let Ok(data) = bincode::serialize(&ping) { if kp_tx.try_send(data).is_err() { break; } }
            }
        });

        // SnapshotCipher для приёма SnapshotResponse (свежий, только для recv)
        let snap_recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(&shared_secret)));

        // ── Главный цикл ──────────────────────────────
        tracing::info!("[CONN] Main loop START");
        loop {
            tokio::select! {
                data = rx.recv() => {
                    match data {
                        Some(d) => {
                            let encrypted = send_cipher.lock().await.encrypt(&d);
                            let len = (encrypted.len() as u32).to_be_bytes();
                            let mut packet = Vec::with_capacity(4 + encrypted.len());
                            packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
                            let mut w = writer.lock().await;
                            if w.write_all(&packet).await.is_err() { break; }
                            let _ = w.flush().await;
                            health.lock().await.messages_sent += 1;
                        }
                        None => break,
                    }
                }
                result = Self::read_msg(&mut reader) => {
                    match result {
                        Ok(encrypted) => {
                            health.lock().await.messages_received += 1;
                            health.lock().await.bytes_received += encrypted.len() as u64;
                            if !health.lock().await.check_rate() {
                                tracing::warn!("[CONN] Rate limit exceeded from {}", self.addr);
                                continue;
                            }
                            if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                                if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                    self.process_message(msg, &ctx, &peers, &peer_id, &writer, &health, &shared_secret).await;
                                    continue;
                                }
                            }
                            if let Some(p) = snap_recv_cipher.lock().await.decrypt(&encrypted) {
                                if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                    tracing::info!("[CONN] Decrypted via SnapshotCipher");
                                    self.process_message(msg, &ctx, &peers, &peer_id, &writer, &health, &shared_secret).await;
                                    continue;
                                }
                            }
                            tracing::warn!("[CONN] decrypt FAILED");
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        tracing::info!("[CONN] Main loop END");
        keepalive_handle.abort();
        self.peers.remove_peer(&peer_id);
    }

    async fn process_message(
        &mut self, msg: AtpMessage, ctx: &Arc<SyncContext>, peers: &Arc<PeersManager>,
        peer_id: &[u8; 20], writer: &Arc<TokioMutex<WriteHalf<TcpStream>>>,
        health: &Arc<TokioMutex<ConnectionHealth>>, shared_secret: &[u8; 32],
    ) {
        match &msg {
            AtpMessage::SnapshotRequest => self.handle_snapshot_request(ctx, writer, shared_secret).await,
            AtpMessage::SnapshotResponse { height, .. } => { tracing::info!("[CONN] SnapshotResponse received h={}", height); handle_atp_message(msg, ctx, peer_id, peers); }
            AtpMessage::SoloChain { blocks } => {
                if blocks.len() > MAX_SOLO_CHAIN_BLOCKS { tracing::warn!("[CONN] SoloChain too large: {}", blocks.len()); }
                else { handle_atp_message(msg, ctx, peer_id, peers); }
            }
            AtpMessage::SoloChainRequest => { handle_atp_message(msg, ctx, peer_id, peers); }
            AtpMessage::Status { height, .. } => {
                tracing::info!("[CONN] Status received: height={}", height);
                self.peer_height = *height;
                peers.update_peer_height(peer_id, *height);
                handle_atp_message(msg, ctx, peer_id, peers);
            }
            AtpMessage::Pong { .. } => { health.lock().await.last_pong = Instant::now(); }
            AtpMessage::Ping { nonce } => { self.enqueue_msg(&AtpMessage::Pong { nonce: *nonce }); }
            AtpMessage::PeerList { ref addrs } => {
                let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                PeerExchange::process_peer_list(addrs, peers, n);
            }
            AtpMessage::HeaderRequest { from, to } => self.handle_header_request(ctx, *from, *to),
            _ => { handle_atp_message(msg, ctx, peer_id, peers); }
        }
    }

    async fn handle_snapshot_request(&mut self, ctx: &Arc<SyncContext>, writer: &Arc<TokioMutex<WriteHalf<TcpStream>>>, shared_secret: &[u8; 32]) {
        if self.last_snapshot_sent.elapsed().as_secs() < SNAPSHOT_RATE_LIMIT_SECS {
            tracing::warn!("[CONN] SnapshotRequest rate limited from {}", hex::encode(&self.peer_id));
            return;
        }
        tracing::info!("[CONN] SnapshotRequest received");
        self.last_snapshot_sent = Instant::now();

        let (height, utxo_data, block_hash, state_root) = {
            let val = ctx.validator.lock().unwrap();
            let utxo = val.utxo_set();
            (val.last_block_height(), bincode::serialize(&utxo.clone()).unwrap_or_default(), val.last_block_hash().0, utxo.get_state_root().0)
        };
        let mut w = writer.lock().await;
        // СВЕЖИЙ SnapshotCipher для каждого снапшота — гарантирует нулевые индексы
        let snap = SnapshotCipher::new(shared_secret);
        if let Err(e) = snap.send_snapshot_response(&mut *w, height, utxo_data, block_hash, state_root).await {
            tracing::warn!("[CONN] SnapshotResponse failed: {}", e);
        }
    }

    fn handle_header_request(&self, ctx: &Arc<SyncContext>, from: u64, to: u64) {
        let actual_to = to.min(from + MAX_HEADERS_PER_REQUEST);
        if to - from > MAX_HEADERS_PER_REQUEST {
            tracing::warn!("[CONN] HeaderRequest clamped: {}-{} -> {}-{}", from, to, from, actual_to);
        }
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
        let _ = writer.write_all(&packet).await; let _ = writer.flush().await;
    }

    async fn read_handshake_msg(reader: &mut ReadHalf<TcpStream>) -> Result<Vec<u8>, std::io::Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > HANDSHAKE_MAX_SIZE { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "handshake too large")); }
        let mut encrypted = vec![0u8; len];
        reader.read_exact(&mut encrypted).await?;
        Ok(encrypted)
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
