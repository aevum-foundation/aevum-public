use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, SyncPhase, create_status, handle_atp_message, BlockHeader};
use crate::p2p::noise::AtpCipher;
use crate::p2p::pex::PeerExchange;
use crate::p2p::sync_dispatcher::SyncDispatcher;
use crate::p2p::snapshot_cipher::SnapshotCipher;
use aevum::core::state::UtxoSet;
use aevum::crypto::hash::Hash;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio::time::Duration;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;
use std::net::SocketAddr;

const MAX_INBOUND_MSG_RATE: u64 = 100;
const MAX_SOLO_CHAIN_BLOCKS: usize = 500;
const MAX_HEADERS_PER_REQUEST: u64 = 2000;
const PONG_TIMEOUT_SECS: u64 = 90;
const MIN_SOLO_REQUEST_INTERVAL: Duration = Duration::from_secs(60);

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

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState { Handshaking, Active, Dead }

#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub connected_at: Option<Instant>,
    pub messages_sent: u64, pub messages_received: u64,
    pub bytes_sent: u64, pub bytes_received: u64,
    pub score: i32,
}

struct ConnectionHealth {
    last_pong: Instant,
    msg_count: u64,
    msg_window_start: Instant,
    last_solo_request: Instant,
}

impl ConnectionHealth {
    fn new() -> Self {
        let now = Instant::now();
        Self { last_pong: now, msg_count: 0, msg_window_start: now, last_solo_request: now - MIN_SOLO_REQUEST_INTERVAL }
    }

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

pub struct AtpConnection {
    pub peer_id: [u8; 20],
    pub addr: SocketAddr,
    pub state: ConnState,
    pub stats: PeerStats,
    is_server: bool,
    send_cipher: Arc<TokioMutex<AtpCipher>>,
    recv_cipher: Arc<TokioMutex<AtpCipher>>,
    snap_cipher: Arc<TokioMutex<AtpCipher>>,
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
    outgoing_tx: Option<mpsc::Sender<Vec<u8>>>,
    peer_height: u64,
    health: Arc<TokioMutex<ConnectionHealth>>,
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
        let snap_cipher = Arc::new(TokioMutex::new(AtpCipher::new(&shared_secret)));
        METRIC_TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        Self {
            peer_id, addr, is_server, peers, ctx,
            state: ConnState::Handshaking,
            stats: PeerStats { connected_at: Some(Instant::now()), ..Default::default() },
            send_cipher, recv_cipher, snap_cipher,
            outgoing_tx: None, peer_height: 0,
            health: Arc::new(TokioMutex::new(ConnectionHealth::new())),
        }
    }

    fn enqueue_msg(&self, msg: &AtpMessage) {
        if let Ok(data) = bincode::serialize(msg) {
            if let Some(ref tx) = self.outgoing_tx { let _ = tx.try_send(data); }
        }
    }

    async fn try_decrypt(ciphers: &[&Arc<TokioMutex<AtpCipher>>], encrypted: &[u8]) -> Option<Vec<u8>> {
        for cipher in ciphers {
            if let Some(dec) = cipher.lock().await.decrypt(encrypted) { return Some(dec); }
        }
        None
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        tracing::info!("[CONN] run START: peer={} addr={}", hex::encode(&self.peer_id), self.addr);

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
        self.outgoing_tx = Some(tx.clone());
        self.peers.register_peer(self.peer_id, self.addr, tx);

        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let snap_cipher = self.snap_cipher.clone();
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;
        let health = self.health.clone();

        let sync_in_progress = Arc::new(AtomicBool::new(false));

        // HANDSHAKE
        tracing::info!("[CONN] HANDSHAKE START: peer={} is_server={}", hex::encode(&self.peer_id), self.is_server);
        if self.is_server {
            if let Ok(encrypted) = Self::read_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                        health.lock().await.last_pong = Instant::now();
                        tracing::info!("[CONN] HANDSHAKE server: received Status height={}", height);
                    }
                }
            } else { tracing::warn!("[CONN] HANDSHAKE server: read_msg failed"); return; }
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
            tracing::info!("[CONN] HANDSHAKE server: Status sent");
        } else {
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
            tracing::info!("[CONN] HANDSHAKE client: Status sent, waiting for response");
            if let Ok(encrypted) = Self::read_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                        health.lock().await.last_pong = Instant::now();
                        tracing::info!("[CONN] HANDSHAKE client: received Status height={}", height);
                    }
                }
            } else { tracing::warn!("[CONN] HANDSHAKE client: read_msg failed"); return; }
        }

        tracing::info!("[CONN] POST-HANDSHAKE: peer_height={}", self.peer_height);
        peers.update_peer_height(&self.peer_id, self.peer_height);
        let our_h = { ctx.validator.lock().unwrap().last_block_height() };
        tracing::info!("[CONN] POST-HANDSHAKE: our_h={} peer_height={}", our_h, self.peer_height);

        let pex_msg = PeerExchange::create_peer_list(&self.peers, 20);
        self.enqueue_msg(&pex_msg);

        let mut node_id = [0u8; 32];
        let hash = blake3::hash(self.addr.to_string().as_bytes());
        node_id.copy_from_slice(&hash.as_bytes()[..32]);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        { ctx.dht.lock().unwrap().add_or_update(node_id, self.addr, now); }

        // Запрос соло-блоков
        if our_h > 0 && self.peer_height > 0 && self.peer_height < our_h && health.lock().await.can_request_solo() {
            tracing::info!("[CONN] Requesting solo blocks from peer {} (peer_h={}, our_h={})", hex::encode(&peer_id), self.peer_height, our_h);
            let req = AtpMessage::SoloChainRequest;
            if let Ok(data) = bincode::serialize(&req) { let _ = self.outgoing_tx.as_ref().map(|tx| tx.try_send(data)); }
        }

        // SyncDispatcher
        if self.peer_height > our_h {
            tracing::info!("[CONN] SyncDispatcher needed: peer_height={} > our_h={}", self.peer_height, our_h);
            let phase = ctx.sync_phase.lock().clone();
            tracing::info!("[CONN] Current sync_phase: {:?}", phase);
            if phase == SyncPhase::Idle || phase == SyncPhase::Synced || matches!(phase, SyncPhase::AwaitingSnapshot { .. }) {
                if sync_in_progress.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    tracing::info!("[CONN] SyncDispatcher STARTING");
                    let mut dispatcher = SyncDispatcher::new(ctx.clone(), peers.clone(), peer_id);
                    dispatcher.set_peer_height(self.peer_height);
                    let sip = sync_in_progress.clone();
                    tokio::spawn(async move {
                        if let Err(e) = dispatcher.start_sync().await {
                            tracing::warn!("[CONN] SyncDispatcher failed: {}", e);
                        }
                        sip.store(false, Ordering::SeqCst);
                    });
                } else {
                    tracing::info!("[CONN] SyncDispatcher already in progress, skipping");
                }
            } else {
                tracing::info!("[CONN] SyncDispatcher skipped: phase not idle/synced");
            }
        } else {
            tracing::info!("[CONN] SyncDispatcher NOT needed: peer_height={} <= our_h={}", self.peer_height, our_h);
        }

        self.state = ConnState::Active;
        let writer = Arc::new(TokioMutex::new(writer));

        // Keepalive
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

        tracing::info!("[CONN] Main loop START: peer={}", hex::encode(&self.peer_id));
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
                        }
                        None => break,
                    }
                }
                result = Self::read_msg(&mut reader) => {
                    match result {
                        Ok(encrypted) => {
                            if !health.lock().await.check_rate() {
                                tracing::warn!("[CONN] Rate limit exceeded from {}", self.addr);
                                continue;
                            }
                            let ciphers = [&recv_cipher, &snap_cipher];
                            if let Some(plain) = Self::try_decrypt(&ciphers, &encrypted).await {
                                if let Ok(msg) = bincode::deserialize::<AtpMessage>(&plain) {
                                    self.stats.messages_received += 1;
                                    self.stats.bytes_received += plain.len() as u64;
                                    self.process_message(msg, &ctx, &peers, &peer_id, &writer, &sync_in_progress, &health).await;
                                    continue;
                                }
                            }
                            tracing::debug!("[CONN] Failed to decrypt message from {}", self.addr);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        tracing::info!("[CONN] Main loop END: peer={}", hex::encode(&self.peer_id));
        keepalive_handle.abort();
        self.peers.remove_peer(&peer_id);
    }

    async fn process_message(
        &mut self, msg: AtpMessage, ctx: &Arc<SyncContext>, peers: &Arc<PeersManager>,
        peer_id: &[u8; 20], writer: &Arc<TokioMutex<WriteHalf<TcpStream>>>,
        _sync_in_progress: &Arc<AtomicBool>, health: &Arc<TokioMutex<ConnectionHealth>>,
    ) {
        match &msg {
            AtpMessage::SnapshotRequest => self.handle_snapshot_request(ctx, writer).await,
            AtpMessage::SnapshotResponse { .. } => self.handle_snapshot_response(&msg, ctx, peer_id),
            AtpMessage::SoloChain { blocks } => {
                if blocks.len() > MAX_SOLO_CHAIN_BLOCKS {
                    tracing::warn!("[CONN] SoloChain too large: {} blocks", blocks.len());
                } else { handle_atp_message(msg, ctx, peer_id, peers); }
            }
            AtpMessage::SoloChainRequest => { handle_atp_message(msg, ctx, peer_id, peers); }
            AtpMessage::Status { height, .. } => {
                tracing::info!("[CONN] Status received: height={} from peer={}", height, hex::encode(peer_id));
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

    async fn handle_snapshot_request(&mut self, ctx: &Arc<SyncContext>, writer: &Arc<TokioMutex<WriteHalf<TcpStream>>>) {
        tracing::info!("[CONN] SnapshotRequest received");
        let mut phase = ctx.sync_phase.lock();
        if matches!(*phase, SyncPhase::Idle | SyncPhase::Synced) {
            *phase = SyncPhase::AwaitingSnapshot { peer_id: self.peer_id, request_time: Instant::now() };
        }
        drop(phase);
        let (height, utxo_data, block_hash) = {
            let val = ctx.validator.lock().unwrap();
            let utxo = val.utxo_set();
            (val.last_block_height(), bincode::serialize(&utxo.clone()).unwrap_or_default(), val.last_block_hash().0)
        };
        let mut w = writer.lock().await;
        let snap = SnapshotCipher::new_with_cipher(&self.snap_cipher);
        if let Err(e) = snap.send_snapshot_response(&mut *w, height, utxo_data, block_hash).await {
            tracing::warn!("[CONN] SnapshotResponse failed: {}", e);
            let mut phase = ctx.sync_phase.lock();
            if matches!(*phase, SyncPhase::AwaitingSnapshot { .. }) { *phase = SyncPhase::Idle; }
        }
    }

    fn handle_snapshot_response(&mut self, msg: &AtpMessage, ctx: &Arc<SyncContext>, peer_id: &[u8; 20]) {
        if let AtpMessage::SnapshotResponse { height, utxo_data, block_hash } = msg {
            tracing::info!("[CONN] PROCESS SnapshotResponse h={}", *height);
            let utxo_set: Option<UtxoSet> = bincode::deserialize::<UtxoSet>(utxo_data).ok();
            let applied = if let Some(utxo) = utxo_set {
                let mut val = ctx.validator.lock().unwrap();
                if !val.genesis_applied {
                    ctx.storage.lock().unwrap().save_utxo_set(&utxo).ok();
                    val.load_utxo_set(utxo);
                    val.genesis_applied = true;
                    val.set_last_block(Hash(*block_hash), *height, 0);
                    tracing::info!("[CONN] Snapshot applied: h={}, supply={}", height, val.utxo_set().total_supply());
                    true
                } else { false }
            } else { false };
            if applied {
                crate::p2p::sync::flush_block_buffer(ctx);
                let our_h = ctx.validator.lock().unwrap().last_block_height();
                let nh = *ctx.network_height.lock().unwrap();
                let mut phase = ctx.sync_phase.lock();
                if our_h >= nh {
                    *phase = SyncPhase::Synced;
                    tracing::info!("[CONN] SyncPhase -> Synced (snapshot complete, h={})", our_h);
                } else {
                    let from = our_h + 1;
                    *phase = SyncPhase::AwaitingHeaders { peer_id: *peer_id, from, to: nh, request_time: Instant::now(), retries: 0 };
                    let req = AtpMessage::HeaderRequest { from, to: nh };
                    self.enqueue_msg(&req);
                }
            } else {
                let mut phase = ctx.sync_phase.lock();
                if matches!(*phase, SyncPhase::AwaitingSnapshot { .. }) { *phase = SyncPhase::Idle; }
            }
        }
    }

    fn handle_header_request(&mut self, ctx: &Arc<SyncContext>, from: u64, to: u64) {
        let count = to.saturating_sub(from);
        if count > MAX_HEADERS_PER_REQUEST { tracing::warn!("[CONN] HeaderRequest too large: {}", count); return; }
        let st = ctx.storage.lock().unwrap();
        let mut headers = Vec::with_capacity(count as usize);
        for h in from..=to {
            if let Ok(Some(block)) = st.load_genesis_block(h) {
                headers.push(BlockHeader {
                    height: block.height, block_hash: block.block_hash.0, prev_hash: block.prev_hash.0,
                    poh_tick_start: block.poh_tick_start, poh_tick_end: block.poh_tick_end,
                    state_root: block.state_root.0, total_supply: block.total_supply,
                });
            }
        }
        drop(st);
        self.enqueue_msg(&AtpMessage::HeaderResponse { headers });
    }

    async fn send_msg(send_cipher: &Arc<TokioMutex<AtpCipher>>, msg: &AtpMessage, writer: &mut WriteHalf<TcpStream>) {
        let data = bincode::serialize(msg).unwrap_or_default();
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
