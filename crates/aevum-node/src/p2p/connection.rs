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
use std::sync::atomic::{AtomicBool, Ordering};
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
    shared_secret: [u8; 32],
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
    pending_outgoing: Vec<Vec<u8>>,
    outgoing_tx: Option<mpsc::Sender<Vec<u8>>>,
    peer_height: u64,
    last_alive: Instant,
}

impl AtpConnection {
    pub fn new(cipher: AtpCipher, peer_id: [u8; 20], addr: SocketAddr, peers: Arc<PeersManager>, ctx: Arc<SyncContext>, is_server: bool) -> Self {
        let shared_secret = cipher.shared_secret_bytes();
        let send_cipher = Arc::new(TokioMutex::new(cipher));
        let recv_cipher = Arc::new(TokioMutex::new(AtpCipher::new(&shared_secret)));
        Self {
            peer_id, addr, is_server, peers, ctx,
            state: ConnState::Handshaking,
            stats: PeerStats { connected_at: Some(Instant::now()), ..Default::default() },
            send_cipher, recv_cipher, shared_secret,
            pending_outgoing: Vec::new(), outgoing_tx: None,
            peer_height: 0, last_alive: Instant::now(),
        }
    }

    fn enqueue_msg(&self, msg: &AtpMessage) {
        if let Ok(data) = bincode::serialize(msg) {
            if let Some(ref tx) = self.outgoing_tx {
                let _ = tx.try_send(data);
            }
        }
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
        self.outgoing_tx = Some(tx.clone());
        self.peers.register_peer(self.peer_id, self.addr, tx);

        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;
        let shared_secret = self.shared_secret;

        let sync_in_progress = Arc::new(AtomicBool::new(false));
        let snap_recv_cipher = SnapshotCipher::new(&shared_secret).recv_cipher;

        // HANDSHAKE
        if self.is_server {
            if let Ok(encrypted) = Self::read_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                    }
                }
            } else { return; }
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
        } else {
            Self::send_msg(&send_cipher, &create_status(&ctx), &mut writer).await;
            if let Ok(encrypted) = Self::read_msg(&mut reader).await {
                if let Some(p) = recv_cipher.lock().await.decrypt(&encrypted) {
                    if let Ok(AtpMessage::Status { height, .. }) = bincode::deserialize::<AtpMessage>(&p) {
                        self.peer_height = height;
                    }
                }
            } else { return; }
        }

        let our_h = { ctx.validator.lock().unwrap().last_block_height() };
        let pex_msg = PeerExchange::create_peer_list(&self.peers, 20);
        self.enqueue_msg(&pex_msg);

        let mut node_id = [0u8; 32];
        let hash = blake3::hash(self.addr.to_string().as_bytes());
        node_id.copy_from_slice(&hash.as_bytes()[..32]);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        { ctx.dht.lock().unwrap().add_or_update(node_id, self.addr, now); }

        // Запускаем SyncDispatcher если нужно
        if self.peer_height > our_h {
            let phase = ctx.sync_phase.lock().clone();
            if phase == SyncPhase::Idle || phase == SyncPhase::Synced || matches!(phase, SyncPhase::AwaitingSnapshot { .. }) {
                sync_in_progress.store(true, Ordering::SeqCst);
                let mut dispatcher = SyncDispatcher::new(ctx.clone(), peers.clone(), peer_id);
                dispatcher.set_peer_height(self.peer_height);
                let sip = sync_in_progress.clone();
                tokio::spawn(async move {
                    if let Err(e) = dispatcher.start_sync().await {
                        tracing::warn!("[CONN] SyncDispatcher failed: {}", e);
                    }
                    sip.store(false, Ordering::SeqCst);
                });
            }
        }

        self.state = ConnState::Active;
        let writer = Arc::new(TokioMutex::new(writer));

        let kp_tx = self.outgoing_tx.clone().unwrap();
        let kp_sync = sync_in_progress.clone();
        let keepalive_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                if !kp_sync.load(Ordering::SeqCst) {
                    let ping = AtpMessage::Ping { nonce: rand::random() };
                    if let Ok(data) = bincode::serialize(&ping) { let _ = kp_tx.try_send(data); }
                }
            }
        });

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
                            self.last_alive = Instant::now();
                            // try main cipher
                            match recv_cipher.lock().await.decrypt(&encrypted) {
                                Some(p) => {
                                    if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                        self.process_message(msg, &ctx, &peers, &peer_id, &writer, &sync_in_progress, &shared_secret).await;
                                        continue;
                                    }
                                }
                                None => {}
                            }
                            // try snapshot cipher
                            match snap_recv_cipher.lock().await.decrypt(&encrypted) {
                                Some(p) => {
                                    if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                                        self.process_message(msg, &ctx, &peers, &peer_id, &writer, &sync_in_progress, &shared_secret).await;
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
        keepalive_handle.abort();
        self.peers.remove_peer(&peer_id);
    }

    async fn process_message(
        &mut self,
        msg: AtpMessage,
        ctx: &Arc<SyncContext>,
        peers: &Arc<PeersManager>,
        peer_id: &[u8; 20],
        writer: &Arc<TokioMutex<WriteHalf<TcpStream>>>,
        sync_in_progress: &Arc<AtomicBool>,
        shared_secret: &[u8; 32],
    ) {
        match &msg {
            AtpMessage::SnapshotRequest => {
                let (height, utxo_data, block_hash) = {
                    let val = ctx.validator.lock().unwrap();
                    let utxo = val.utxo_set();
                    (val.last_block_height(),
                     bincode::serialize(&utxo.clone()).unwrap_or_default(),
                     val.last_block_hash().0)
                };
                let mut w = writer.lock().await;
                let snap = SnapshotCipher::new(shared_secret);
                if let Err(e) = snap.send_snapshot_response(&mut *w, height, utxo_data, block_hash).await {
                    tracing::warn!("[CONN] SnapshotResponse failed: {}", e);
                }
                return;
            }

            AtpMessage::SnapshotResponse { height, utxo_data, block_hash } => {
                tracing::info!("[CONN] PROCESS SnapshotResponse h={}", *height);
                let mut val = ctx.validator.lock().unwrap();
                if !val.genesis_applied {
                    if let Ok(utxo) = bincode::deserialize::<UtxoSet>(utxo_data) {
                        val.load_utxo_set(utxo);
                        val.genesis_applied = true;
                        val.set_last_block(Hash(*block_hash), *height, 0);
                        ctx.storage.lock().unwrap().save_utxo_set(val.utxo_set()).ok();
                        tracing::info!("[CONN] Snapshot applied: h={}, supply={}", height, val.utxo_set().total_supply());
                    }
                }
                drop(val);
                crate::p2p::sync::flush_block_buffer(ctx);
                return;
            }

            AtpMessage::Status { height, .. } => {
                self.peer_height = *height;
                return;
            }

            AtpMessage::Pong { .. } => return,
            AtpMessage::Ping { nonce } => {
                self.enqueue_msg(&AtpMessage::Pong { nonce: *nonce });
                return;
            }
            AtpMessage::PeerList { ref addrs } => {
                let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                PeerExchange::process_peer_list(addrs, peers, n);
                return;
            }
            AtpMessage::HeaderRequest { from, to } => {
                let st = ctx.storage.lock().unwrap();
                let mut headers = Vec::new();
                for h in *from..=*to {
                    if let Ok(Some(block)) = st.load_genesis_block(h) {
                        headers.push(BlockHeader {
                            height: block.height, block_hash: block.block_hash.0,
                            prev_hash: block.prev_hash.0,
                            poh_tick_start: block.poh_tick_start, poh_tick_end: block.poh_tick_end,
                            state_root: block.state_root.0, total_supply: block.total_supply,
                        });
                    }
                }
                drop(st);
                let resp = AtpMessage::HeaderResponse { headers };
                self.enqueue_msg(&resp);
                return;
            }
            _ => {}
        }
        handle_atp_message(msg, ctx, peer_id, peers);
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
