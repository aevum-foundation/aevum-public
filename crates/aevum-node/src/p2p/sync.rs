use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::state::UtxoSet;
use aevum::crypto::hash::Hash;
use crate::p2p::peers::PeersManager;
use crate::storage::Storage;
use crate::http_server::SharedMetrics;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

const MAX_HEADERS_PER_REQUEST: u64 = 2000;
const MAX_BLOCKS_PER_RESPONSE: usize = 500;
const MAX_SOLO_CHAIN_BLOCKS: usize = 1000;
const SNAPSHOT_TIMEOUT_SECS: u64 = 30;
const HEADERS_TIMEOUT_SECS: u64 = 15;
const BLOCKS_TIMEOUT_SECS: u64 = 30;
const SOLO_CHAIN_TIMEOUT_SECS: u64 = 60;
const MAX_RETRIES: u8 = 3;
const PENDING_SOLO_REQUEST_TIMEOUT_SECS: u64 = 60;
const SNAPSHOT_THRESHOLD: u64 = 5000;
const PRUNE_KEEP_LAST: u64 = 100;

static SYNC_PHASE_CHANGES: AtomicU64 = AtomicU64::new(0);
static SYNC_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static SOLO_CHAINS_PROCESSED: AtomicU64 = AtomicU64::new(0);
static MESSAGE_LIMIT_REJECTED: AtomicU64 = AtomicU64::new(0);
static PENDING_SOLO_REQUESTS_CLEANED: AtomicU64 = AtomicU64::new(0);
static CHUNKED_SYNCS: AtomicU64 = AtomicU64::new(0);
static CHUNKED_RETRIES: AtomicU64 = AtomicU64::new(0);
static BLOCK_REQUESTS_SENT: AtomicU64 = AtomicU64::new(0);
static BLOCK_RESPONSES_RECEIVED: AtomicU64 = AtomicU64::new(0);
static BLOCK_RESPONSES_REJECTED: AtomicU64 = AtomicU64::new(0);
static HEADER_GAPS_DETECTED: AtomicU64 = AtomicU64::new(0);

pub fn sync_metrics() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (SYNC_PHASE_CHANGES.load(Ordering::Relaxed), SYNC_TIMEOUTS.load(Ordering::Relaxed),
     SOLO_CHAINS_PROCESSED.load(Ordering::Relaxed), MESSAGE_LIMIT_REJECTED.load(Ordering::Relaxed),
     PENDING_SOLO_REQUESTS_CLEANED.load(Ordering::Relaxed), CHUNKED_SYNCS.load(Ordering::Relaxed),
     CHUNKED_RETRIES.load(Ordering::Relaxed), BLOCK_REQUESTS_SENT.load(Ordering::Relaxed),
     BLOCK_RESPONSES_RECEIVED.load(Ordering::Relaxed), BLOCK_RESPONSES_REJECTED.load(Ordering::Relaxed),
     HEADER_GAPS_DETECTED.load(Ordering::Relaxed))
}

#[derive(Clone, Debug, PartialEq)]
pub enum SyncPhase {
    Idle,
    AwaitingSnapshot { peer_id: [u8; 20], request_time: Instant },
    AwaitingHeaders { peer_id: [u8; 20], from: u64, to: u64, request_time: Instant, retries: u8 },
    AwaitingHeadersChunked { peer_id: [u8; 20], from: u64, to: u64, next_from: u64, request_time: Instant, retries: u8 },
    AwaitingBlocks { peer_id: [u8; 20], from: u64, to: u64, request_id: u64, request_time: Instant, retries: u8 },
    AwaitingSoloBlocks { peer_id: [u8; 20], request_time: Instant },
    Synced,
}

impl SyncPhase {
    pub fn is_active(&self) -> bool { !matches!(self, SyncPhase::Idle | SyncPhase::Synced) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64, pub block_hash: [u8; 32], pub prev_hash: [u8; 32],
    pub poh_tick_start: u64, pub poh_tick_end: u64,
    pub state_root: [u8; 32], pub total_supply: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AtpMessage {
    Status { height: u64, poh_tick: u64, state_root: [u8; 32], total_supply: u64, version: u32, capabilities: u32 },
    HeaderRequest { from: u64, to: u64 },
    HeaderResponse { headers: Vec<BlockHeader> },
    BlockRequest { request_id: u64, from: u64, to: u64 },
    BlockResponse { request_id: u64, blocks: Vec<(u64, Vec<u8>)> },
    Transaction { tx_hash: [u8; 32], ttl: u8, bytes: Vec<u8> },
    BlobRequest { blob_hashes: Vec<[u8; 32]> },
    BlobResponse { blobs: Vec<crate::encrypted_replication::EncryptedBlob> },
    GetPeers { count: u8 }, PeerList { addrs: Vec<([u8; 16], u16)> },
    ReadySignal, FindNode { target_id: [u8; 32], count: u8 },
    NodeList { nodes: Vec<([u8; 32], String)> }, Ping { nonce: u64 }, Pong { nonce: u64 },
    SnapshotRequest,
    SnapshotResponse { height: u64, utxo_data: Vec<u8>, block_hash: [u8; 32], state_root: [u8; 32] },
    SoloChain { blocks: Vec<(u64, Vec<u8>)> },
    SoloChainRequest,
}

#[derive(Clone, Debug)]
pub struct PendingSoloRequest {
    pub peer_id: [u8; 20], pub request_id: u64, pub request_time: Instant,
}

pub struct SyncContext {
    pub validator: Arc<StdMutex<Validator>>,
    pub storage: Arc<StdMutex<Storage>>,
    pub chain_sync: Arc<StdMutex<crate::sync::ChainSync>>,
    pub block_buffer: Arc<StdMutex<BTreeMap<u64, Vec<u8>>>>,
    pub dht: Arc<StdMutex<crate::p2p::dht::Dht>>,
    pub orchestrator: Arc<StdMutex<crate::p2p::chain_orchestrator::ChainOrchestrator>>,
    pub replication: Option<Arc<StdMutex<crate::encrypted_replication::EncryptedReplication>>>,
    pub network_height: Arc<StdMutex<u64>>,
    pub sync_phase: Arc<parking_lot::Mutex<SyncPhase>>,
    pub sync_peer: Arc<parking_lot::Mutex<Option<[u8; 20]>>>,
    pub pending_solo_requests: Arc<StdMutex<Vec<PendingSoloRequest>>>,
    pub metrics: SharedMetrics,
}

fn check_message_limits(msg: &AtpMessage) -> Result<(), &'static str> {
    match msg {
        AtpMessage::HeaderResponse { headers } if headers.len() > MAX_HEADERS_PER_REQUEST as usize => Err("too many headers"),
        AtpMessage::BlockResponse { blocks, .. } if blocks.len() > MAX_BLOCKS_PER_RESPONSE => Err("too many blocks"),
        AtpMessage::SoloChain { blocks } if blocks.len() > MAX_SOLO_CHAIN_BLOCKS => Err("too many solo blocks"),
        _ => Ok(()),
    }
}

fn update_network_height(ctx: &SyncContext, peer_height: u64) {
    let mut nh = ctx.network_height.lock().unwrap();
    if peer_height > *nh && peer_height.saturating_sub(*nh) < 10000 { *nh = peer_height; }
}

pub fn create_status(ctx: &SyncContext) -> AtpMessage {
    let val = ctx.validator.lock().unwrap();
    let utxo = val.utxo_set();
    AtpMessage::Status {
        height: val.last_block_height(), poh_tick: val.poh().current_tick_number(),
        state_root: utxo.get_state_root().0, total_supply: utxo.total_supply(),
        version: 1, capabilities: 0x01,
    }
}

fn send_msg_to(peers: &Arc<PeersManager>, peer_id: &[u8; 20], msg: &AtpMessage) {
    if let Ok(data) = bincode::serialize(msg) {
        if !peers.send_to(peer_id, data) {
            tracing::warn!("[SYNC] send_to failed for {:?}", std::mem::discriminant(msg));
        }
    }
}

fn send_snapshot_response(peers: &Arc<PeersManager>, peer_id: &[u8; 20], ctx: &SyncContext) {
    let val = ctx.validator.lock().unwrap();
    let utxo = val.utxo_set();
    let resp = AtpMessage::SnapshotResponse {
        height: val.last_block_height(),
        utxo_data: bincode::serialize(&utxo.clone()).unwrap_or_default(),
        block_hash: val.last_block_hash().0,
        state_root: utxo.get_state_root().0,
    };
    drop(val);
    send_msg_to(peers, peer_id, &resp);
}

fn request_headers_chunked(peer_id: &[u8; 20], from: u64, to: u64, phase: &mut SyncPhase, peers: &Arc<PeersManager>) {
    let diff = to.saturating_sub(from);
    if diff <= MAX_HEADERS_PER_REQUEST {
        *phase = SyncPhase::AwaitingHeaders { peer_id: *peer_id, from, to, request_time: Instant::now(), retries: 0 };
        send_msg_to(peers, peer_id, &AtpMessage::HeaderRequest { from, to });
    } else {
        let chunk_end = from + MAX_HEADERS_PER_REQUEST;
        *phase = SyncPhase::AwaitingHeadersChunked { peer_id: *peer_id, from, to, next_from: chunk_end + 1, request_time: Instant::now(), retries: 0 };
        send_msg_to(peers, peer_id, &AtpMessage::HeaderRequest { from, to: chunk_end });
        CHUNKED_SYNCS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn handle_atp_message(msg: AtpMessage, ctx: &Arc<SyncContext>, peer_id: &[u8; 20], peers: &Arc<PeersManager>) {
    let disc = std::mem::discriminant(&msg);
    tracing::debug!("[SYNC] >>> {:?} from {}", disc, hex::encode(&peer_id[..8]));
    if let Err(_) = check_message_limits(&msg) { MESSAGE_LIMIT_REJECTED.fetch_add(1, Ordering::Relaxed); return; }
    match msg {
        AtpMessage::Status { height, version, .. } => {
            if version != 1 { return; }
            if height > 0 { update_network_height(ctx, height); }
            peers.update_peer_height(peer_id, height);
            let my = ctx.validator.lock().unwrap().last_block_height();
            tracing::info!("[SYNC] Status: my={}, peer={}", my, height);
            if height <= my { return; }
            let mut phase = ctx.sync_phase.lock();
            if phase.is_active() { return; }
            *ctx.sync_peer.lock() = Some(*peer_id);
            let diff = height.saturating_sub(my);
            let need_snapshot = my == 0 || my < 100 || diff > 10000 || (diff > 1000 && my < 5000);
            if need_snapshot {
                tracing::info!("[SYNC] -> AwaitingSnapshot (diff={})", diff);
                *phase = SyncPhase::AwaitingSnapshot { peer_id: *peer_id, request_time: Instant::now() };
                send_msg_to(peers, peer_id, &AtpMessage::SnapshotRequest);
            } else {
                tracing::info!("[SYNC] -> Headers from={} to={}", my + 1, height);
                request_headers_chunked(peer_id, my + 1, height, &mut *phase, peers);
            }
            SYNC_PHASE_CHANGES.fetch_add(1, Ordering::Relaxed);
        }
        AtpMessage::SnapshotRequest => {
            send_snapshot_response(peers, peer_id, ctx);
        }
        AtpMessage::SnapshotResponse { height, utxo_data, block_hash, state_root } => {
            tracing::info!("[SYNC] SnapshotResponse h={}", height);
            let phase_ok = {
                let phase = ctx.sync_phase.lock();
                matches!(&*phase, SyncPhase::AwaitingSnapshot { peer_id: expected, .. } if *expected == *peer_id)
            };
            let my_h = ctx.validator.lock().unwrap().last_block_height();
            // Принимаем снапшот всегда если отстаём
            let mut val = ctx.validator.lock().unwrap();
            let nh = *ctx.network_height.lock().unwrap();
            if val.genesis_applied && my_h >= 100 && my_h >= nh { return; }
            if let Ok(utxo) = bincode::deserialize::<UtxoSet>(&utxo_data) {
                if utxo.get_state_root().0 != state_root { tracing::warn!("[SYNC] state_root mismatch"); return; }
                val.load_utxo_set(utxo); val.genesis_applied = true; val.set_last_block(Hash(block_hash), height, 0);
                ctx.storage.lock().unwrap().save_utxo_set(val.utxo_set()).ok();
                let supply = val.utxo_set().total_supply();
                if nh > height {
                    let mut phase = ctx.sync_phase.lock();
                    request_headers_chunked(peer_id, height + 1, nh, &mut *phase, peers);
                } else {
                    *ctx.sync_phase.lock() = SyncPhase::Synced;
                }
                SYNC_PHASE_CHANGES.fetch_add(1, Ordering::Relaxed);
                ctx.metrics.update_chain(height, supply, nh, val.utxo_set().len(), val.poh().current_tick_number(), height >= nh);
                drop(val);
                flush_block_buffer(ctx);
                tracing::info!("[SYNC] Snapshot APPLIED h={}, supply={}", height, supply);
            }
        }
        AtpMessage::HeaderResponse { headers } => {
            if headers.is_empty() { return; }
            let from = headers.iter().map(|h| h.height).min().unwrap();
            let to = headers.iter().map(|h| h.height).max().unwrap();
            tracing::info!("[SYNC] HeaderResponse: {} headers, range {}..{}", headers.len(), from, to);
            { let mut nh = ctx.network_height.lock().unwrap(); if to > *nh && to.saturating_sub(*nh) < 10000 { *nh = to; } }
            for w in headers.windows(2) { if w[1].height != w[0].height + 1 { HEADER_GAPS_DETECTED.fetch_add(1, Ordering::Relaxed); *ctx.sync_phase.lock() = SyncPhase::Idle; return; } }
            let our_last_hash = ctx.validator.lock().unwrap().last_block_hash().0;
            let our_last_height = ctx.validator.lock().unwrap().last_block_height();
            let mut expected_prev = our_last_hash;
            let mut fork_detected = false;
            for h in &headers {
                if h.height == our_last_height + 1 && h.prev_hash != expected_prev {
                    tracing::warn!("[SYNC] FORK at {}: expected {} got {}", h.height, hex::encode(&expected_prev[..8]), hex::encode(&h.prev_hash[..8]));
                    fork_detected = true; break;
                }
                expected_prev = h.block_hash;
            }
            if fork_detected {
                tracing::info!("[SYNC] Requesting SoloChain from {}", hex::encode(&peer_id[..8]));
                *ctx.sync_phase.lock() = SyncPhase::AwaitingSoloBlocks { peer_id: *peer_id, request_time: Instant::now() };
                ctx.pending_solo_requests.lock().unwrap().push(PendingSoloRequest { peer_id: *peer_id, request_id: 0, request_time: Instant::now() });
                send_msg_to(peers, peer_id, &AtpMessage::SoloChainRequest);
                return;
            }
            let request_id = rand::random();
            {
                let mut phase = ctx.sync_phase.lock();
                let is_chunked = matches!(&*phase, SyncPhase::AwaitingHeadersChunked { .. });
                if is_chunked {
                    let old = phase.clone();
                    if let SyncPhase::AwaitingHeadersChunked { peer_id: pid, from: total_from, to: total_to, next_from, .. } = &old {
                        if *next_from <= *total_to {
                            let chunk_end = (*next_from + MAX_HEADERS_PER_REQUEST).min(*total_to);
                            *phase = SyncPhase::AwaitingHeadersChunked { peer_id: *pid, from: *total_from, to: *total_to, next_from: chunk_end + 1, request_time: Instant::now(), retries: 0 };
                            send_msg_to(peers, pid, &AtpMessage::HeaderRequest { from: *next_from, to: chunk_end });
                            return;
                        }
                    }
                }
                *phase = SyncPhase::AwaitingBlocks { peer_id: *peer_id, from, to, request_id, request_time: Instant::now(), retries: 0 };
            }
            tracing::info!("[SYNC] Requesting blocks {}..{}", from, to);
            send_msg_to(peers, peer_id, &AtpMessage::BlockRequest { request_id, from, to });
            BLOCK_REQUESTS_SENT.fetch_add(1, Ordering::Relaxed);
        }
        AtpMessage::BlockRequest { request_id, from, to } => {
            let st = ctx.storage.lock().unwrap();
            let our_height = ctx.validator.lock().unwrap().last_block_height();
            let keep_from = our_height.saturating_sub(PRUNE_KEEP_LAST);
            if from < keep_from {
                drop(st);
                tracing::info!("[SYNC] BlockRequest for pruned blocks ({} < {}), sending Snapshot", from, keep_from);
                send_snapshot_response(peers, peer_id, ctx);
                return;
            }
            let mut blocks = Vec::new();
            for h in from..=to { if let Ok(Some(block)) = st.load_genesis_block(h) { if let Ok(bytes) = bincode::serialize(&block) { blocks.push((h, bytes)); } } }
            drop(st);
            send_msg_to(peers, peer_id, &AtpMessage::BlockResponse { request_id, blocks });
        }
        AtpMessage::BlockResponse { request_id, blocks } => {
            let expected_id = { let phase = ctx.sync_phase.lock(); match &*phase { SyncPhase::AwaitingBlocks { request_id: expected, .. } => *expected, _ => { BLOCK_RESPONSES_REJECTED.fetch_add(1, Ordering::Relaxed); return; } } };
            if request_id != expected_id { BLOCK_RESPONSES_REJECTED.fetch_add(1, Ordering::Relaxed); return; }
            BLOCK_RESPONSES_RECEIVED.fetch_add(1, Ordering::Relaxed);
            if let Some((last_h, _)) = blocks.last() { let mut nh = ctx.network_height.lock().unwrap(); if *last_h > *nh && last_h.saturating_sub(*nh) < 10000 { *nh = *last_h; } }
            let mut buffer = ctx.block_buffer.lock().unwrap();
            for (height, bytes) in &blocks { buffer.insert(*height, bytes.clone()); }
            drop(buffer);
            flush_block_buffer(ctx);
            let val = ctx.validator.lock().unwrap(); let nh = *ctx.network_height.lock().unwrap();
            if val.last_block_height() >= nh { *ctx.sync_phase.lock() = SyncPhase::Synced; }
        }
        AtpMessage::Transaction { bytes, .. } => {
            let gossip_msg = AtpMessage::Transaction { tx_hash: [0u8; 32], ttl: 0, bytes };
            if let Ok(data) = bincode::serialize(&gossip_msg) { peers.broadcast(data); }
        }
        AtpMessage::Ping { nonce } => { send_msg_to(peers, peer_id, &AtpMessage::Pong { nonce }); }
        AtpMessage::GetPeers { .. } => {
            let addrs: Vec<([u8; 16], u16)> = peers.known_addresses_iter().iter().map(|a| crate::p2p::pex::socket_to_bytes(a)).collect();
            send_msg_to(peers, peer_id, &AtpMessage::PeerList { addrs });
        }
        AtpMessage::PeerList { addrs } => {
            let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            crate::p2p::pex::PeerExchange::process_peer_list(&addrs, peers, n);
        }
        AtpMessage::SoloChain { blocks } => {
            let is_expected = ctx.pending_solo_requests.lock().unwrap().iter().any(|req| req.peer_id == *peer_id);
            if !is_expected { return; }
            ctx.pending_solo_requests.lock().unwrap().retain(|req| req.peer_id != *peer_id);
            let block_objs: Vec<Block> = blocks.iter().filter_map(|(_, bytes)| bincode::deserialize(bytes).ok()).collect();
            if !block_objs.is_empty() {
                let mut orch = ctx.orchestrator.lock().unwrap();
                let mut val = ctx.validator.lock().unwrap(); let mut st = ctx.storage.lock().unwrap();
                match orch.accept_solo_chain(peer_id, &block_objs, &mut val, &mut st) {
                    Ok((count, reward, _)) => {
                        SOLO_CHAINS_PROCESSED.fetch_add(1, Ordering::Relaxed);
                        tracing::info!("[SYNC] SoloChain accepted: {} blocks, {} reward", count, reward);
                        let new_h = val.last_block_height(); let nh = *ctx.network_height.lock().unwrap();
                        *ctx.sync_phase.lock() = if new_h >= nh { SyncPhase::Synced } else { SyncPhase::Idle };
                        let supply = val.utxo_set().total_supply();
                        ctx.metrics.update_chain(new_h, supply, nh, val.utxo_set().len(), val.poh().current_tick_number(), new_h >= nh);
                        ctx.storage.lock().unwrap().save_utxo_set(val.utxo_set()).ok();
                        drop(val); drop(st);
                        flush_block_buffer(ctx);
                    }
                    Err(e) => { tracing::warn!("[SYNC] SoloChain rejected: {}", e); *ctx.sync_phase.lock() = SyncPhase::Idle; }
                }
            }
        }
        AtpMessage::SoloChainRequest => {
            let st = ctx.storage.lock().unwrap();
            let our_h = ctx.validator.lock().unwrap().last_block_height();
            let mut blocks: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            for h in 1..=our_h {
                if let Ok(Some(block)) = st.load_my_block(h) { if let Ok(bytes) = bincode::serialize(&block) { blocks.entry(h).or_insert(bytes); } }
            }
            for h in 1..=our_h {
                if !blocks.contains_key(&h) { if let Ok(Some(block)) = st.load_genesis_block(h) { if let Ok(bytes) = bincode::serialize(&block) { blocks.insert(h, bytes); } } }
            }
            drop(st);
            if !blocks.is_empty() {
                let blocks_vec: Vec<(u64, Vec<u8>)> = blocks.into_iter().collect();
                let len = blocks_vec.len();
                send_msg_to(peers, peer_id, &AtpMessage::SoloChain { blocks: blocks_vec });
                tracing::info!("[SYNC] SoloChain sent: {} blocks", len);
            }
        }
        _ => {}
    }
}

pub fn check_sync_timeouts(ctx: &Arc<SyncContext>, _peers: &Arc<PeersManager>) {
    let mut phase = ctx.sync_phase.lock();
    let now = Instant::now();
    match &*phase {
        SyncPhase::AwaitingSnapshot { request_time, .. } => { if now.duration_since(*request_time).as_secs() > SNAPSHOT_TIMEOUT_SECS { SYNC_TIMEOUTS.fetch_add(1, Ordering::Relaxed); *phase = SyncPhase::Idle; } }
        SyncPhase::AwaitingHeaders { request_time, retries, peer_id, from, to } => { if now.duration_since(*request_time).as_secs() > HEADERS_TIMEOUT_SECS { if *retries < MAX_RETRIES { send_msg_to(_peers, peer_id, &AtpMessage::HeaderRequest { from: *from, to: *to }); *phase = SyncPhase::AwaitingHeaders { peer_id: *peer_id, from: *from, to: *to, request_time: now, retries: *retries + 1 }; } else { SYNC_TIMEOUTS.fetch_add(1, Ordering::Relaxed); *phase = SyncPhase::Idle; } } }
        SyncPhase::AwaitingHeadersChunked { request_time, retries, peer_id, from, to, next_from } => { if now.duration_since(*request_time).as_secs() > HEADERS_TIMEOUT_SECS { if *retries < MAX_RETRIES { CHUNKED_RETRIES.fetch_add(1, Ordering::Relaxed); let chunk_end = (*next_from + MAX_HEADERS_PER_REQUEST).min(*to); send_msg_to(_peers, peer_id, &AtpMessage::HeaderRequest { from: *next_from, to: chunk_end }); *phase = SyncPhase::AwaitingHeadersChunked { peer_id: *peer_id, from: *from, to: *to, next_from: *next_from, request_time: now, retries: *retries + 1 }; } else { SYNC_TIMEOUTS.fetch_add(1, Ordering::Relaxed); *phase = SyncPhase::Idle; } } }
        SyncPhase::AwaitingBlocks { request_time, retries, peer_id, from, to, .. } => { if now.duration_since(*request_time).as_secs() > BLOCKS_TIMEOUT_SECS { if *retries < MAX_RETRIES { let new_id = rand::random(); send_msg_to(_peers, peer_id, &AtpMessage::BlockRequest { request_id: new_id, from: *from, to: *to }); *phase = SyncPhase::AwaitingBlocks { peer_id: *peer_id, from: *from, to: *to, request_id: new_id, request_time: now, retries: *retries + 1 }; } else { SYNC_TIMEOUTS.fetch_add(1, Ordering::Relaxed); *phase = SyncPhase::Idle; } } }
        SyncPhase::AwaitingSoloBlocks { request_time, .. } => { if now.duration_since(*request_time).as_secs() > SOLO_CHAIN_TIMEOUT_SECS { SYNC_TIMEOUTS.fetch_add(1, Ordering::Relaxed); *phase = SyncPhase::Idle; } }
        _ => {}
    }
}

pub fn cleanup_pending_solo_requests(ctx: &SyncContext) {
    let mut pending = ctx.pending_solo_requests.lock().unwrap();
    pending.retain(|req| req.request_time.elapsed().as_secs() < PENDING_SOLO_REQUEST_TIMEOUT_SECS);
}

pub fn flush_block_buffer(ctx: &SyncContext) {
    let mut applied_total = 0u64;
    let mut skipped_count = 0u64;
    loop {
        let (block_bytes, _) = { let val = ctx.validator.lock().unwrap(); let next = val.last_block_height() + 1; let mut buffer = ctx.block_buffer.lock().unwrap(); (buffer.remove(&next), next) };
        let block_bytes = match block_bytes { Some(b) => b, None => break };
        let block: Block = match bincode::deserialize(&block_bytes) { Ok(b) => b, Err(_) => { skipped_count += 1; continue; } };
        let mut val = ctx.validator.lock().unwrap();
        let mut st = ctx.storage.lock().unwrap();
        if block.height > 0 && val.last_block_height() >= block.height { drop(val); drop(st); continue; }
        let original_hash = block.block_hash;
        match val.validate_and_apply(&mut block.clone()) {
            Ok(_) => {
                st.save_genesis_block(&block).ok(); st.save_utxo_set(val.utxo_set()).ok();
                val.last_block_hash = original_hash; applied_total += 1;
                let nh = *ctx.network_height.lock().unwrap();
                ctx.metrics.update_chain(val.last_block_height(), val.utxo_set().total_supply(), nh, val.utxo_set().len(), val.poh().current_tick_number(), val.last_block_height() >= nh);
                drop(val); drop(st);
            }
            Err(e) => {
                let err_msg = format!("{:?}", e);
                tracing::warn!("[SYNC] Block {} failed: {}", block.height, err_msg);
                if err_msg.contains("prev_hash") || err_msg.contains("fork") { drop(val); drop(st); if let Ok(mut orch) = ctx.orchestrator.lock() { let mut v = ctx.validator.lock().unwrap(); let mut s = ctx.storage.lock().unwrap(); let _ = orch.resolve_fork(&mut v, &mut s); } }
                else { drop(val); drop(st); }
                continue;
            }
        }
    }
    if applied_total > 0 || skipped_count > 0 { tracing::info!("[SYNC] flush: applied {}, skipped {}", applied_total, skipped_count); }
}
