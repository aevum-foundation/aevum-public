use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::state::UtxoSet;
use aevum::crypto::hash::Hash;
use crate::p2p::peers::PeersManager;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

// ── Константы ────────────────────────────────────────────────
const MAX_HEADERS_PER_REQUEST: u64 = 2000;
const MAX_BLOCKS_PER_RESPONSE: usize = 500;
const MAX_SOLO_CHAIN_BLOCKS: usize = 1000;
const SNAPSHOT_TIMEOUT_SECS: u64 = 30;
const HEADERS_TIMEOUT_SECS: u64 = 15;
const BLOCKS_TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u8 = 3;
const PENDING_SOLO_REQUEST_TIMEOUT_SECS: u64 = 60;
const SNAPSHOT_THRESHOLD: u64 = 5000;

// ── Метрики ──────────────────────────────────────────────────
static SYNC_PHASE_CHANGES: AtomicU64 = AtomicU64::new(0);
static SYNC_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static SOLO_CHAINS_PROCESSED: AtomicU64 = AtomicU64::new(0);
static MESSAGE_LIMIT_REJECTED: AtomicU64 = AtomicU64::new(0);
static PENDING_SOLO_REQUESTS_CLEANED: AtomicU64 = AtomicU64::new(0);
static CHUNKED_SYNCS: AtomicU64 = AtomicU64::new(0);

pub fn sync_metrics() -> (u64, u64, u64, u64, u64, u64) {
    (SYNC_PHASE_CHANGES.load(Ordering::Relaxed),
     SYNC_TIMEOUTS.load(Ordering::Relaxed),
     SOLO_CHAINS_PROCESSED.load(Ordering::Relaxed),
     MESSAGE_LIMIT_REJECTED.load(Ordering::Relaxed),
     PENDING_SOLO_REQUESTS_CLEANED.load(Ordering::Relaxed),
     CHUNKED_SYNCS.load(Ordering::Relaxed))
}

// ── Фазы синхронизации ──────────────────────────────────────
#[derive(Clone, Debug, PartialEq)]
pub enum SyncPhase {
    Idle,
    AwaitingSnapshot { peer_id: [u8; 20], request_time: Instant },
    AwaitingHeaders { peer_id: [u8; 20], from: u64, to: u64, request_time: Instant, retries: u8 },
    AwaitingHeadersChunked { peer_id: [u8; 20], from: u64, to: u64, next_from: u64, request_time: Instant, retries: u8 },
    AwaitingBlocks { peer_id: [u8; 20], from: u64, to: u64, request_time: Instant, retries: u8 },
    AwaitingSoloBlocks { peer_id: [u8; 20], request_time: Instant },
    Synced,
}

// ── Структуры ────────────────────────────────────────────────
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
    SnapshotResponse { height: u64, utxo_data: Vec<u8>, block_hash: [u8; 32] },
    SoloChain { blocks: Vec<(u64, Vec<u8>)> },
    SoloChainRequest,
}

#[derive(Clone, Debug)]
pub struct PendingSoloRequest {
    pub peer_id: [u8; 20],
    pub request_time: Instant,
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
}

// ── Проверка лимитов ────────────────────────────────────────
fn check_message_limits(msg: &AtpMessage) -> Result<(), &'static str> {
    match msg {
        AtpMessage::HeaderResponse { headers } if headers.len() > MAX_HEADERS_PER_REQUEST as usize => Err("too many headers"),
        AtpMessage::BlockResponse { blocks, .. } if blocks.len() > MAX_BLOCKS_PER_RESPONSE => Err("too many blocks"),
        AtpMessage::SoloChain { blocks } if blocks.len() > MAX_SOLO_CHAIN_BLOCKS => Err("too many solo blocks"),
        _ => Ok(()),
    }
}

// ── Создание статуса ────────────────────────────────────────
pub fn create_status(ctx: &SyncContext) -> AtpMessage {
    let val = ctx.validator.lock().unwrap();
    let utxo = val.utxo_set();
    AtpMessage::Status {
        height: val.last_block_height(),
        poh_tick: val.poh().current_tick_number(),
        state_root: utxo.get_state_root().0,
        total_supply: utxo.total_supply(),
        version: 1, capabilities: 0x01,
    }
}

// ── Запрос заголовков (автоматически чанками если нужно) ────
fn request_headers_chunked(peer_id: &[u8; 20], from: u64, to: u64, phase: &mut SyncPhase, peers: &Arc<PeersManager>) {
    let diff = to.saturating_sub(from);
    if diff <= MAX_HEADERS_PER_REQUEST {
        // Один запрос
        *phase = SyncPhase::AwaitingHeaders { peer_id: *peer_id, from, to, request_time: Instant::now(), retries: 0 };
        let req = AtpMessage::HeaderRequest { from, to };
        if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
    } else {
        // Чанковая загрузка
        let chunk_end = from + MAX_HEADERS_PER_REQUEST;
        *phase = SyncPhase::AwaitingHeadersChunked {
            peer_id: *peer_id, from, to, next_from: chunk_end + 1,
            request_time: Instant::now(), retries: 0,
        };
        let req = AtpMessage::HeaderRequest { from, to: chunk_end };
        if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
        CHUNKED_SYNCS.fetch_add(1, Ordering::Relaxed);
        tracing::info!("[SYNC] Chunked sync started: {}-{} (total {})", from, chunk_end, to);
    }
}

// ── Главный обработчик ─────────────────────────────────────
pub fn handle_atp_message(msg: AtpMessage, ctx: &Arc<SyncContext>, peer_id: &[u8; 20], peers: &Arc<PeersManager>) {
    if let Err(reason) = check_message_limits(&msg) {
        MESSAGE_LIMIT_REJECTED.fetch_add(1, Ordering::Relaxed);
        tracing::warn!("[SYNC] Message rejected from {}: {}", hex::encode(peer_id), reason);
        return;
    }

    match msg {
        AtpMessage::Status { height, version, .. } => {
            if version != 1 { tracing::warn!("[SYNC] Unsupported version {} from {}", version, hex::encode(peer_id)); return; }
            if height > 0 { let mut nh = ctx.network_height.lock().unwrap(); if height > *nh { *nh = height; } }
            peers.update_peer_height(peer_id, height);
            let my = ctx.validator.lock().unwrap().last_block_height();
            if height <= my { return; }
            let mut phase = ctx.sync_phase.lock();
            if *phase != SyncPhase::Idle && *phase != SyncPhase::Synced { return; }
            *ctx.sync_peer.lock() = Some(*peer_id);

            let diff = height.saturating_sub(my);
            if my == 0 || diff > SNAPSHOT_THRESHOLD {
                // Используем снапшот для больших разниц или новой ноды
                *phase = SyncPhase::AwaitingSnapshot { peer_id: *peer_id, request_time: Instant::now() };
                let req = AtpMessage::SnapshotRequest;
                if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
                tracing::info!("[SYNC] Snapshot requested: our={}, peer={}, diff={}", my, height, diff);
            } else {
                // Заголовки (чанками если > 2000)
                request_headers_chunked(peer_id, my + 1, height, &mut *phase, peers);
            }
            SYNC_PHASE_CHANGES.fetch_add(1, Ordering::Relaxed);
        }
        AtpMessage::SnapshotRequest => {}
        AtpMessage::SnapshotResponse { height, utxo_data, block_hash } => {
            let mut val = ctx.validator.lock().unwrap();
            if val.genesis_applied && val.last_block_height() > 0 { return; }
            if let Ok(utxo) = bincode::deserialize::<UtxoSet>(&utxo_data) {
                val.load_utxo_set(utxo); val.genesis_applied = true; val.set_last_block(Hash(block_hash), height, 0);
                let mut st = ctx.storage.lock().unwrap(); st.save_utxo_set(val.utxo_set()).ok(); drop(st);
                let nh = *ctx.network_height.lock().unwrap();
                if nh > height {
                    let mut phase = ctx.sync_phase.lock();
                    request_headers_chunked(peer_id, height + 1, nh, &mut *phase, peers);
                } else { let mut phase = ctx.sync_phase.lock(); *phase = SyncPhase::Synced; }
                SYNC_PHASE_CHANGES.fetch_add(1, Ordering::Relaxed);
                flush_block_buffer(ctx);
            }
        }
        AtpMessage::HeaderResponse { headers } => {
            if headers.is_empty() { return; }
            let from = headers.iter().map(|h| h.height).min().unwrap();
            let to = headers.iter().map(|h| h.height).max().unwrap();
            { let mut nh = ctx.network_height.lock().unwrap(); if to > *nh { *nh = to; } }

            // Проверяем целостность цепочки заголовков
            let our_last_hash = ctx.validator.lock().unwrap().last_block_hash().0;
            let mut expected_prev = our_last_hash;
            for h in &headers {
                if h.prev_hash != expected_prev {
                    tracing::warn!("[SYNC] Header chain broken at height {}", h.height);
                    let mut phase = ctx.sync_phase.lock(); *phase = SyncPhase::Idle; return;
                }
                expected_prev = h.block_hash;
            }

            let mut phase = ctx.sync_phase.lock();
            let old_phase = phase.clone();

            // Проверяем нужен ли следующий чанк
            if let SyncPhase::AwaitingHeadersChunked { peer_id: pid, from: total_from, to: total_to, next_from, .. } = &old_phase {
                if *next_from <= *total_to {
                    let chunk_end = (*next_from + MAX_HEADERS_PER_REQUEST).min(*total_to);
                    *phase = SyncPhase::AwaitingHeadersChunked {
                        peer_id: *pid, from: *total_from, to: *total_to,
                        next_from: chunk_end + 1, request_time: Instant::now(), retries: 0,
                    };
                    let req = AtpMessage::HeaderRequest { from: *next_from, to: chunk_end };
                    if let Ok(data) = bincode::serialize(&req) { peers.send_to(pid, data); }
                    tracing::info!("[SYNC] Chunked sync continue: {}-{} (total {})", *next_from, chunk_end, *total_to);
                    return;
                }
            }

            // Все заголовки получены — запрашиваем блоки
            *phase = SyncPhase::AwaitingBlocks { peer_id: *peer_id, from, to, request_time: Instant::now(), retries: 0 };
            let req = AtpMessage::BlockRequest { request_id: rand::random(), from, to };
            if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
            SYNC_PHASE_CHANGES.fetch_add(1, Ordering::Relaxed);
        }
        AtpMessage::BlockRequest { request_id, from, to } => {
            let st = ctx.storage.lock().unwrap();
            let mut blocks = Vec::new();
            for h in from..=to { if let Ok(Some(block)) = st.load_genesis_block(h) { if let Ok(bytes) = bincode::serialize(&block) { blocks.push((h, bytes)); } } }
            drop(st);
            let resp = AtpMessage::BlockResponse { request_id, blocks };
            if let Ok(data) = bincode::serialize(&resp) { peers.send_to(peer_id, data); }
        }
        AtpMessage::BlockResponse { blocks, .. } => {
            if let Some((last_h, _)) = blocks.last() { let mut nh = ctx.network_height.lock().unwrap(); if *last_h > *nh { *nh = *last_h; } }
            let mut buffer = ctx.block_buffer.lock().unwrap();
            for (height, bytes) in &blocks { buffer.insert(*height, bytes.clone()); }
            drop(buffer);
            flush_block_buffer(ctx);
            let val = ctx.validator.lock().unwrap(); let nh = *ctx.network_height.lock().unwrap();
            if val.last_block_height() >= nh { let mut phase = ctx.sync_phase.lock(); *phase = SyncPhase::Synced; }
        }
        AtpMessage::Transaction { bytes, .. } => {
            let gossip_msg = AtpMessage::Transaction { tx_hash: [0u8; 32], ttl: 0, bytes };
            if let Ok(data) = bincode::serialize(&gossip_msg) { peers.broadcast(data); }
        }
        AtpMessage::Ping { nonce } => { let pong = AtpMessage::Pong { nonce }; if let Ok(data) = bincode::serialize(&pong) { peers.send_to(peer_id, data); } }
        AtpMessage::SoloChain { blocks } => {
            let is_expected = ctx.pending_solo_requests.lock().unwrap().iter().any(|req| req.peer_id == *peer_id);
            if !is_expected { tracing::warn!("[SYNC] Unsolicited SoloChain from {}", hex::encode(peer_id)); return; }
            ctx.pending_solo_requests.lock().unwrap().retain(|req| req.peer_id != *peer_id);

            tracing::info!("[SYNC] Received SoloChain from {}: {} blocks", hex::encode(peer_id), blocks.len());
            let block_objs: Vec<Block> = blocks.iter().filter_map(|(_, bytes)| bincode::deserialize(bytes).ok()).collect();
            if !block_objs.is_empty() {
                let mut orch = ctx.orchestrator.lock().unwrap();
                let mut val = ctx.validator.lock().unwrap();
                let mut st = ctx.storage.lock().unwrap();
                match orch.accept_solo_chain(peer_id, &block_objs, &mut val, &mut st) {
                    Ok((count, reward, coeff)) => {
                        SOLO_CHAINS_PROCESSED.fetch_add(1, Ordering::Relaxed);
                        tracing::info!("[SYNC] SoloChain accepted: {} blocks, {} AEV reward, coeff={:.4}", count, reward as f64 / 100_000_000.0, coeff);
                        if let Some(last) = block_objs.last() { let mut nh = ctx.network_height.lock().unwrap(); if last.height > *nh { *nh = last.height; } }
                    }
                    Err(e) => tracing::warn!("[SYNC] SoloChain rejected: {}", e),
                }
            }
        }
        AtpMessage::SoloChainRequest => {
            tracing::info!("[SYNC] SoloChainRequest from {}", hex::encode(peer_id));
            let st = ctx.storage.lock().unwrap();
            let mut blocks = Vec::new();
            let our_h = ctx.validator.lock().unwrap().last_block_height();
            for h in 1..=our_h { if let Ok(Some(block)) = st.load_my_block(h) { if let Ok(bytes) = bincode::serialize(&block) { blocks.push((h, bytes)); } } }
            let block_count = blocks.len(); drop(st);
            if !blocks.is_empty() {
                let resp = AtpMessage::SoloChain { blocks };
                if let Ok(data) = bincode::serialize(&resp) { peers.send_to(peer_id, data); }
                tracing::info!("[SYNC] SoloChain sent to {}: {} blocks", hex::encode(peer_id), block_count);
            }
        }
        _ => {}
    }
}

// ── Таймауты ────────────────────────────────────────────────
pub fn check_sync_timeouts(ctx: &Arc<SyncContext>, _peers: &Arc<PeersManager>) {
    let mut phase = ctx.sync_phase.lock();
    match phase.clone() {
        SyncPhase::AwaitingSnapshot { .. } => {}
        SyncPhase::AwaitingHeaders { peer_id, from, to, request_time, retries } |
        SyncPhase::AwaitingHeadersChunked { peer_id, from, to, request_time, retries, .. } => {
            if request_time.elapsed().as_secs() > HEADERS_TIMEOUT_SECS {
                SYNC_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                if retries < MAX_RETRIES {
                    let new_retries = retries + 1;
                    // Повторяем запрос с теми же параметрами
                    *phase = SyncPhase::AwaitingHeaders { peer_id, from, to, request_time: Instant::now(), retries: new_retries };
                    let req = AtpMessage::HeaderRequest { from, to };
                    if let Ok(data) = bincode::serialize(&req) { _peers.send_to(&peer_id, data); }
                } else { *phase = SyncPhase::Idle; }
            }
        }
        SyncPhase::AwaitingBlocks { peer_id, from, to, request_time, retries } => {
            if request_time.elapsed().as_secs() > BLOCKS_TIMEOUT_SECS {
                SYNC_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
                if retries < MAX_RETRIES {
                    *phase = SyncPhase::AwaitingBlocks { peer_id, from, to, request_time: Instant::now(), retries: retries + 1 };
                    let req = AtpMessage::BlockRequest { request_id: rand::random(), from, to };
                    if let Ok(data) = bincode::serialize(&req) { _peers.send_to(&peer_id, data); }
                } else { *phase = SyncPhase::Idle; }
            }
        }
        _ => {}
    }
}

// ── Очистка pending solo requests ───────────────────────────
pub fn cleanup_pending_solo_requests(ctx: &SyncContext) {
    let mut pending = ctx.pending_solo_requests.lock().unwrap();
    let before = pending.len();
    pending.retain(|req| req.request_time.elapsed().as_secs() < PENDING_SOLO_REQUEST_TIMEOUT_SECS);
    let removed = before - pending.len();
    if removed > 0 { PENDING_SOLO_REQUESTS_CLEANED.fetch_add(removed as u64, Ordering::Relaxed); }
}

// ── Пакетная обработка блоков ──────────────────────────────
pub fn flush_block_buffer(ctx: &SyncContext) {
    let mut applied_total = 0u64;
    let mut need_fork = false;

    loop {
        let block_bytes = {
            let val = ctx.validator.lock().unwrap();
            let next = val.last_block_height() + 1;
            drop(val);
            let mut buffer = ctx.block_buffer.lock().unwrap();
            buffer.remove(&next)
        };
        let block_bytes = match block_bytes { Some(b) => b, None => break };
        let block: Block = match bincode::deserialize(&block_bytes) { Ok(b) => b, Err(_) => continue };

        let mut val = ctx.validator.lock().unwrap();
        let mut st = ctx.storage.lock().unwrap();
        if block.height > 0 && st.load_genesis_block(block.height).ok().flatten().is_some() && val.last_block_height() >= block.height { continue; }

        let original_hash = block.block_hash;
        match val.validate_and_apply(&mut block.clone()) {
            Ok(_) => { st.save_genesis_block(&block).ok(); st.save_utxo_set(val.utxo_set()).ok(); val.last_block_hash = original_hash; applied_total += 1; }
            Err(e) => { if format!("{:?}", e).contains("prev_hash") && val.last_block_height() > 0 { need_fork = true; } break; }
        }
    }

    if applied_total > 0 { tracing::info!("[SYNC] flush: applied {} blocks", applied_total); }

    if need_fork {
        if let Ok(mut orch) = ctx.orchestrator.lock() {
            let mut v = ctx.validator.lock().unwrap(); let mut s = ctx.storage.lock().unwrap();
            match orch.resolve_fork(&mut v, &mut s) {
                Ok(saved) => tracing::info!("[SYNC] Fork resolved: {} blocks saved", saved),
                Err(e) => tracing::error!("[SYNC] Fork resolution failed: {}", e),
            }
        }
    }
}
