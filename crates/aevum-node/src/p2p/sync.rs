use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::state::UtxoSet;
use aevum::crypto::hash::Hash;
use crate::p2p::peers::PeersManager;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use parking_lot::Mutex as PlMutex;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq)]
pub enum SyncPhase {
    Idle,
    AwaitingSnapshot { peer_id: [u8; 20], request_time: Instant },
    AwaitingHeaders { peer_id: [u8; 20], from: u64, to: u64, request_time: Instant, retries: u8 },
    AwaitingBlocks { peer_id: [u8; 20], from: u64, to: u64, request_time: Instant, retries: u8 },
    Synced,
}

const SNAPSHOT_TIMEOUT_SECS: u64 = 30;
const HEADERS_TIMEOUT_SECS: u64 = 15;
const BLOCKS_TIMEOUT_SECS: u64 = 30;
const MAX_RETRIES: u8 = 3;

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
}

pub fn find_best_peer(peers: &Arc<PeersManager>, _network_height: &Arc<StdMutex<u64>>) -> Option<[u8; 20]> {
    let peer_ids: Vec<[u8; 20]> = peers.peers.iter().map(|e| *e.key()).collect();
    if peer_ids.is_empty() { None } else {
        use rand::seq::SliceRandom;
        Some(*peer_ids.choose(&mut rand::thread_rng()).unwrap())
    }
}

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

pub fn handle_atp_message(msg: AtpMessage, ctx: &Arc<SyncContext>, peer_id: &[u8; 20], peers: &Arc<PeersManager>) {
    match msg {
        AtpMessage::Status { height, .. } => {
            if height > 0 { let mut nh = ctx.network_height.lock().unwrap(); if height > *nh { *nh = height; } }
            let my = ctx.validator.lock().unwrap().last_block_height();
            if height <= my { return; }
            let mut phase = ctx.sync_phase.lock();
            if *phase != SyncPhase::Idle && *phase != SyncPhase::Synced { return; }
            *ctx.sync_peer.lock() = Some(*peer_id);
            if my == 0 {
                *phase = SyncPhase::AwaitingSnapshot { peer_id: *peer_id, request_time: Instant::now() };
            } else {
                let from = my + 1;
                *phase = SyncPhase::AwaitingHeaders { peer_id: *peer_id, from, to: height, request_time: Instant::now(), retries: 0 };
                let req = AtpMessage::HeaderRequest { from, to: height };
                if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
            }
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
                    let from = height + 1;
                    let mut phase = ctx.sync_phase.lock();
                    *phase = SyncPhase::AwaitingHeaders { peer_id: *peer_id, from, to: nh, request_time: Instant::now(), retries: 0 };
                    let req = AtpMessage::HeaderRequest { from, to: nh };
                    if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
                } else { let mut phase = ctx.sync_phase.lock(); *phase = SyncPhase::Synced; }
                flush_block_buffer(ctx);
            }
        }
        AtpMessage::HeaderResponse { headers } => {
            if headers.is_empty() { return; }
            let from = headers.iter().map(|h| h.height).min().unwrap();
            let to = headers.iter().map(|h| h.height).max().unwrap();
            { let mut nh = ctx.network_height.lock().unwrap(); if to > *nh { *nh = to; } }
            let our_last_hash = ctx.validator.lock().unwrap().last_block_hash().0;
            let mut expected_prev = our_last_hash;
            for h in &headers { if h.prev_hash != expected_prev { let mut phase = ctx.sync_phase.lock(); *phase = SyncPhase::Idle; return; } expected_prev = h.block_hash; }
            let mut phase = ctx.sync_phase.lock();
            *phase = SyncPhase::AwaitingBlocks { peer_id: *peer_id, from, to, request_time: Instant::now(), retries: 0 };
            let req = AtpMessage::BlockRequest { request_id: rand::random(), from, to };
            if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
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
        AtpMessage::Ping { nonce } => {
            let pong = AtpMessage::Pong { nonce };
            if let Ok(data) = bincode::serialize(&pong) { peers.send_to(peer_id, data); }
        }
        _ => {}
    }
}

pub fn check_sync_timeouts(ctx: &Arc<SyncContext>, _peers: &Arc<PeersManager>) {
    let mut phase = ctx.sync_phase.lock();
    match phase.clone() {
        SyncPhase::AwaitingSnapshot { .. } => {}
        SyncPhase::AwaitingHeaders { peer_id, from, to, request_time, retries } => {
            if request_time.elapsed().as_secs() > HEADERS_TIMEOUT_SECS {
                if retries < MAX_RETRIES {
                    *phase = SyncPhase::AwaitingHeaders { peer_id, from, to, request_time: Instant::now(), retries: retries + 1 };
                    let req = AtpMessage::HeaderRequest { from, to };
                    if let Ok(data) = bincode::serialize(&req) { _peers.send_to(&peer_id, data); }
                } else { *phase = SyncPhase::Idle; }
            }
        }
        SyncPhase::AwaitingBlocks { peer_id, from, to, request_time, retries } => {
            if request_time.elapsed().as_secs() > BLOCKS_TIMEOUT_SECS {
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

pub fn flush_block_buffer(ctx: &SyncContext) {
    let mut val = ctx.validator.lock().unwrap();
    if !val.genesis_applied { return; }
    let mut st = ctx.storage.lock().unwrap();
    let mut buffer = ctx.block_buffer.lock().unwrap();
    let our_before = val.last_block_height();
    let mut applied = 0u64;
    let mut need_fork = false;
    loop {
        let next = val.last_block_height() + 1;
        if let Some(block_bytes) = buffer.remove(&next) {
            let block: Block = match bincode::deserialize(&block_bytes) { Ok(b) => b, Err(_) => continue };
            if block.height > 0 && st.load_genesis_block(block.height).ok().flatten().is_some() && val.last_block_height() >= block.height { continue; }
            let original_hash = block.block_hash;
            match val.validate_and_apply(&mut block.clone()) {
                Ok(_) => { st.save_genesis_block(&block).ok(); st.save_utxo_set(val.utxo_set()).ok(); val.last_block_hash = original_hash; applied += 1; }
                Err(e) => { if format!("{:?}", e).contains("prev_hash") && val.last_block_height() > 0 { need_fork = true; } break; }
            }
        } else { break; }
    }
    if applied > 0 { tracing::info!("[SYNC] flush: applied {} blocks, height {} -> {}", applied, our_before, val.last_block_height()); }
    drop(buffer); drop(st); drop(val);
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
