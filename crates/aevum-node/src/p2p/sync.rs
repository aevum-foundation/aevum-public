use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use crate::storage::Storage;
use crate::sync::ChainSync;
use crate::p2p::peers::PeersManager;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};

const MAX_BLOCKS_PER_REQUEST: u64 = 500;
const MAX_BUFFERED_BLOCKS: usize = 2000;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AtpMessage {
    Status { height: u64, poh_tick: u64, state_root: [u8; 32], total_supply: u64, version: u32, capabilities: u32 },
    HeaderRequest { from: u64, to: u64 },
    HeaderResponse { headers: Vec<BlockHeader> },
    BlockRequest { request_id: u64, from: u64, to: u64 },
    BlockResponse { request_id: u64, blocks: Vec<(u64, Vec<u8>)> },
    Transaction { tx_hash: [u8; 32], ttl: u8, bytes: Vec<u8> },
    BlobRequest { blob_hashes: Vec<[u8; 32]> },
    BlobResponse { blobs: Vec<crate::encrypted_replication::EncryptedBlob> },
    Ping { nonce: u64 },
    ReadySignal,
    Pong { nonce: u64 },
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub state_root: [u8; 32],
}

pub struct SyncContext {
    pub validator: Arc<StdMutex<Validator>>,
    pub storage: Arc<StdMutex<Storage>>,
    pub chain_sync: Arc<StdMutex<ChainSync>>,
    pub block_buffer: Arc<StdMutex<BTreeMap<u64, Vec<u8>>>>,
    pub replication: Option<Arc<StdMutex<crate::encrypted_replication::EncryptedReplication>>>,
}

pub fn handle_atp_message(msg: AtpMessage, ctx: &Arc<SyncContext>, peer_id: &[u8; 20], peers: &Arc<PeersManager>) {
    match msg {
        AtpMessage::Status { height, state_root, .. } => { tracing::info!("[SYNC] Status");
            let my = ctx.validator.lock().unwrap().last_block_height();
            tracing::info!("📊 Peer {} height: {}, my: {}, state_root: {}", hex::encode(peer_id), height, my, hex::encode(&state_root));
            if height > my {
                let from = if my == 0 { 1 } else { my + 1 };
                let req = AtpMessage::HeaderRequest { from, to: height };
                if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
            }
        }
        AtpMessage::HeaderRequest { from, to } => {
            tracing::info!("📥 Header request {}-{}", from, to);
            let st = ctx.storage.lock().unwrap();
            let mut headers = Vec::new();
            for h in from..=to {
                if let Ok(Some(b)) = st.load_block(h) {
                    headers.push(BlockHeader { height: b.height, block_hash: b.block_hash.0, prev_hash: b.prev_hash.0, state_root: b.state_root.0 });
                }
            }
            drop(st);
            if let Ok(data) = bincode::serialize(&AtpMessage::HeaderResponse { headers }) { peers.send_to(peer_id, data); }
        }
        AtpMessage::HeaderResponse { headers } => {
            if let Some(last) = headers.last() {
                let my = ctx.validator.lock().unwrap().last_block_height();
                if last.height > my {
                    let req = AtpMessage::BlockRequest { request_id: rand::random(), from: my + 1, to: (my + MAX_BLOCKS_PER_REQUEST).min(last.height) };
                    if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
                }
            }
        }
        AtpMessage::BlockRequest { request_id, from, to } => {
            tracing::info!("📥 Block request {}-{} (req={})", from, to, request_id);
            let st = ctx.storage.lock().unwrap();
            let mut blocks = Vec::new();
            for h in from..=to {
                if let Ok(Some(b)) = st.load_block(h) {
                    if let Ok(block_bytes) = bincode::serialize(&b) { blocks.push((h, block_bytes)); }
                }
            }
            drop(st);
            if let Ok(data) = bincode::serialize(&AtpMessage::BlockResponse { request_id, blocks }) { peers.send_to(peer_id, data); }
        }
        AtpMessage::BlockResponse { blocks, .. } => { tracing::info!("[SYNC] BlockResponse({})", blocks.len());
            let mut buffer = ctx.block_buffer.lock().unwrap();
            for (height, block_bytes) in blocks {
                if buffer.len() >= MAX_BUFFERED_BLOCKS {
                    if let Some(oldest) = buffer.keys().next().cloned() { buffer.remove(&oldest); }
                }
                buffer.insert(height, block_bytes);
            }
            drop(buffer);
            flush_block_buffer(ctx);
        }
        AtpMessage::ReadySignal => { tracing::info!("[SYNC] ReadySignal received from {}", hex::encode(peer_id)); }
        AtpMessage::Ping { nonce } => {
            if let Ok(data) = bincode::serialize(&AtpMessage::Pong { nonce }) { peers.send_to(peer_id, data); }
        }
        AtpMessage::BlobRequest { blob_hashes } => { tracing::info!("[SYNC] BlobRequest({})", blob_hashes.len());
            if let Some(rep) = ctx.replication.as_ref() {
                let rep = rep.lock().unwrap();
                let blobs = rep.query_blobs_by_hash(&blob_hashes);
                let resp = AtpMessage::BlobResponse { blobs };
                if let Ok(data) = bincode::serialize(&resp) { peers.send_to(peer_id, data); }
            }
        }
        AtpMessage::BlobResponse { blobs } => { tracing::info!("[SYNC] BlobResponse({})", blobs.len());
            if let Some(rep) = ctx.replication.as_ref() {
                let mut rep = rep.lock().unwrap();
                for blob in blobs { rep.store_received(blob); }
            }
        }
        _ => {}
    }
}

pub fn create_status(ctx: &SyncContext) -> AtpMessage {
    let val = ctx.validator.lock().unwrap();
    AtpMessage::Status {
        height: val.last_block_height(),
        poh_tick: val.poh().current_tick_number(),
        state_root: { let mut u = val.utxo_set().clone(); u.state_root().0 },
        total_supply: val.utxo_set().total_supply(),
        version: 1, capabilities: 0x01,
    }
}

pub fn flush_block_buffer(ctx: &SyncContext) {
    let mut val = ctx.validator.lock().unwrap();
    let mut st = ctx.storage.lock().unwrap();
    let mut buffer = ctx.block_buffer.lock().unwrap();
    let mut next = val.last_block_height() + 1;

    while let Some(block_bytes) = buffer.remove(&next) {
        if let Ok(block) = bincode::deserialize::<Block>(&block_bytes) {
            let mut b = block;
            match val.validate_and_apply(&mut b) {
                Ok(_) => {
                    st.save_block(&b).ok();
                    st.save_utxo_set(val.utxo_set()).ok();
                    ctx.chain_sync.lock().unwrap().mark_received(b.height);
                    tracing::info!("📦 Synced block at height {}", b.height);
                    next += 1;
                }
                Err(e) => {
                    let err_msg = format!("{:?}", e);
                    tracing::warn!("Block {} failed: {}", next, err_msg);
                    if err_msg.contains("prev_hash") {
                        tracing::warn!("🔄 Fork at height {}: rewinding for peer chain", next);
                        if let Some(my_block) = st.load_block(next).ok().flatten() {
                            for tx in &my_block.transactions {
                                for input in &tx.inputs {
                                    if let Ok(Some(utxo_data)) = st.load_metadata(&format!("utxo_backup_{}", hex::encode(input.nullifier.as_bytes()))) {
                                        if let Ok(utxo) = bincode::deserialize(&utxo_data) {
                                            val.utxo_set_mut().add(utxo);
                                        }
                                    }
                                }
                            }
                        }
                        st.delete_block(next).ok();
                        if val.validate_and_apply(&mut b).is_ok() {
                            st.save_block(&b).ok();
                            st.save_utxo_set(val.utxo_set()).ok();
                            ctx.chain_sync.lock().unwrap().mark_received(b.height);
                            tracing::info!("📦 Synced block at height {} (fork resolved)", b.height);
                        }
                    }
                    next += 1;
                }
            }
        } else { break; }
    }
}
