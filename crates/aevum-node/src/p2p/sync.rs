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
    Status {
        height: u64,
        poh_tick: u64,
        state_root: [u8; 32],
        total_supply: u64,
        version: u32,
        capabilities: u32,
    },
    BlockRequest {
        request_id: u64,
        from: u64,
        to: u64,
    },
    BlockResponse {
        request_id: u64,
        blocks: Vec<(u64, Vec<u8>)>,
    },
    Transaction {
        tx_hash: [u8; 32],
        ttl: u8,
        bytes: Vec<u8>,
    },
    Ping { nonce: u64 },
    Pong { nonce: u64 },
}

pub struct SyncContext {
    pub validator: Arc<StdMutex<Validator>>,
    pub storage: Arc<StdMutex<Storage>>,
    pub chain_sync: Arc<StdMutex<ChainSync>>,
    pub block_buffer: Arc<StdMutex<BTreeMap<u64, Vec<u8>>>>,
}

/// Обработать входящее ATP сообщение
pub fn handle_atp_message(
    msg: AtpMessage,
    ctx: &SyncContext,
    peer_id: &[u8; 20],
    peers: &PeersManager,
) {
    match msg {
        AtpMessage::Status { height, .. } => {
            let my = ctx.validator.lock().unwrap().last_block_height();
            tracing::info!("📊 Peer {} height: {}, my: {}", hex::encode(peer_id), height, my);
            
            if height > my {
                let to = (my + 1 + MAX_BLOCKS_PER_REQUEST).min(height);
                let req = AtpMessage::BlockRequest {
                    request_id: rand::random(),
                    from: my + 1,
                    to,
                };
                if let Ok(data) = bincode::serialize(&req) {
                    peers.send_to(peer_id, data);
                }
            }
        }
        AtpMessage::BlockRequest { request_id, from, to } => {
            tracing::info!("📥 Block request {}-{} (req={})", from, to, request_id);
            let st = ctx.storage.lock().unwrap();
            let mut blocks = Vec::new();
            
            for h in from..=to {
                if let Ok(Some(b)) = st.load_block(h) {
                    if let Ok(block_bytes) = bincode::serialize(&b) {
                        blocks.push((h, block_bytes));
                    }
                }
            }
            drop(st);
            
            let resp = AtpMessage::BlockResponse { request_id, blocks };
            if let Ok(data) = bincode::serialize(&resp) {
                peers.send_to(peer_id, data);
            }
        }
        AtpMessage::BlockResponse { blocks, .. } => {
            let mut buffer = ctx.block_buffer.lock().unwrap();
            
            for (height, block_bytes) in blocks {
                if buffer.len() >= MAX_BUFFERED_BLOCKS {
                    if let Some(oldest_key) = buffer.keys().next().cloned() {
                        buffer.remove(&oldest_key);
                    }
                }
                buffer.insert(height, block_bytes);
            }
            drop(buffer);
            
            flush_block_buffer(ctx);
        }
        AtpMessage::Ping { nonce } => {
            let pong = AtpMessage::Pong { nonce };
            if let Ok(data) = bincode::serialize(&pong) {
                peers.send_to(peer_id, data);
            }
        }
        _ => {}
    }
}

/// Создать статус-сообщение
pub fn create_status(ctx: &SyncContext) -> AtpMessage {
    let val = ctx.validator.lock().unwrap();
    AtpMessage::Status {
        height: val.last_block_height(),
        poh_tick: val.poh().current_tick_number(),
        state_root: val.utxo_set().state_root().0,
        total_supply: val.utxo_set().total_supply(),
        version: 1,
        capabilities: 0x01,
    }
}

/// Применить все последовательные блоки из буфера
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
                    tracing::warn!("Block {} failed: {:?}", next, e);
                    next += 1;
                }
            }
        } else {
            break;
        }
    }
}
