use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::crypto::hash::Hash;
use crate::p2p::peers::PeersManager;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};

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
    GetPeers { count: u8 },
    PeerList { addrs: Vec<([u8; 16], u16)> },
    ReadySignal,
    FindNode { target_id: [u8; 32], count: u8 },
    NodeList { nodes: Vec<([u8; 32], String)> },
    Ping { nonce: u64 }, Pong { nonce: u64 },
}

pub struct SyncContext {
    pub validator: Arc<StdMutex<Validator>>,
    pub storage: Arc<StdMutex<Storage>>,
    pub chain_sync: Arc<StdMutex<crate::sync::ChainSync>>,
    pub block_buffer: Arc<StdMutex<BTreeMap<u64, Vec<u8>>>>,
    pub dht: Arc<StdMutex<crate::p2p::dht::Dht>>,
    pub replication: Option<Arc<StdMutex<crate::encrypted_replication::EncryptedReplication>>>,
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
            let my = ctx.validator.lock().unwrap().last_block_height();
            if height > my {
                let from = if my == 0 { 1 } else { my + 1 };
                let req = AtpMessage::HeaderRequest { from, to: height };
                if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
            }
        }
        AtpMessage::HeaderRequest { from, to } => {
            let st = ctx.storage.lock().unwrap();
            let mut headers = Vec::new();
            for h in from..=to {
                if let Ok(Some(block)) = st.load_block(h) {
                    headers.push(BlockHeader {
                        height: block.height, block_hash: block.block_hash.0,
                        prev_hash: block.prev_hash.0,
                        poh_tick_start: block.poh_tick_start, poh_tick_end: block.poh_tick_end,
                        state_root: block.state_root.0, total_supply: block.total_supply,
                    });
                }
            }
            let resp = AtpMessage::HeaderResponse { headers };
            if let Ok(data) = bincode::serialize(&resp) { peers.send_to(peer_id, data); }
        }
        AtpMessage::HeaderResponse { headers } => {
            if !headers.is_empty() {
                let from = headers.iter().map(|h| h.height).min().unwrap();
                let to = headers.iter().map(|h| h.height).max().unwrap();
                let req = AtpMessage::BlockRequest { request_id: rand::random(), from, to };
                if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
            }
        }
        AtpMessage::BlockRequest { request_id, from, to } => {
            let st = ctx.storage.lock().unwrap();
            let mut blocks = Vec::new();
            for h in from..=to {
                if let Ok(Some(block)) = st.load_block(h) {
                    if let Ok(bytes) = bincode::serialize(&block) { blocks.push((h, bytes)); }
                }
            }
            let resp = AtpMessage::BlockResponse { request_id, blocks };
            if let Ok(data) = bincode::serialize(&resp) { peers.send_to(peer_id, data); }
        }
        AtpMessage::BlockResponse { blocks, .. } => {
            let mut buffer = ctx.block_buffer.lock().unwrap();
            for (height, bytes) in blocks { buffer.insert(height, bytes); }
            drop(buffer);
            flush_block_buffer_with_rollback(ctx, peer_id, peers);
        }
        AtpMessage::Ping { nonce } => {
            if let Ok(data) = bincode::serialize(&AtpMessage::Pong { nonce }) { peers.send_to(peer_id, data); }
        }
        AtpMessage::GetPeers { count } => {
            let msg = crate::p2p::pex::PeerExchange::create_peer_list(peers, count as usize);
            if let Ok(data) = bincode::serialize(&msg) { peers.send_to(peer_id, data); }
        }
        AtpMessage::PeerList { addrs } => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            crate::p2p::pex::PeerExchange::process_peer_list(&addrs, peers, now);
        }
        _ => {}
    }
}

fn flush_block_buffer_with_rollback(ctx: &SyncContext, peer_id: &[u8; 20], peers: &Arc<PeersManager>) {
    let mut val = ctx.validator.lock().unwrap();
    let mut st = ctx.storage.lock().unwrap();
    let mut buffer = ctx.block_buffer.lock().unwrap();
    let our_before = val.last_block_height();
    let mut applied = 0u64;

    loop {
        let next = val.last_block_height() + 1;
        if let Some(block_bytes) = buffer.remove(&next) {
            let block: Block = match bincode::deserialize(&block_bytes) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let height = block.height;
            match val.validate_and_apply(&mut block.clone()) {
                Ok(_) => {
                    st.save_block(&block).ok();
                    st.save_utxo_set(val.utxo_set()).ok();
                    ctx.chain_sync.lock().unwrap().mark_received(height);
                    applied += 1;
                }
                Err(e) => {
                    let err_str = format!("{:?}", e);
                    if err_str.contains("prev_hash") {
                        // Откатываемся до общего предка
                        if let Err(re) = rollback_to_height(&mut val, &mut st, height.saturating_sub(1)) {
                            tracing::warn!("[SYNC] Rollback failed: {}", re);
                        }
                        // Пропускаем этот блок — попробуем следующий
                        continue;
                    }
                    // Другие ошибки — останавливаем
                    break;
                }
            }
        } else {
            break;
        }
    }

    if applied > 0 {
        tracing::info!("[SYNC] Applied {} blocks, height: {} → {}", applied, our_before, val.last_block_height());
    }
}

fn rollback_to_height(val: &mut Validator, st: &mut Storage, target: u64) -> Result<(), String> {
    let current = val.last_block_height();
    if current <= target { return Ok(()); }
    for h in (target + 1..=current).rev() {
        st.delete_block(h).map_err(|e| format!("delete {}: {}", h, e))?;
    }
    if target == 0 {
        let genesis = st.load_block(0).map_err(|e| format!("genesis: {:?}", e))?.ok_or("no genesis")?;
        val.set_last_block(genesis.block_hash, 0, genesis.poh_tick_end);
    } else {
        let base = st.load_block(target).map_err(|e| format!("base: {:?}", e))?.ok_or("no base")?;
        val.set_last_block(base.block_hash, base.height, base.poh_tick_end);
    }
    Ok(())
}
