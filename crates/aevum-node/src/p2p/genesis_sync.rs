use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext};
use crate::storage::Storage;
use std::sync::Arc;

pub fn ensure_genesis(ctx: &SyncContext, peer_id: &[u8; 20], peers: &Arc<PeersManager>) -> bool {
    let val = ctx.validator.lock().unwrap();
    if val.genesis_applied {
        return true;
    }
    drop(val);

    let mut st = ctx.storage.lock().unwrap();
    if let Ok(Some(genesis)) = st.load_genesis_block(0) {
        let mut val = ctx.validator.lock().unwrap();
        if !val.genesis_applied {
            let mut g = genesis.clone();
            if val.validate_and_apply(&mut g).is_ok() {
                // Перезаписываем хеш оригинальным от пира
                val.last_block_hash = genesis.block_hash;
                tracing::info!("[GENESIS] Applied existing genesis from DB, hash={}", genesis.block_hash.to_hex());
                return true;
            }
        }
        return val.genesis_applied;
    }
    drop(st);

    tracing::info!("[GENESIS] Requesting block 0 from peer...");
    let req = AtpMessage::HeaderRequest { from: 0, to: 0 };
    if let Ok(data) = bincode::serialize(&req) {
        peers.send_to(peer_id, data);
    }
    false
}

pub fn apply_genesis(ctx: &SyncContext, block: &Block) -> bool {
    tracing::info!("[GENESIS-DEBUG] apply_genesis called, block.height={}", block.height);
    let mut val = ctx.validator.lock().unwrap();
    if val.genesis_applied {
        return true;
    }
    if block.height != 0 {
        return false;
    }

    let mut st = ctx.storage.lock().unwrap();
    if st.save_genesis_block(block).is_err() {
        return false;
    }

    let mut g = block.clone();
    match val.validate_and_apply(&mut g) {
        Ok(_) => {
            // Перезаписываем хеш оригинальным от пира
            val.last_block_hash = block.block_hash;
            tracing::info!("[GENESIS] Genesis applied! hash={}", block.block_hash.to_hex());
            st.save_utxo_set(val.utxo_set()).ok();
            true
        }
        Err(e) => {
            tracing::error!("[GENESIS] Failed to apply genesis: {:?}", e);
            false
        }
    }
}
