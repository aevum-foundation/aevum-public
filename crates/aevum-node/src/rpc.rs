use crate::mempool::Mempool;
use crate::storage::Storage;
use aevum::core::block::Block;
use aevum::core::state::UtxoSet;
use aevum::core::transaction::Transaction;
use aevum::crypto::hash::Hash;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Serialize)]
pub struct BlockInfo {
    pub height: u64,
    pub hash: String,
    pub prev_hash: String,
    pub transactions: usize,
    pub useful_solution: bool,
}

#[derive(Serialize)]
pub struct TxInfo {
    pub hash: String,
    pub inputs: usize,
    pub outputs: usize,
}

#[derive(Serialize)]
pub struct NodeStatus {
    pub height: u64,
    pub peers: usize,
    pub mempool_size: usize,
    pub utxo_count: usize,
}

pub struct RpcHandler {
    pub mempool: Arc<Mutex<Mempool>>,
    pub storage: Arc<Mutex<Storage>>,
    pub peer_count: Arc<Mutex<usize>>,
    pub last_height: Arc<Mutex<u64>>,
}

impl RpcHandler {
    pub fn new(
        mempool: Arc<Mutex<Mempool>>,
        storage: Arc<Mutex<Storage>>,
        peer_count: Arc<Mutex<usize>>,
        last_height: Arc<Mutex<u64>>,
    ) -> Self {
        RpcHandler {
            mempool,
            storage,
            peer_count,
            last_height,
        }
    }

    pub async fn handle(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        match method {
            "getblockbyheight" => {
                let height = params[0].as_u64().unwrap_or(0);
                let st = self.storage.lock().await;
                match st.load_block(height).ok().flatten() {
                    Some(b) => serde_json::json!(BlockInfo {
                        height: b.height,
                        hash: hex::encode(b.block_hash.as_bytes()),
                        prev_hash: hex::encode(b.prev_hash.as_bytes()),
                        transactions: b.transactions.len(),
                        useful_solution: b.useful_solution.is_some(),
                    }),
                    None => serde_json::json!({"error": "not found"}),
                }
            }
            "getstatus" => {
                let peers = *self.peer_count.lock().await;
                let height = *self.last_height.lock().await;
                let mempool_size = self.mempool.lock().await.len();
                let utxo_count = {
                    let st = self.storage.lock().await;
                    st.load_utxo_set().map(|u| u.len()).unwrap_or(0)
                };
                serde_json::json!(NodeStatus {
                    height,
                    peers,
                    mempool_size,
                    utxo_count
                })
            }
            _ => serde_json::json!({"error": "method not found"}),
        }
    }
}
