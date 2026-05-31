pub mod framing;
pub mod gossip;
pub mod noise;
pub mod peers;
pub mod sync;
pub mod sync_dispatcher;
pub mod snapshot_cipher;

use aevum::consensus::validator::Validator;
use crate::mempool::Mempool;
use crate::storage::Storage;
use crate::sync::ChainSync;
use std::sync::{Arc, Mutex as StdMutex};
use std::collections::HashSet;
pub type PeerId = [u8; 20];

pub struct NodeContext {
    pub validator: Arc<StdMutex<Validator>>,
    pub mempool: Arc<StdMutex<Mempool>>,
    pub storage: Arc<StdMutex<Storage>>,
    pub chain_sync: Arc<StdMutex<ChainSync>>,
    pub peer_count: Arc<StdMutex<usize>>,
}

pub struct P2pNode {
    connected_peers: Arc<StdMutex<HashSet<PeerId>>>,
    bootstrap_peers: Vec<String>,
    listen_addr: String,
    context: Arc<NodeContext>,
}

pub struct P2pHandle {
    pub sender: crossbeam::channel::Sender<P2pCommand>,
}

#[derive(Debug)]
pub enum P2pCommand {
    BroadcastTransaction(Vec<u8>),
    BroadcastBlock(Vec<u8>),
}

impl P2pNode {
    pub async fn new(listen_addr: &str, bootstrap_peers: Vec<String>, context: Arc<NodeContext>) -> Result<(Self, P2pHandle), Box<dyn std::error::Error>> {
        let (cmd_tx, _) = crossbeam::channel::unbounded();
        let node = P2pNode {
            connected_peers: Arc::new(StdMutex::new(HashSet::new())),
            bootstrap_peers,
            listen_addr: listen_addr.to_string(),
            context,
        };
        let handle = P2pHandle { sender: cmd_tx };
        Ok((node, handle))
    }

    pub fn start(self) -> P2pHandle {
        let (cmd_tx, _) = crossbeam::channel::unbounded();
        P2pHandle { sender: cmd_tx }
    }
}

pub mod connection;
pub mod dht;
pub mod peer_score;
pub mod addr_manager;
pub mod snapshots;
pub use noise::AtpCipher as NoiseCipher;
pub mod pex;
pub mod peer_db;
pub mod connection_manager;
pub mod chain_orchestrator;
pub mod genesis_sync;
pub mod dht_integration;
