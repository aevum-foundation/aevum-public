use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::transaction::Transaction;
use crate::mempool::Mempool;
use crate::storage::Storage;
use crate::sync::ChainSync;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext};

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub struct AtpNode {
    peers: Arc<PeersManager>,
    sync_ctx: Arc<SyncContext>,
    listen_addr: String,
    bootstrap_peers: String,
}

impl AtpNode {
    pub async fn new(
        listen_addr: &str,
        bootstrap_peers: &str,
        validator: Arc<StdMutex<Validator>>,
        storage: Arc<StdMutex<Storage>>,
        chain_sync: Arc<StdMutex<ChainSync>>,
        mempool: Arc<StdMutex<Mempool>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let our_key = aevum::crypto::keys::PrivateKey::generate();

        let peers = Arc::new(PeersManager::new(our_key));
        let sync_ctx = Arc::new(SyncContext {
            validator,
            storage,
            chain_sync,
            block_buffer: Arc::new(StdMutex::new(BTreeMap::new())),
            replication: None,
            dht: Arc::new(StdMutex::new(crate::p2p::dht::Dht::new([0u8; 32]))),
            orchestrator: Arc::new(std::sync::Mutex::new(crate::p2p::chain_orchestrator::ChainOrchestrator::new())),
        });

        Ok(Self {
            peers,
            sync_ctx,
            listen_addr: listen_addr.to_string(),
            bootstrap_peers: bootstrap_peers.to_string(),
        })
    }

    pub fn start(&self) {
        let _peers = self.peers.clone();
        let _sync_ctx = self.sync_ctx.clone();
        let listen_addr = self.listen_addr.clone();
        let bootstrap = self.bootstrap_peers.clone();

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move {
                // Сервер
                let listener = TcpListener::bind(&listen_addr).await.unwrap();
                tracing::info!("[ATP] Listening on {}", listen_addr);

                // Bootstrap
                if !bootstrap.is_empty() {
                    for addr_str in bootstrap.split(',') {
                        if let Ok(addr) = addr_str.trim().parse::<SocketAddr>() {
                            tracing::info!("[ATP] Dialing {}", addr);
                            // В реальном коде здесь dial
                        }
                    }
                }

                loop {
                    let (stream, addr) = listener.accept().await.unwrap();
                    tracing::info!("[ATP] Connection from {}", addr);
                    // В реальном коде здесь accept + handshake
                }
            });
        });
    }
}
