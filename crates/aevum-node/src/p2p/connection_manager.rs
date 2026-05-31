use crate::p2p::peers::PeersManager;
use crate::p2p::sync::SyncContext;
use crate::p2p::noise::TofuStore;
use crate::p2p::connection::AtpConnection;
use crate::p2p::pex::PeerExchange;
use aevum::crypto::keys::PrivateKey;
use std::collections::{HashSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

const MAX_PEERS: usize = 8;
const SCAN_INTERVAL: Duration = Duration::from_secs(10);
const GOSSIP_INTERVAL: Duration = Duration::from_secs(300);
const MAX_CANDIDATES: usize = 20;

pub struct ConnectionManager {
    peers: Arc<PeersManager>,
    sync_ctx: Arc<SyncContext>,
    our_key: PrivateKey,
    tofu: Arc<tokio::sync::Mutex<TofuStore>>,
    bootstrap_peers: Vec<String>,
    shutdown: Arc<AtomicBool>,
    handles: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    last_gossip: Instant,
}

impl ConnectionManager {
    pub fn new(
        peers: Arc<PeersManager>,
        sync_ctx: Arc<SyncContext>,
        our_key: PrivateKey,
        tofu: Arc<tokio::sync::Mutex<TofuStore>>,
        bootstrap_peers: Vec<String>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        ConnectionManager {
            peers, sync_ctx, our_key, tofu, bootstrap_peers, shutdown,
            handles: Arc::new(StdMutex::new(Vec::new())),
            last_gossip: Instant::now(),
        }
    }

    pub async fn run(mut self) {
        self.scan_and_connect().await;
        loop {
            if self.shutdown.load(Ordering::SeqCst) { break; }
            self.scan_and_connect().await;
            if self.last_gossip.elapsed() >= GOSSIP_INTERVAL {
                self.gossip_all_addresses();
                self.last_gossip = Instant::now();
            }
            tokio::time::sleep(SCAN_INTERVAL).await;
        }
        self.shutdown_handles().await;
    }

    async fn scan_and_connect(&self) {
        let connected: HashSet<SocketAddr> = self.peers.connected_addr_set();
        // Группируем по IP — bootstrap_peers имеют приоритет
        let mut unique: HashMap<String, SocketAddr> = HashMap::new();
        // Сначала bootstrap (высший приоритет)
        for addr_str in &self.bootstrap_peers {
            if let Ok(addr) = addr_str.trim().parse() {
                if !connected.contains(&addr) { unique.insert(addr.ip().to_string(), addr); }
            }
        }
        // Потом DHT
        {
            let dht = self.sync_ctx.dht.lock().unwrap();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            for node in dht.random_nodes(50, now, 300) {
                let key = node.addr.ip().to_string();
                if !connected.contains(&node.addr) { unique.entry(key).or_insert(node.addr); }
            }
        }
        // Потом PeerDb (низший приоритет — не перезаписываем)
        for addr in self.peers.known_addresses_iter() {
            let key = addr.ip().to_string();
            if !connected.contains(&addr) { unique.entry(key).or_insert(addr); }
        }
        
        let candidates: Vec<SocketAddr> = unique.into_values().take(MAX_CANDIDATES).collect();
        if candidates.is_empty() { return; }
        
        let peer_count = self.peers.peer_count();
        tracing::info!("[CONNMGR] {} unique candidates (peers={})", candidates.len(), peer_count);
        
        for addr in &candidates {
            if self.shutdown.load(Ordering::SeqCst) { break; }
            if self.peers.peer_count() >= MAX_PEERS { break; }
            if connected.contains(addr) { continue; }
            match crate::p2p::peers::dial_peer(*addr, self.our_key.clone(), &self.tofu).await {
                Ok((cipher, peer_id, reader, writer)) => {
                    tracing::info!("[CONNMGR] ✅ Connected to {}", addr);
                    let conn = AtpConnection::new(cipher, peer_id, *addr, self.peers.clone(), self.sync_ctx.clone(), false);
                    let h = tokio::spawn(async move { conn.run(reader, writer).await; });
                    self.handles.lock().unwrap().push(h);
                    PeerExchange::request_peers(&self.peers, &peer_id);
                }
                Err(e) => { tracing::debug!("[CONNMGR] {} — {}", addr, e); }
            }
        }
    }

    fn gossip_all_addresses(&self) {
        let addrs = self.peers.known_addresses_iter();
        if addrs.is_empty() { return; }
        let addr_bytes: Vec<([u8; 16], u16)> = addrs.iter().map(|a| crate::p2p::pex::socket_to_bytes(a)).collect();
        let msg = crate::p2p::sync::AtpMessage::PeerList { addrs: addr_bytes };
        if let Ok(data) = bincode::serialize(&msg) {
            self.peers.broadcast(data);
            tracing::info!("[CONNMGR] Gossiped {} addresses", addrs.len());
        }
    }

    async fn shutdown_handles(&self) {
        let handles: Vec<JoinHandle<()>> = self.handles.lock().unwrap().drain(..).collect();
        for h in handles { let _ = tokio::time::timeout(Duration::from_secs(5), h).await; }
    }
}
