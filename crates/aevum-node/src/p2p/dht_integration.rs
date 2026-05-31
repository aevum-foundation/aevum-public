use crate::p2p::dht::Dht;
use crate::p2p::peers::PeersManager;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

pub struct DhtIntegration {
    our_node_id: [u8; 32],
    our_addr: SocketAddr,
    peers: Arc<PeersManager>,
    last_announce: StdMutex<std::time::Instant>,
}

impl DhtIntegration {
    pub fn new(our_node_id: [u8; 32], our_addr: SocketAddr, peers: Arc<PeersManager>) -> Self {
        DhtIntegration {
            our_node_id, our_addr, peers,
            last_announce: StdMutex::new(std::time::Instant::now()),
        }
    }

    /// Сохранить себя в DHT
    pub fn announce_self(&self, dht: &mut Dht) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        dht.add_or_update(self.our_node_id, self.our_addr, now);
        *self.last_announce.lock().unwrap() = std::time::Instant::now();
        tracing::debug!("[DHT] Announced self: {}", self.our_addr);
    }

    /// Получить кандидатов из DHT
    pub fn get_dht_candidates(&self, dht: &Dht) -> Vec<SocketAddr> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        dht.random_nodes(50, now, 300).into_iter().map(|n| n.addr).collect()
    }

    /// Получить кандидатов из PeerDb (для совместимости)
    pub fn get_bootstrap_candidates(&self) -> Vec<SocketAddr> {
        self.peers.known_addresses_iter()
    }

    pub fn should_announce(&self) -> bool {
        self.last_announce.lock().unwrap().elapsed().as_secs() > 900
    }
}
