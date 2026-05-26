use crate::p2p::dht::{Dht, DhtNode};
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::AtpMessage;
use crate::p2p::pex;
use std::sync::Arc;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Интеграция DHT + PEX — авто-поиск пиров
pub struct DhtIntegration {
    pub dht: Dht,
    pub peers: Arc<PeersManager>,
    pub our_addr: SocketAddr,
    last_pex_broadcast: Instant,
    last_dht_lookup: Instant,
    pex_interval: Duration,
    dht_lookup_interval: Duration,
    peer_timeout_secs: u64,
}

impl DhtIntegration {
    pub fn new(our_id: [u8; 32], our_addr: SocketAddr, peers: Arc<PeersManager>) -> Self {
        DhtIntegration {
            dht: Dht::new(our_id),
            peers,
            our_addr,
            last_pex_broadcast: Instant::now(),
            last_dht_lookup: Instant::now(),
            pex_interval: Duration::from_secs(30),
            dht_lookup_interval: Duration::from_secs(60),
            peer_timeout_secs: 300,
        }
    }

    /// Добавить пира в DHT после успешного handshake
    pub fn on_peer_connected(&mut self, node_id: [u8; 32], addr: SocketAddr) {
        let now = Self::now_secs();
        self.dht.add_or_update(node_id, addr, now);
    }

    /// Создать PeerList для отправки пиру
    pub fn create_peer_list(&self) -> AtpMessage {
        let now = Self::now_secs();
        let nodes = self.dht.random_nodes(20, now, self.peer_timeout_secs);
        let addrs: Vec<([u8; 16], u16)> = nodes
            .into_iter()
            .map(|n| pex::socket_to_bytes(&n.addr))
            .collect();
        AtpMessage::PeerList { addrs }
    }

    /// Обработать полученный PeerList
    pub fn on_peer_list_received(&mut self, addrs: &[([u8; 16], u16)]) -> usize {
        let mut added = 0;
        let now = Self::now_secs();
        for (ip_bytes, port) in addrs {
            if let Some(addr) = pex::bytes_to_socket(*ip_bytes, *port) {
                if self.peers.can_accept(&addr) {
                    let mut node_id = [0u8; 32];
                    let hash = blake3::hash(addr.to_string().as_bytes());
                    node_id.copy_from_slice(&hash.as_bytes()[..32]);
                    self.dht.add_or_update(node_id, addr, now);
                    self.peers.add_known_address(addr, now);
                    added += 1;
                }
            }
        }
        if added > 0 {
            tracing::info!("[DHT] Added {} peers from PeerList", added);
        }
        added
    }

    /// Периодическая проверка — нужно ли искать новых пиров
    pub fn should_lookup(&mut self) -> bool {
        if self.last_dht_lookup.elapsed() >= self.dht_lookup_interval {
            self.last_dht_lookup = Instant::now();
            true
        } else {
            false
        }
    }

    /// Периодическая проверка — нужно ли рассылать PEX
    pub fn should_broadcast_pex(&mut self) -> bool {
        if self.last_pex_broadcast.elapsed() >= self.pex_interval {
            self.last_pex_broadcast = Instant::now();
            true
        } else {
            false
        }
    }

    /// Получить случайных пиров для подключения
    pub fn get_bootstrap_candidates(&self) -> Vec<SocketAddr> {
        let now = Self::now_secs();
        self.dht.random_nodes(8, now, self.peer_timeout_secs)
            .into_iter()
            .map(|n| n.addr)
            .collect()
    }

    /// Количество известных пиров
    pub fn known_peers_count(&self) -> usize {
        let now = Self::now_secs();
        self.dht.alive_nodes(now, self.peer_timeout_secs)
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
