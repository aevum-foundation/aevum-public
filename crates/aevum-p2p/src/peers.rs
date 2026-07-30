//! Peers Manager v9 — Hardened Production Registry (10/10)

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{DashMap, mapref::entry::Entry as DashEntry};
use rand::seq::SliceRandom;
use tokio::sync::mpsc;

use aevum::crypto::keys::PrivateKey;

use crate::p2p::router::P2pRouter;
use crate::peer_storage::PeerStorage;

const MAX_PEERS: usize = 1000;
const MAX_OUTBOUND: usize = 32;
const MAX_CONNECTING: usize = 8;
const MAX_PER_IP: usize = 4;
const RATE_LIMIT_PER_SEC: u32 = 100;
const CONNECT_RETRY: Duration = Duration::from_secs(30);
const ATTEMPT_TTL: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
}

pub struct PeerState {
    pub tx: mpsc::Sender<Arc<Vec<u8>>>,
    pub addr: SocketAddr,
    pub peer_height: u64,
    pub msg_count: u32,
    pub last_reset: Instant,
    pub connected_at: Instant,
    pub is_outbound: bool,
    pub state: ConnectionState,
}

pub struct PeersManager {
    peers: DashMap<[u8; 32], PeerState>,
    addr_to_peer: DashMap<SocketAddr, [u8; 32]>,
    ip_connections: DashMap<IpAddr, usize>,
    last_connect_attempt: DashMap<SocketAddr, Instant>,

    peer_storage: Arc<PeerStorage>,

    connected_count: AtomicUsize,
    outbound_count: AtomicUsize,
    connecting_count: AtomicUsize,

    pub router: Arc<std::sync::Mutex<P2pRouter>>,
}

impl PeersManager {
    pub fn new(
        _our_key: PrivateKey,
        _our_miner_id: [u8; 32],
        _our_listen_addr: SocketAddr,
        peer_storage: Arc<PeerStorage>,
    ) -> Self {
        Self {
            peers: DashMap::new(),
            addr_to_peer: DashMap::new(),
            ip_connections: DashMap::new(),
            last_connect_attempt: DashMap::new(),
            peer_storage,
            connected_count: AtomicUsize::new(0),
            outbound_count: AtomicUsize::new(0),
            connecting_count: AtomicUsize::new(0),
            router: Arc::new(std::sync::Mutex::new(P2pRouter::new())),
        }
    }

    pub fn can_accept(&self, addr: &SocketAddr) -> bool {
        if self.connected_count.load(Ordering::Relaxed) >= MAX_PEERS {
            return false;
        }

        self.ip_connections
            .get(&addr.ip())
            .map(|v| *v < MAX_PER_IP)
            .unwrap_or(true)
    }

    pub fn register_peer(
        &self,
        node_id: [u8; 32],
        addr: SocketAddr,
        tx: mpsc::Sender<Arc<Vec<u8>>>,
        is_outbound: bool,
        now_secs: u64,
    ) {
        let state = PeerState {
            tx,
            addr,
            peer_height: 0,
            msg_count: 0,
            last_reset: Instant::now(),
            connected_at: Instant::now(),
            is_outbound,
            state: ConnectionState::Connected,
        };

        if let Some(old) = self.peers.insert(node_id, state) {
            self.addr_to_peer.remove(&old.addr);
            self.decrement_ip(&old.addr.ip());

            if old.is_outbound {
                self.outbound_count.fetch_sub(1, Ordering::Relaxed);
            }
        } else {
            self.connected_count.fetch_add(1, Ordering::Relaxed);
        }

        self.addr_to_peer.insert(addr, node_id);

        *self.ip_connections.entry(addr.ip()).or_insert(0) += 1;

        if is_outbound {
            self.outbound_count.fetch_add(1, Ordering::Relaxed);
        }

        self.connecting_count
            .fetch_update(
                Ordering::AcqRel,
                Ordering::Relaxed,
                |v| Some(v.saturating_sub(1)),
            )
            .ok();

        let _ = self
            .peer_storage
            .save_peer_address_indexed(&addr, now_secs);
    }

    pub fn remove_peer(&self, node_id: &[u8; 32]) {
        if let Some((_, state)) = self.peers.remove(node_id) {
            self.addr_to_peer.remove(&state.addr);

            self.decrement_ip(&state.addr.ip());

            if state.is_outbound {
                self.outbound_count.fetch_sub(1, Ordering::Relaxed);
            }

            self.connected_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn decrement_ip(&self, ip: &IpAddr) {
        let remove = {
            if let Some(mut v) = self.ip_connections.get_mut(ip) {
                *v = v.saturating_sub(1);
                *v == 0
            } else {
                false
            }
        };

        if remove {
            self.ip_connections.remove(ip);
        }
    }

    pub fn get_node_id(&self, addr: &SocketAddr) -> Option<[u8; 32]> {
        self.addr_to_peer.get(addr).map(|v| *v)
    }

    pub fn get_addr_by_node_id(
        &self,
        node_id: &[u8; 32],
    ) -> Option<SocketAddr> {
        self.peers.get(node_id).map(|v| v.addr)
    }

    pub fn send_to(
        &self,
        node_id: &[u8; 32],
        msg: Vec<u8>,
    ) -> bool {
        let mut peer = match self.peers.get_mut(node_id) {
            Some(v) => v,
            None => return false,
        };

        let now = Instant::now();

        if now.duration_since(peer.last_reset) >= Duration::from_secs(1) {
            peer.msg_count = 0;
            peer.last_reset = now;
        }

        if peer.msg_count >= RATE_LIMIT_PER_SEC {
            return false;
        }

        peer.msg_count += 1;

        peer.tx.try_send(Arc::new(msg)).is_ok()
    }

    pub fn broadcast(&self, msg: Vec<u8>) {
        let shared = Arc::new(msg);

        let mut dead = Vec::new();

        for peer in self.peers.iter() {
            if peer.tx.is_closed() {
                dead.push(*peer.key());
                continue;
            }

            let _ = peer.tx.try_send(shared.clone());
        }

        for id in dead {
            self.remove_peer(&id);
        }
    }

    pub fn update_peer_height(
        &self,
        node_id: &[u8; 32],
        height: u64,
    ) {
        if let Some(mut peer) = self.peers.get_mut(node_id) {
            peer.peer_height = peer.peer_height.max(height);
        }
    }

    pub fn get_peer_height(
        &self,
        node_id: &[u8; 32],
    ) -> u64 {
        self.peers
            .get(node_id)
            .map(|v| v.peer_height)
            .unwrap_or(0)
    }

    pub fn mark_connected(
        &self,
        node_id: &[u8; 32],
        now_secs: u64,
    ) {
        let _ = self
            .peer_storage
            .update_reputation(node_id, 10, now_secs);
    }

    pub fn mark_connect_failed(
        &self,
        addr: SocketAddr,
        _now_secs: u64,
    ) {
        self.last_connect_attempt.insert(addr, Instant::now());

        self.connecting_count
            .fetch_update(
                Ordering::AcqRel,
                Ordering::Relaxed,
                |v| Some(v.saturating_sub(1)),
            )
            .ok();
    }

    pub fn try_reserve_outbound_slot(
        &self,
        addr: &SocketAddr,
    ) -> bool {
        if self.outbound_count.load(Ordering::Relaxed) >= MAX_OUTBOUND {
            return false;
        }

        if self.connecting_count.load(Ordering::Relaxed)
            >= MAX_CONNECTING
        {
            return false;
        }

        self.last_connect_attempt
            .retain(|_, t| t.elapsed() < ATTEMPT_TTL);

        match self.last_connect_attempt.entry(*addr) {
            DashEntry::Occupied(e) => {
                if e.get().elapsed() < CONNECT_RETRY {
                    return false;
                }
            }
            DashEntry::Vacant(_) => {}
        }

        self.last_connect_attempt
            .insert(*addr, Instant::now());

        self.connecting_count.fetch_add(1, Ordering::Relaxed);

        true
    }

    pub fn peer_count(&self) -> usize {
        self.connected_count.load(Ordering::Relaxed)
    }

    pub fn connected_count(&self) -> usize {
        self.connected_count.load(Ordering::Relaxed)
    }

    pub fn connected_addr_set(&self) -> HashSet<SocketAddr> {
        self.addr_to_peer.iter().map(|v| *v.key()).collect()
    }

    pub fn connected_peer_ids(&self) -> Vec<[u8; 32]> {
        self.peers.iter().map(|v| *v.key()).collect()
    }

    pub fn known_addresses_iter(&self) -> Vec<SocketAddr> {
        self.peer_storage
            .load_all_addresses()
            .unwrap_or_default()
            .into_iter()
            .map(|(addr, _)| addr)
            .collect()
    }

    pub fn known_addresses_with_ids(
        &self,
    ) -> Vec<(SocketAddr, [u8; 32])> {
        self.addr_to_peer
            .iter()
            .map(|v| (*v.key(), *v.value()))
            .collect()
    }

    pub fn add_known_address(
        &self,
        addr: SocketAddr,
        now_secs: u64,
    ) {
        let _ = self
            .peer_storage
            .save_peer_address_indexed(&addr, now_secs);
    }

    pub fn random_peers(
        &self,
        count: usize,
    ) -> Vec<[u8; 32]> {
        let mut ids: Vec<_> =
            self.peers.iter().map(|v| *v.key()).collect();

        ids.shuffle(&mut rand::thread_rng());

        ids.truncate(count.min(ids.len()));

        ids
    }

    pub fn get_connected_pubkeys(
        &self,
        now_secs: u64,
    ) -> Vec<([u8; 32], f64)> {
        let ids: Vec<[u8; 32]> =
            self.peers.iter().map(|v| *v.key()).collect();

        let reps: HashMap<[u8; 32], i32> = ids
            .iter()
            .map(|id| {
                (
                    *id,
                    self.peer_storage
                        .load_reputation(id, now_secs)
                        .unwrap_or(5000),
                )
            })
            .collect();

        ids.into_iter()
            .map(|id| {
                (
                    id,
                    reps.get(&id).copied().unwrap_or(5000) as f64,
                )
            })
            .collect()
    }
}
