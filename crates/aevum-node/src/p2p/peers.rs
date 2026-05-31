use crate::http_server::SharedMetrics;
use crate::p2p::noise::{NoiseHandshake, AtpCipher, peer_id_from_pubkey, HANDSHAKE_TIMEOUT, TofuStore};
use crate::p2p::peer_db::PeerDb;
use crate::storage::Storage;
use aevum::crypto::keys::PrivateKey;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const MAX_PEERS: usize = 1000;
const MAX_OUTBOUND: usize = 8;
const MAX_SIMULTANEOUS_CONNECTS: usize = 3;
const MIN_RECONNECT_INTERVAL: Duration = Duration::from_secs(30);
const MAX_IP_CONNECTIONS: usize = 4;
const RATE_LIMIT_PER_SEC: u64 = 100;
const BAN_DURATION_FIRST: Duration = Duration::from_secs(60);
const BAN_DURATION_SECOND: Duration = Duration::from_secs(300);
const BAN_CLEANUP_INTERVAL: Duration = Duration::from_secs(600);

pub(crate) struct PeerState {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub addr: SocketAddr,
    pub msg_count: u64,
    pub last_reset: Instant,
    pub peer_height: u64,
    pub is_outbound: bool,
}

pub struct PeersManager {
    pub peers: DashMap<[u8; 20], PeerState>,
    pub peer_ips: DashMap<[u8; 20], SocketAddr>,
    pub peer_db: PeerDb,
    pub ip_connections: DashMap<SocketAddr, usize>,
    pub ban_list: DashMap<SocketAddr, (Instant, u32)>,
    pub our_key: PrivateKey,
    pub tofu: tokio::sync::Mutex<TofuStore>,
    pub outbound_count: std::sync::atomic::AtomicUsize,
    pub last_connect_attempt: DashMap<SocketAddr, Instant>,
    pub connecting_count: std::sync::atomic::AtomicUsize,
    pub metrics: SharedMetrics,
    pub last_ban_cleanup: std::sync::Mutex<Instant>,
}

impl PeersManager {
    pub fn new(our_key: PrivateKey, metrics: SharedMetrics, storage: Arc<StdMutex<Storage>>) -> Self {
        let peer_db = PeerDb::load(storage);
        Self {
            peers: DashMap::new(), peer_ips: DashMap::new(),
            peer_db, ip_connections: DashMap::new(),
            ban_list: DashMap::new(), our_key,
            tofu: tokio::sync::Mutex::new(TofuStore::new()),
            outbound_count: std::sync::atomic::AtomicUsize::new(0),
            last_connect_attempt: DashMap::new(),
            connecting_count: std::sync::atomic::AtomicUsize::new(0),
            metrics,
            last_ban_cleanup: std::sync::Mutex::new(Instant::now()),
        }
    }

    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(e) = self.ban_list.get(addr) { if Instant::now() < e.0 { return true; } } false
    }

    pub fn ban_ip(&self, addr: SocketAddr) {
        let mut e = self.ban_list.entry(addr).or_insert((Instant::now(), 0));
        e.1 += 1; let d = match e.1 { 1 => BAN_DURATION_FIRST, 2 => BAN_DURATION_SECOND, _ => Duration::from_secs(u64::MAX) };
        *e = (Instant::now() + d, e.1);
    }

    pub fn cleanup_bans(&self) {
        let mut last = self.last_ban_cleanup.lock().unwrap();
        if last.elapsed() < BAN_CLEANUP_INTERVAL { return; }
        let now = Instant::now();
        self.ban_list.retain(|_, (expire, _)| now < *expire);
        *last = now;
    }

    pub fn can_accept(&self, addr: &SocketAddr) -> bool {
        if self.is_banned(addr) { return false; }
        if self.peers.len() >= MAX_PEERS { return false; }
        self.ip_connections.get(addr).map(|e| *e).unwrap_or(0) < MAX_IP_CONNECTIONS
    }

    pub fn can_connect_to(&self, addr: &SocketAddr) -> bool {
        if self.peer_ips.iter().any(|e| *e.value() == *addr) { return false; }
        if self.outbound_count.load(Ordering::Relaxed) >= MAX_OUTBOUND { return false; }
        if self.connecting_count.load(Ordering::Relaxed) >= MAX_SIMULTANEOUS_CONNECTS { return false; }
        if let Some(last) = self.last_connect_attempt.get(addr) {
            if last.elapsed() < MIN_RECONNECT_INTERVAL { return false; }
        }
        if self.is_banned(addr) { return false; }
        true
    }

    pub fn mark_connecting(&self, addr: SocketAddr) {
        self.connecting_count.fetch_add(1, Ordering::Relaxed);
        self.last_connect_attempt.insert(addr, Instant::now());
    }

    pub fn mark_connected(&self, _addr: SocketAddr) {
        self.connecting_count.fetch_sub(1, Ordering::Relaxed);
        self.outbound_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn register_peer(&self, peer_id: [u8; 20], addr: SocketAddr, tx: mpsc::Sender<Vec<u8>>, is_outbound: bool) {
        tracing::info!("[PEERS] register_peer: {} ({}) outbound={}", hex::encode(&peer_id), addr, is_outbound);
        self.peers.insert(peer_id, PeerState { tx, addr, msg_count: 0, last_reset: Instant::now(), peer_height: 0, is_outbound });
        self.peer_ips.insert(peer_id, addr);
        *self.ip_connections.entry(addr).or_insert(0) += 1;
        self.metrics.peers.store(self.peers.len(), Ordering::Relaxed);
        // Критичный адрес — сохраняем немедленно
        self.peer_db.add_and_flush(addr);
        tracing::info!("[PEERS] total peers after register: {}", self.peers.len());
    }

    pub fn remove_peer(&self, peer_id: &[u8; 20]) {
        tracing::info!("[PEERS] remove_peer: {}", hex::encode(peer_id));
        if let Some((_, s)) = self.peers.remove(peer_id) {
            if let Some(mut c) = self.ip_connections.get_mut(&s.addr) { *c = c.saturating_sub(1); }
            if s.is_outbound { self.outbound_count.fetch_sub(1, Ordering::Relaxed); }
        }
        self.peer_ips.remove(peer_id);
        self.metrics.peers.store(self.peers.len(), Ordering::Relaxed);
        tracing::info!("[PEERS] total peers after remove: {}", self.peers.len());
    }

    pub fn peer_count(&self) -> usize { self.peers.len() }

    pub fn random_peers(&self, count: usize) -> Vec<[u8; 20]> {
        use rand::seq::SliceRandom;
        let mut peers: Vec<[u8; 20]> = self.peers.iter().map(|e| *e.key()).collect();
        peers.shuffle(&mut rand::thread_rng());
        peers.truncate(count.min(peers.len()));
        peers
    }

    /// Добавить адрес в PeerDb (память + периодический flush)
    pub fn add_known_address(&self, addr: SocketAddr) {
        self.peer_db.add(addr);
    }

    /// Сохранить PeerDb на диск
    pub fn flush_known_addresses(&self) {
        self.peer_db.flush_if_needed();
    }

    /// Получить все известные адреса
    pub fn known_addresses_iter(&self) -> Vec<SocketAddr> {
        self.peer_db.get_all()
    }

    /// Построить HashSet подключенных адресов
    pub fn connected_addr_set(&self) -> std::collections::HashSet<SocketAddr> {
        self.peer_ips.iter().map(|e| *e.value()).collect()
    }

    pub fn send_to(&self, peer_id: &[u8; 20], msg: Vec<u8>) -> bool {
        match self.peers.get_mut(peer_id) {
            Some(mut s) => {
                if s.last_reset.elapsed() >= Duration::from_secs(1) { s.msg_count = 0; s.last_reset = Instant::now(); }
                if s.msg_count >= RATE_LIMIT_PER_SEC { return false; }
                s.msg_count += 1;
                s.tx.try_send(msg).is_ok()
            }
            None => false,
        }
    }

    pub fn broadcast(&self, msg: Vec<u8>) {
        let count = self.peers.len();
        if count == 0 { return; }
        let shared = Arc::new(msg);
        for e in &self.peers { let _ = e.value().tx.try_send(shared.as_ref().clone()); }
    }

    pub fn update_peer_height(&self, peer_id: &[u8; 20], height: u64) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            if height > peer.peer_height { peer.peer_height = height; }
        }
    }

    pub fn get_peer_height(&self, peer_id: &[u8; 20]) -> u64 {
        self.peers.get(peer_id).map(|p| p.peer_height).unwrap_or(0)
    }
}

pub async fn accept_connection(
    stream: TcpStream, our_key: PrivateKey, tofu: &tokio::sync::Mutex<TofuStore>,
) -> Result<(AtpCipher, [u8; 20], SocketAddr, ReadHalf<TcpStream>, WriteHalf<TcpStream>), String> {
    let addr = stream.peer_addr().map_err(|e| format!("addr: {}", e))?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut handshake = NoiseHandshake::new(our_key);
    let mut init_msg = [0u8; 64];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut init_msg))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("read: {}", e))?;
    let mut pk_bytes = [0u8; 32]; pk_bytes.copy_from_slice(&init_msg[..32]);
    let pk = aevum::crypto::keys::PublicKey::from_bytes(pk_bytes).map_err(|_| "bad pk")?;
    if !tofu.lock().await.check_or_store(&addr, &pk) { return Err("TOFU".into()); }
    let resp = handshake.step2_responder(&init_msg).map_err(|e| format!("handshake: {}", e))?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&resp))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("write: {}", e))?;
    let secret = *handshake.shared_secret().ok_or("handshake")?;
    let cipher = AtpCipher::with_peer_pubkey(&secret, pk.clone());
    let peer_id = peer_id_from_pubkey(&pk);
    Ok((cipher, peer_id, addr, reader, writer))
}

pub async fn dial_peer(
    addr: SocketAddr, our_key: PrivateKey, tofu: &tokio::sync::Mutex<TofuStore>,
) -> Result<(AtpCipher, [u8; 20], ReadHalf<TcpStream>, WriteHalf<TcpStream>), String> {
    let stream = TcpStream::connect(addr).await.map_err(|e| format!("connect: {}", e))?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut handshake = NoiseHandshake::new(our_key);
    let init_msg = handshake.step1_initiator();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&init_msg))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("write: {}", e))?;
    let mut resp = [0u8; 96];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut resp))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("read: {}", e))?;
    handshake.step3_initiator(&resp).map_err(|e| format!("handshake: {}", e))?;
    let secret = *handshake.shared_secret().ok_or("handshake")?;
    let pk = handshake.peer_pubkey().ok_or("no peer pubkey")?.clone();
    if !tofu.lock().await.check_or_store(&addr, &pk) { return Err("TOFU".into()); }
    let cipher = AtpCipher::with_peer_pubkey(&secret, pk.clone());
    let peer_id = peer_id_from_pubkey(&pk);
    Ok((cipher, peer_id, reader, writer))
}
