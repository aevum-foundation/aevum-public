use crate::p2p::noise::{NoiseHandshake, AtpCipher, peer_id_from_pubkey, HANDSHAKE_TIMEOUT, TofuStore};
use aevum::crypto::keys::PrivateKey;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

const MAX_PEERS: usize = 1000;
const MAX_IP_CONNECTIONS: usize = 4;
const RATE_LIMIT_PER_SEC: u64 = 100;
const BAN_DURATION_FIRST: Duration = Duration::from_secs(60);
const BAN_DURATION_SECOND: Duration = Duration::from_secs(300);

pub(crate) struct PeerState {
    tx: mpsc::Sender<Vec<u8>>, addr: SocketAddr, msg_count: u64, last_reset: Instant,
}

pub struct PeersManager {
    pub peers: DashMap<[u8; 20], PeerState>,
    pub ip_connections: DashMap<SocketAddr, usize>,
    pub ban_list: DashMap<SocketAddr, (Instant, u32)>,
    pub our_key: PrivateKey,
    pub tofu: std::sync::Mutex<TofuStore>,
}

impl PeersManager {
    pub fn new(our_key: PrivateKey) -> Self {
        Self { peers: DashMap::new(), ip_connections: DashMap::new(), ban_list: DashMap::new(), our_key, tofu: std::sync::Mutex::new(TofuStore::new()) }
    }
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(e) = self.ban_list.get(addr) { if Instant::now() < e.0 { return true; } } false
    }
    pub fn ban_ip(&self, addr: SocketAddr) {
        let mut e = self.ban_list.entry(addr).or_insert((Instant::now(), 0));
        e.1 += 1; let d = match e.1 { 1 => BAN_DURATION_FIRST, 2 => BAN_DURATION_SECOND, _ => Duration::from_secs(u64::MAX) };
        *e = (Instant::now() + d, e.1);
    }
    pub fn can_accept(&self, addr: &SocketAddr) -> bool {
        if self.is_banned(addr) { return false; }
        if self.peers.len() >= MAX_PEERS { return false; }
        self.ip_connections.get(addr).map(|e| *e).unwrap_or(0) < MAX_IP_CONNECTIONS
    }
    pub fn register_peer(&self, peer_id: [u8; 20], addr: SocketAddr, tx: mpsc::Sender<Vec<u8>>) {
        self.peers.insert(peer_id, PeerState { tx, addr, msg_count: 0, last_reset: Instant::now() });
        *self.ip_connections.entry(addr).or_insert(0) += 1;
    }
    pub fn remove_peer(&self, peer_id: &[u8; 20]) {
        if let Some((_, s)) = self.peers.remove(peer_id) {
            if let Some(mut c) = self.ip_connections.get_mut(&s.addr) { *c = c.saturating_sub(1); }
        }
    }
    pub fn peer_count(&self) -> usize { self.peers.len() }
    pub fn random_peers(&self, count: usize) -> Vec<[u8; 20]> {
        use rand::seq::SliceRandom;
        let mut peers: Vec<[u8; 20]> = self.peers.iter().map(|e| *e.key()).collect();
        peers.shuffle(&mut rand::thread_rng());
        peers.truncate(count.min(peers.len()));
        peers
    }
    pub fn send_to(&self, peer_id: &[u8; 20], msg: Vec<u8>) -> bool {
        if let Some(mut s) = self.peers.get_mut(peer_id) {
            if s.last_reset.elapsed() >= Duration::from_secs(1) { s.msg_count = 0; s.last_reset = Instant::now(); }
            if s.msg_count >= RATE_LIMIT_PER_SEC { return false; }
            s.msg_count += 1; s.tx.try_send(msg).is_ok()
        } else { false }
    }
    pub fn broadcast(&self, msg: Vec<u8>) { for e in &self.peers { let _ = e.value().tx.send(msg.clone()); } }
}

/// Сервер: шаг 2 XX handshake
pub async fn accept_connection(
    stream: TcpStream, our_key: PrivateKey, tofu: &std::sync::Mutex<TofuStore>,
) -> Result<(AtpCipher, [u8; 20], SocketAddr, ReadHalf<TcpStream>, WriteHalf<TcpStream>), String> {
    let addr = stream.peer_addr().map_err(|e| format!("addr: {}", e))?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    
    let mut handshake = NoiseHandshake::new(our_key);
    
    // Читаем шаг 1 от клиента: [pubkey | ephemeral] = 64 байта
    let mut init_msg = [0u8; 64];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut init_msg))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("read: {}", e))?;
    
    // TOFU: проверяем/сохраняем pubkey
    {
        let mut pk_bytes = [0u8; 32]; pk_bytes.copy_from_slice(&init_msg[..32]);
        let pk = aevum::crypto::keys::PublicKey::from_bytes(pk_bytes).map_err(|_| "bad pk")?;
        if !tofu.lock().unwrap().check_or_store(&addr, &pk) { return Err("TOFU".into()); }
    }
    
    // Шаг 2: отправляем [server_pubkey | server_ephemeral]
    let resp = handshake.step2_responder(&init_msg);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&resp))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("write: {}", e))?;
    
    let secret = *handshake.shared_secret().ok_or("handshake")?;
    let cipher = AtpCipher::new(&secret);
    
    let mut pk_bytes = [0u8; 32]; pk_bytes.copy_from_slice(&init_msg[..32]);
    let pk = aevum::crypto::keys::PublicKey::from_bytes(pk_bytes).unwrap();
    let peer_id = peer_id_from_pubkey(&pk);
    
    Ok((cipher, peer_id, addr, reader, writer))
}

/// Клиент: шаг 1 + шаг 3 XX handshake
pub async fn dial_peer(
    addr: SocketAddr, our_key: PrivateKey, _tofu: &std::sync::Mutex<TofuStore>,
) -> Result<(AtpCipher, [u8; 20], ReadHalf<TcpStream>, WriteHalf<TcpStream>), String> {
    let stream = TcpStream::connect(addr).await.map_err(|e| format!("connect: {}", e))?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    
    let mut handshake = NoiseHandshake::new(our_key);
    
    // Шаг 1: отправляем [our_pubkey | ephemeral]
    let init_msg = handshake.step1_initiator();
    tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&init_msg))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("write: {}", e))?;
    
    // Шаг 3: читаем ответ [server_pubkey | server_ephemeral] = 64 байта
    let mut resp = [0u8; 64];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut resp))
        .await.map_err(|_| "timeout".to_string())?.map_err(|e| format!("read: {}", e))?;
    
    handshake.step3_initiator(&resp);
    
    let secret = *handshake.shared_secret().ok_or("handshake")?;
    let cipher = AtpCipher::new(&secret);
    
    let mut pk_bytes = [0u8; 32]; pk_bytes.copy_from_slice(&resp[..32]);
    let pk = aevum::crypto::keys::PublicKey::from_bytes(pk_bytes).unwrap();
    let peer_id = peer_id_from_pubkey(&pk);
    
    Ok((cipher, peer_id, reader, writer))
}
