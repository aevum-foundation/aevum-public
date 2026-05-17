use crate::p2p::noise::{NoiseHandshake, AtpCipher, peer_id_from_pubkey, HANDSHAKE_TIMEOUT, TofuStore};
use aevum::crypto::keys::PrivateKey;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream};
use tokio::sync::mpsc;

const MAX_PEERS: usize = 1000;
const MAX_IP_CONNECTIONS: usize = 4;
const RATE_LIMIT_PER_SEC: u64 = 100;
const BAN_DURATION_FIRST: Duration = Duration::from_secs(60);
const BAN_DURATION_SECOND: Duration = Duration::from_secs(300);
const BAN_DURATION_PERMANENT: Duration = Duration::from_secs(u64::MAX);

pub(crate) struct PeerState {
    tx: mpsc::Sender<Vec<u8>>,
    addr: SocketAddr,
    msg_count: u64,
    last_reset: Instant,
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
        Self {
            peers: DashMap::new(),
            ip_connections: DashMap::new(),
            ban_list: DashMap::new(),
            our_key,
            tofu: std::sync::Mutex::new(TofuStore::new()),
        }
    }

    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(entry) = self.ban_list.get(addr) {
            if Instant::now() < entry.0 { return true; }
        }
        false
    }

    pub fn ban_ip(&self, addr: SocketAddr) {
        let mut entry = self.ban_list.entry(addr).or_insert((Instant::now(), 0));
        entry.1 += 1;
        let duration = match entry.1 {
            1 => BAN_DURATION_FIRST, 2 => BAN_DURATION_SECOND, _ => BAN_DURATION_PERMANENT,
        };
        *entry = (Instant::now() + duration, entry.1);
    }

    pub fn can_accept(&self, addr: &SocketAddr) -> bool {
        if self.is_banned(addr) { return false; }
        if self.peers.len() >= MAX_PEERS { return false; }
        let count = self.ip_connections.get(addr).map(|e| *e).unwrap_or(0);
        count < MAX_IP_CONNECTIONS
    }

    pub fn register_peer(&self, peer_id: [u8; 20], addr: SocketAddr, tx: mpsc::Sender<Vec<u8>>) {
        self.peers.insert(peer_id, PeerState { tx, addr, msg_count: 0, last_reset: Instant::now() });
        *self.ip_connections.entry(addr).or_insert(0) += 1;
    }

    pub fn remove_peer(&self, peer_id: &[u8; 20]) {
        if let Some((_, state)) = self.peers.remove(peer_id) {
            if let Some(mut count) = self.ip_connections.get_mut(&state.addr) {
                *count = count.saturating_sub(1);
            }
        }
    }

    pub fn peer_count(&self) -> usize { self.peers.len() }

    pub fn send_to(&self, peer_id: &[u8; 20], msg: Vec<u8>) -> bool {
        if let Some(mut state) = self.peers.get_mut(peer_id) {
            let elapsed = state.last_reset.elapsed();
            if elapsed >= Duration::from_secs(1) { state.msg_count = 0; state.last_reset = Instant::now(); }
            if state.msg_count >= RATE_LIMIT_PER_SEC { return false; }
            state.msg_count += 1;
            state.tx.try_send(msg).is_ok()
        } else { false }
    }

    pub fn broadcast(&self, msg: Vec<u8>) {
        for entry in &self.peers { let _ = entry.value().tx.send(msg.clone()); }
    }
}

pub async fn accept_connection(
    stream: TcpStream, our_key: PrivateKey, tofu: &std::sync::Mutex<TofuStore>,
) -> Result<(AtpCipher, [u8; 20], SocketAddr, TcpStream), String> {
    let addr = stream.peer_addr().map_err(|e| format!("peer_addr: {}", e))?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut handshake = NoiseHandshake::new(our_key);
    let mut init_msg = [0u8; 64];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut init_msg))
        .await.map_err(|_| "Handshake timeout".to_string())?.map_err(|e| format!("Read error: {}", e))?;
    let init_pubkey: [u8; 32] = init_msg[..32].try_into().unwrap();
    let init_ephemeral: [u8; 32] = init_msg[32..64].try_into().unwrap();
    {
        let init_pk = aevum::crypto::keys::PublicKey::from_bytes(init_pubkey).map_err(|_| "Invalid pubkey")?;
        let mut tofu_store = tofu.lock().unwrap();
        if !tofu_store.check_or_store(&addr, &init_pk) { return Err("TOFU check failed".to_string()); }
    }
    let resp_ephemeral = handshake.responder_handshake(&init_pubkey, &init_ephemeral);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&resp_ephemeral[..32]))
        .await.map_err(|_| "Handshake timeout".to_string())?.map_err(|e| format!("Write error: {}", e))?;
    let shared_secret = *handshake.shared_secret().ok_or("Handshake incomplete")?;
    let cipher = AtpCipher::new(&shared_secret);
    let init_pk = aevum::crypto::keys::PublicKey::from_bytes(init_pubkey).unwrap();
    let peer_id = peer_id_from_pubkey(&init_pk);
    let stream = reader.unsplit(writer);
    Ok((cipher, peer_id, addr, stream))
}

pub async fn dial_peer(
    addr: SocketAddr, our_key: PrivateKey, tofu: &std::sync::Mutex<TofuStore>,
) -> Result<(AtpCipher, [u8; 20], TcpStream), String> {
    let stream = TcpStream::connect(addr).await.map_err(|e| format!("Connect: {}", e))?;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut handshake = NoiseHandshake::new(our_key);
    let placeholder_pk = aevum::crypto::keys::PublicKey::from_bytes([0u8; 32]).unwrap();
    let (init_msg, our_pubkey_bytes) = handshake.initiator_handshake(placeholder_pk);
    tokio::time::timeout(HANDSHAKE_TIMEOUT, writer.write_all(&init_msg[..64]))
        .await.map_err(|_| "Handshake timeout".to_string())?.map_err(|e| format!("Write: {}", e))?;
    let mut resp = [0u8; 32];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.read_exact(&mut resp))
        .await.map_err(|_| "Handshake timeout".to_string())?.map_err(|e| format!("Read: {}", e))?;
    let shared_secret = *handshake.shared_secret().ok_or("Handshake incomplete")?;
    let cipher = AtpCipher::new(&shared_secret);
    let our_pk = aevum::crypto::keys::PublicKey::from_bytes(our_pubkey_bytes[..32].try_into().unwrap()).unwrap();
    let peer_id = peer_id_from_pubkey(&our_pk);
    let stream = reader.unsplit(writer);
    Ok((cipher, peer_id, stream))
}
