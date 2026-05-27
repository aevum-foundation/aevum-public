use aevum::crypto::keys::{PublicKey, PrivateKey};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex as TokioMutex;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
const NONCE_SIZE: usize = 12;
const HMAC_SIZE: usize = 32;
const INDEX_SIZE: usize = 8;
const PACKET_OVERHEAD: usize = INDEX_SIZE + NONCE_SIZE + HMAC_SIZE;
const HANDSHAKE_MSG_SIZE: usize = 64;
const KEY_CONFIRMATION_TAG_SIZE: usize = 32;

type HmacSha256 = Hmac<Sha256>;

static HANDSHAKE_SUCCESS: AtomicU64 = AtomicU64::new(0);
static HANDSHAKE_FAILURE: AtomicU64 = AtomicU64::new(0);

pub fn handshake_metrics() -> (u64, u64) {
    (HANDSHAKE_SUCCESS.load(Ordering::Relaxed), HANDSHAKE_FAILURE.load(Ordering::Relaxed))
}

pub fn peer_id_from_pubkey(pk: &PublicKey) -> [u8; 20] {
    let hash = blake3::hash(&pk.to_bytes());
    let mut id = [0u8; 20];
    id.copy_from_slice(&hash.as_bytes()[..20]);
    id
}

#[derive(Debug)]
pub enum HandshakeError {
    InvalidPubkey,
    KeyConfirmationFailed,
    CryptoError(String),
    Timeout,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            HandshakeError::InvalidPubkey => write!(f, "Invalid public key"),
            HandshakeError::KeyConfirmationFailed => write!(f, "Key confirmation failed"),
            HandshakeError::CryptoError(s) => write!(f, "Crypto error: {}", s),
            HandshakeError::Timeout => write!(f, "Handshake timeout"),
        }
    }
}

pub struct NoiseHandshake {
    our_key: PrivateKey,
    our_pubkey: PublicKey,
    peer_pubkey: Option<PublicKey>,
    shared_secret: Option<[u8; 32]>,
    saved_ephemeral: Option<[u8; 32]>,
}

impl NoiseHandshake {
    pub fn new(our_key: PrivateKey) -> Self {
        let our_pubkey = our_key.public_key();
        Self { our_key, our_pubkey, peer_pubkey: None, shared_secret: None, saved_ephemeral: None }
    }

    pub fn our_pubkey(&self) -> &PublicKey { &self.our_pubkey }
    pub fn shared_secret(&self) -> Option<&[u8; 32]> { self.shared_secret.as_ref() }
    pub fn peer_pubkey(&self) -> Option<&PublicKey> { self.peer_pubkey.as_ref() }

    fn validate_pubkey(pk: &PublicKey) -> Result<(), HandshakeError> {
        let bytes = pk.to_bytes();
        if bytes.iter().all(|&b| b == 0) { Err(HandshakeError::InvalidPubkey) } else { Ok(()) }
    }

    fn compute_key_confirmation(secret: &[u8; 32], msg: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
        mac.update(msg);
        mac.finalize().into_bytes().into()
    }

    fn verify_key_confirmation(secret: &[u8; 32], msg: &[u8], tag: &[u8; 32]) -> bool {
        Self::compute_key_confirmation(secret, msg) == *tag
    }

    pub fn step1_initiator(&mut self) -> Vec<u8> {
        let ephemeral = PrivateKey::generate();
        let ephemeral_pub = ephemeral.public_key();
        self.saved_ephemeral = Some(ephemeral.to_bytes());
        let mut msg = Vec::with_capacity(HANDSHAKE_MSG_SIZE);
        msg.extend_from_slice(&self.our_pubkey.to_bytes());
        msg.extend_from_slice(&ephemeral_pub.to_bytes());
        msg
    }

    pub fn step2_responder(&mut self, initiator_msg: &[u8; 64]) -> Result<Vec<u8>, HandshakeError> {
        let init_pubkey = PublicKey::from_bytes(initiator_msg[..32].try_into().unwrap())
            .map_err(|_| HandshakeError::InvalidPubkey)?;
        Self::validate_pubkey(&init_pubkey)?;
        let init_ephemeral = PublicKey::from_bytes(initiator_msg[32..].try_into().unwrap())
            .map_err(|_| HandshakeError::InvalidPubkey)?;
        Self::validate_pubkey(&init_ephemeral)?;
        self.peer_pubkey = Some(init_pubkey.clone());

        let our_ephemeral = PrivateKey::generate();
        let our_ephemeral_pub = our_ephemeral.public_key();

        let dh1 = our_ephemeral.diffie_hellman(&init_ephemeral);
        let dh2 = self.our_key.diffie_hellman(&init_ephemeral);
        let dh3 = our_ephemeral.diffie_hellman(&init_pubkey);
        let mut secret = [0u8; 32];
        for i in 0..32 { secret[i] = dh1[i] ^ dh2[i] ^ dh3[i]; }
        self.shared_secret = Some(secret);

        let mut msg = Vec::with_capacity(HANDSHAKE_MSG_SIZE + KEY_CONFIRMATION_TAG_SIZE);
        msg.extend_from_slice(&self.our_pubkey.to_bytes());
        msg.extend_from_slice(&our_ephemeral_pub.to_bytes());
        let tag = Self::compute_key_confirmation(&self.shared_secret.unwrap(), &msg);
        msg.extend_from_slice(&tag);

        HANDSHAKE_SUCCESS.fetch_add(1, Ordering::Relaxed);
        Ok(msg)
    }

    pub fn step3_initiator(&mut self, server_msg: &[u8]) -> Result<(), HandshakeError> {
        if server_msg.len() < HANDSHAKE_MSG_SIZE + KEY_CONFIRMATION_TAG_SIZE {
            HANDSHAKE_FAILURE.fetch_add(1, Ordering::Relaxed);
            return Err(HandshakeError::InvalidPubkey);
        }

        let server_pubkey = PublicKey::from_bytes(server_msg[..32].try_into().unwrap())
            .map_err(|_| HandshakeError::InvalidPubkey)?;
        Self::validate_pubkey(&server_pubkey)?;
        let server_ephemeral = PublicKey::from_bytes(server_msg[32..64].try_into().unwrap())
            .map_err(|_| HandshakeError::InvalidPubkey)?;
        Self::validate_pubkey(&server_ephemeral)?;
        self.peer_pubkey = Some(server_pubkey.clone());

        let ephemeral_bytes = self.saved_ephemeral.take()
            .ok_or(HandshakeError::CryptoError("No ephemeral saved".into()))?;
        let our_ephemeral = PrivateKey::from_bytes(ephemeral_bytes)
            .map_err(|_| HandshakeError::CryptoError("Invalid ephemeral".into()))?;

        let dh1 = our_ephemeral.diffie_hellman(&server_ephemeral);
        let dh2 = our_ephemeral.diffie_hellman(&server_pubkey);
        let dh3 = self.our_key.diffie_hellman(&server_ephemeral);

        let mut secret = [0u8; 32];
        for i in 0..32 { secret[i] = dh1[i] ^ dh2[i] ^ dh3[i]; }
        self.shared_secret = Some(secret);

        let handshake_msg = &server_msg[..64];
        let received_tag: &[u8; 32] = server_msg[64..96].try_into().unwrap();
        if !Self::verify_key_confirmation(&self.shared_secret.unwrap(), handshake_msg, received_tag) {
            HANDSHAKE_FAILURE.fetch_add(1, Ordering::Relaxed);
            return Err(HandshakeError::KeyConfirmationFailed);
        }

        HANDSHAKE_SUCCESS.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Clone)]
pub struct AtpCipher {
    encrypt_key: [u8; 32],
    hmac_key: [u8; 32],
    send_index: u64,
    recv_index: u64,
    peer_pubkey: Option<PublicKey>,
}

impl AtpCipher {
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let hmac_key = derive_hmac_key(shared_secret, b"hmac");
        Self {
            encrypt_key: *shared_secret,
            hmac_key,
            send_index: 0, recv_index: 0,
            peer_pubkey: None,
        }
    }

    pub fn with_peer_pubkey(shared_secret: &[u8; 32], peer_pubkey: PublicKey) -> Self {
        let mut s = Self::new(shared_secret);
        s.peer_pubkey = Some(peer_pubkey);
        s
    }

    pub fn shared_secret_bytes(&self) -> [u8; 32] { self.encrypt_key }
    pub fn set_peer_pubkey(&mut self, pk: PublicKey) { self.peer_pubkey = Some(pk); }

    pub fn remote_static(&self) -> [u8; 32] {
        self.peer_pubkey.as_ref().map(|p| p.to_bytes()).unwrap_or([0u8; 32])
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.send_index += 1;
        let nonce: [u8; 12] = (self.send_index as u128).to_le_bytes()[..12].try_into().unwrap();
        let mut cipher = ChaCha20::new(&self.encrypt_key.into(), &nonce.into());
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);
        let hmac = compute_hmac(&self.hmac_key, self.send_index, &nonce, &ciphertext);
        let mut packet = Vec::with_capacity(PACKET_OVERHEAD + ciphertext.len());
        packet.extend_from_slice(&self.send_index.to_le_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&hmac);
        packet
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < PACKET_OVERHEAD { return None; }
        let index = u64::from_le_bytes(data[..8].try_into().unwrap());
        let nonce: &[u8; 12] = data[8..20].try_into().unwrap();
        let ciphertext = &data[20..data.len() - 32];
        let hmac_received: &[u8; 32] = data[data.len() - 32..].try_into().unwrap();
        if index <= self.recv_index { return None; }
        let hmac_expected = compute_hmac(&self.hmac_key, index, nonce, ciphertext);
        if hmac_received != &hmac_expected { return None; }
        self.recv_index = index;
        let mut cipher = ChaCha20::new(&self.encrypt_key.into(), nonce.into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);
        Some(plaintext)
    }
}

fn derive_hmac_key(secret: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aevum-v1");
    hasher.update(secret);
    hasher.update(info);
    hasher.finalize().into()
}

fn compute_hmac(key: &[u8; 32], index: u64, nonce: &[u8; 12], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(&index.to_le_bytes());
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

#[derive(Clone)]
pub struct TofuStore {
    pub keys: std::collections::HashMap<std::net::SocketAddr, PublicKey>,
}

impl TofuStore {
    pub fn new() -> Self { Self { keys: std::collections::HashMap::new() } }

    pub fn check_or_store(&mut self, addr: &std::net::SocketAddr, pk: &PublicKey) -> bool {
        if let Some(stored) = self.keys.get(addr) { stored.to_bytes() == pk.to_bytes() }
        else { self.keys.insert(*addr, pk.clone()); true }
    }

    pub fn save_to_storage(&self, st: &mut crate::storage::Storage) -> Result<(), String> {
        let data = bincode::serialize(&self.keys).map_err(|e| format!("ser: {}", e))?;
        st.save_metadata("tofu_store", &data).map_err(|e| format!("save: {}", e))
    }

    pub fn load_from_storage(st: &crate::storage::Storage) -> Self {
        let keys = st.load_metadata("tofu_store").ok().flatten()
            .and_then(|d| bincode::deserialize(&d).ok()).unwrap_or_default();
        Self { keys }
    }
}

pub type SharedTofuStore = Arc<TokioMutex<TofuStore>>;

pub fn new_shared_tofu() -> SharedTofuStore {
    Arc::new(TokioMutex::new(TofuStore::new()))
}
