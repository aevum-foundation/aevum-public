use aevum::crypto::keys::{PublicKey, PrivateKey};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use std::time::Duration;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

type HmacSha256 = Hmac<Sha256>;

pub fn peer_id_from_pubkey(pk: &PublicKey) -> [u8; 20] {
    let hash = Sha256::digest(pk.to_bytes());
    let mut id = [0u8; 20]; id.copy_from_slice(&hash[..20]); id
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

    /// Шаг 1 (клиент): отправить [our_pubkey, ephemeral_pubkey]
    pub fn step1_initiator(&mut self) -> Vec<u8> {
        let ephemeral = PrivateKey::generate();
        let ephemeral_pub = ephemeral.public_key();
        self.saved_ephemeral = Some(ephemeral.to_bytes());
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.our_pubkey.to_bytes());
        msg.extend_from_slice(&ephemeral_pub.to_bytes());
        msg
    }

    /// Шаг 2 (сервер): прочитать [initiator_pubkey, initiator_ephemeral], отправить [server_pubkey, server_ephemeral]
    pub fn step2_responder(&mut self, initiator_msg: &[u8; 64]) -> Vec<u8> {
        let init_pubkey_bytes: [u8; 32] = initiator_msg[..32].try_into().unwrap();
        let init_ephemeral_bytes: [u8; 32] = initiator_msg[32..].try_into().unwrap();
        let init_pubkey = PublicKey::from_bytes(init_pubkey_bytes).unwrap();
        let init_ephemeral = PublicKey::from_bytes(init_ephemeral_bytes).unwrap();
        self.peer_pubkey = Some(init_pubkey.clone());
        
        let our_ephemeral = PrivateKey::generate();
        let our_ephemeral_pub = our_ephemeral.public_key();
        
        let dh1 = our_ephemeral.diffie_hellman(&init_ephemeral);
        let dh2 = self.our_key.diffie_hellman(&init_ephemeral);
        let dh3 = our_ephemeral.diffie_hellman(&init_pubkey);
        
        let mut secret = [0u8; 32];
        for i in 0..32 { secret[i] = dh1[i] ^ dh2[i] ^ dh3[i]; }
        self.shared_secret = Some(secret);
        
        let mut msg = Vec::new();
        msg.extend_from_slice(&self.our_pubkey.to_bytes());
        msg.extend_from_slice(&our_ephemeral_pub.to_bytes());
        msg
    }

    /// Шаг 3 (клиент): прочитать [server_pubkey, server_ephemeral], вычислить shared_secret
    pub fn step3_initiator(&mut self, server_msg: &[u8; 64]) {
        let server_pubkey_bytes: [u8; 32] = server_msg[..32].try_into().unwrap();
        let server_ephemeral_bytes: [u8; 32] = server_msg[32..].try_into().unwrap();
        let server_pubkey = PublicKey::from_bytes(server_pubkey_bytes).unwrap();
        let server_ephemeral = PublicKey::from_bytes(server_ephemeral_bytes).unwrap();
        self.peer_pubkey = Some(server_pubkey.clone());
        
        let ephemeral_bytes = self.saved_ephemeral.take().unwrap();
        let our_ephemeral = PrivateKey::from_bytes(ephemeral_bytes).unwrap();
        
        let dh1 = our_ephemeral.diffie_hellman(&server_ephemeral);
        let dh2 = our_ephemeral.diffie_hellman(&server_pubkey);
        let dh3 = self.our_key.diffie_hellman(&server_ephemeral);
        
        let mut secret = [0u8; 32];
        for i in 0..32 { secret[i] = dh1[i] ^ dh2[i] ^ dh3[i]; }
        self.shared_secret = Some(secret);
    }
}

/// AtpCipher — автономное шифрование
pub struct AtpCipher {
    shared_secret: [u8; 32],
    send_index: u64,
    recv_index: u64,
}

impl AtpCipher {
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        Self { shared_secret: *shared_secret, send_index: 0, recv_index: 0 }
    }
    pub fn shared_secret_bytes(&self) -> [u8; 32] { self.shared_secret }
    
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.send_index += 1;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let key = derive_key(&self.shared_secret, self.send_index, b"encrypt");
        let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);
        let hmac = compute_hmac(&self.shared_secret, self.send_index, &nonce, &ciphertext);
        let mut packet = Vec::with_capacity(8 + 12 + ciphertext.len() + 32);
        packet.extend_from_slice(&self.send_index.to_le_bytes());
        packet.extend_from_slice(&nonce);
        packet.extend_from_slice(&ciphertext);
        packet.extend_from_slice(&hmac);
        packet
    }
    
    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 64 { return None; }
        let index = u64::from_le_bytes(data[..8].try_into().unwrap());
        let nonce = &data[8..20];
        let hmac_received = &data[data.len() - 32..];
        let ciphertext = &data[20..data.len() - 32];
        if index <= self.recv_index { return None; }
        let hmac_expected = compute_hmac(&self.shared_secret, index, nonce, ciphertext);
        if hmac_received != hmac_expected { return None; }
        self.recv_index = index;
        let key = derive_key(&self.shared_secret, index, b"encrypt");
        let mut cipher = ChaCha20::new(&key.into(), nonce.into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);
        Some(plaintext)
    }
}

fn derive_key(secret: &[u8; 32], index: u64, direction: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new(); hasher.update(secret); hasher.update(&index.to_le_bytes()); hasher.update(direction);
    hasher.finalize().into()
}

fn compute_hmac(secret: &[u8; 32], index: u64, nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
    mac.update(&index.to_le_bytes()); mac.update(nonce); mac.update(ciphertext);
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
}
