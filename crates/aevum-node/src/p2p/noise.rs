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
    let mut id = [0u8; 20];
    id.copy_from_slice(&hash[..20]);
    id
}

pub struct NoiseHandshake {
    our_key: PrivateKey,
    our_pubkey: PublicKey,
    peer_pubkey: Option<PublicKey>,
    shared_secret: Option<[u8; 32]>,
}

impl NoiseHandshake {
    pub fn new(our_key: PrivateKey) -> Self {
        let our_pubkey = our_key.public_key();
        Self { our_key, our_pubkey, peer_pubkey: None, shared_secret: None }
    }
    pub fn our_pubkey(&self) -> &PublicKey { &self.our_pubkey }
    pub fn initiator_handshake(&mut self, peer_pubkey: PublicKey) -> (Vec<u8>, Vec<u8>) {
        self.peer_pubkey = Some(peer_pubkey.clone());
        let ephemeral = PrivateKey::generate();
        let ephemeral_pub = ephemeral.public_key();
        let dh1 = self.our_key.diffie_hellman(&peer_pubkey);
        let dh2 = ephemeral.diffie_hellman(&peer_pubkey);
        let mut secret = [0u8; 32];
        for i in 0..32 { secret[i] = dh1[i] ^ dh2[i]; }
        self.shared_secret = Some(secret);
        let mut message = Vec::new();
        message.extend_from_slice(&self.our_pubkey.to_bytes());
        message.extend_from_slice(&ephemeral_pub.to_bytes());
        (message, self.our_pubkey.to_bytes().to_vec())
    }
    pub fn responder_handshake(&mut self, initiator_pubkey_bytes: &[u8; 32], initiator_ephemeral_bytes: &[u8; 32]) -> Vec<u8> {
        let initiator_pubkey = PublicKey::from_bytes(*initiator_pubkey_bytes).expect("Invalid pubkey");
        let initiator_ephemeral = PublicKey::from_bytes(*initiator_ephemeral_bytes).expect("Invalid ephemeral");
        self.peer_pubkey = Some(initiator_pubkey.clone());
        let dh1 = self.our_key.diffie_hellman(&initiator_ephemeral);
        let dh2 = self.our_key.diffie_hellman(&initiator_pubkey);
        let mut secret = [0u8; 32];
        for i in 0..32 { secret[i] = dh1[i] ^ dh2[i]; }
        self.shared_secret = Some(secret);
        let our_ephemeral = PrivateKey::generate();
        our_ephemeral.public_key().to_bytes().to_vec()
    }
    pub fn shared_secret(&self) -> Option<&[u8; 32]> { self.shared_secret.as_ref() }
}

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
    let mut hasher = Sha256::new();
    hasher.update(secret);
    hasher.update(&index.to_le_bytes());
    hasher.update(direction);
    hasher.finalize().into()
}

fn compute_hmac(secret: &[u8; 32], index: u64, nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
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
        if let Some(stored) = self.keys.get(addr) {
            stored.to_bytes() == pk.to_bytes()
        } else {
            self.keys.insert(*addr, pk.clone());
            true
        }
    }
}
