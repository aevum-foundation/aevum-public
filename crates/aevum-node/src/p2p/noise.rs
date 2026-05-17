use aevum::crypto::keys::{PublicKey, PrivateKey};
use sha2::{Sha256, Digest};
use chacha20poly1305::{KeyInit, 
    ChaCha20Poly1305, Key, Nonce,
    aead::Aead,
};
use std::time::Duration;
use rand::Rng;

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

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
    pub fn peer_pubkey(&self) -> Option<&PublicKey> { self.peer_pubkey.as_ref() }

    pub fn initiator_handshake(&mut self, peer_pubkey: PublicKey) -> (Vec<u8>, Vec<u8>) {
        self.peer_pubkey = Some(peer_pubkey.clone());
        let ephemeral = PrivateKey::generate();
        let ephemeral_pub = ephemeral.public_key();
        let dh1 = self.our_key.diffie_hellman(&peer_pubkey);
        let dh2 = ephemeral.diffie_hellman(&peer_pubkey);
        let mut secret = [0u8; 32];
        for i in 0..32 { secret[i] = dh1[i] ^ dh2[i]; }
        self.shared_secret = Some(secret);
        let mut message = Vec::with_capacity(64);
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

/// Шифрование с явным nonce в сообщении — никакой рассинхронизации
#[derive(Clone)]
pub struct NoiseCipher {
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
}

impl NoiseCipher {
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let send_key = Sha256::digest(shared_secret);
        let recv_key = send_key;
        Self {
            send_cipher: ChaCha20Poly1305::new(Key::from_slice(&send_key)),
            recv_cipher: ChaCha20Poly1305::new(Key::from_slice(&recv_key)),
        }
    }

    /// Шифрует с новым случайным nonce, возвращает [nonce | ciphertext]
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self.send_cipher.encrypt(nonce, plaintext).unwrap_or_default();
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        result
    }

    /// Расшифровывает сообщение формата [nonce | ciphertext]
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 { return None; }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.recv_cipher.decrypt(nonce, ciphertext).ok()
    }
}

use std::net::SocketAddr;

pub struct TofuStore {
    pub keys: std::collections::HashMap<SocketAddr, PublicKey>,
}

impl TofuStore {
    pub fn new() -> Self { Self { keys: std::collections::HashMap::new() } }
    pub fn check_or_store(&mut self, addr: &SocketAddr, pk: &PublicKey) -> bool {
        if let Some(stored) = self.keys.get(addr) {
            stored.to_bytes() == pk.to_bytes()
        } else {
            self.keys.insert(*addr, pk.clone());
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0xAAu8; 32];
        let send_cipher = NoiseCipher::new(&key);
        let recv_cipher = NoiseCipher::new(&key);
        let msg = b"Hello, Aevum Protocol!";
        let encrypted = send_cipher.encrypt(msg);
        let decrypted = recv_cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, msg);
    }
}
