use aevum::crypto::keys::{PublicKey, PrivateKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub owner: [u8; 32],
    pub blob_hash: [u8; 32],
    pub encrypted_data: Vec<u8>,
    pub nonce: [u8; 12],
    pub version: u16,
    pub created_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BlobType {
    UtxoSnapshot,
    TransactionHistory,
    BalanceProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptedBlob {
    pub blob_type: BlobType,
    pub owner: [u8; 32],
    pub data: Vec<u8>,
    pub height: u64,
    pub signature: Vec<u8>,
}

pub struct EncryptedReplication {
    pub store: HashMap<[u8; 32], Vec<EncryptedBlob>>,
    pub local_key: Option<PrivateKey>,
    max_blobs: usize,
}

impl EncryptedReplication {
    pub fn new(local_key: Option<PrivateKey>, max_blobs: usize) -> Self {
        EncryptedReplication { store: HashMap::new(), local_key, max_blobs }
    }

    /// Зашифровать и сохранить блоб с подписью владельца
    pub fn store_blob(
        &mut self, owner: &PublicKey, blob_type: BlobType,
        data: Vec<u8>, height: u64, owner_private: &PrivateKey,
    ) -> Result<[u8; 32], String> {
        // Подписываем данные приватным ключом владельца
        let sig_msg = [&data[..], &height.to_le_bytes()].concat();
        let signature = owner_private.sign(&sig_msg);

        let decrypted = DecryptedBlob {
            blob_type, owner: owner.to_bytes(), data, height, signature: signature.to_vec(),
        };

        let plaintext = bincode::serialize(&decrypted).map_err(|e| format!("Serialize: {}", e))?;
        let shared_secret = owner_private.diffie_hellman(owner);
        let mut cipher = crate::p2p::noise::AtpCipher::new(&shared_secret);
        let encrypted = cipher.encrypt(&plaintext);

        let blob = EncryptedBlob {
            owner: owner.to_bytes(),
            blob_hash: blake3::hash(&encrypted).into(),
            encrypted_data: encrypted,
            nonce: [0u8; 12], version: 1, created_height: height,
        };

        let hash = blob.blob_hash;
        let entry = self.store.entry(owner.to_bytes()).or_default();
        if entry.len() >= self.max_blobs { entry.remove(0); }
        entry.push(blob);
        tracing::info!("Stored signed blob for {}", hex::encode(&owner.to_bytes()[..8]));
        Ok(hash)
    }

    pub fn query_blobs(&self, owner: &[u8; 32]) -> Vec<&EncryptedBlob> {
        self.store.get(owner).map(|v| v.iter().collect()).unwrap_or_default()
    }

    pub fn query_blobs_by_hash(&self, hashes: &[[u8; 32]]) -> Vec<EncryptedBlob> {
        self.store.values().flatten().filter(|b| hashes.contains(&b.blob_hash)).cloned().collect()
    }

    pub fn store_received(&mut self, blob: EncryptedBlob) {
        let entry = self.store.entry(blob.owner).or_default();
        if !entry.iter().any(|b| b.blob_hash == blob.blob_hash) {
            if entry.len() >= self.max_blobs { entry.remove(0); }
            entry.push(blob);
        }
    }

    /// Расшифровать свои блобы и проверить подпись
    pub fn decrypt_my_blobs(&self) -> Result<Vec<DecryptedBlob>, String> {
        let local_key = self.local_key.as_ref().ok_or("No local key")?;
        let my_pubkey = local_key.public_key().to_bytes();
        let my_pubkey_obj = local_key.public_key();
        let blobs = self.query_blobs(&my_pubkey);
        let mut decrypted = Vec::new();

        for blob in blobs {
            let shared_secret = local_key.diffie_hellman(
                &PublicKey::from_bytes(blob.owner).map_err(|_| "Invalid pubkey")?
            );
            let mut cipher = crate::p2p::noise::AtpCipher::new(&shared_secret);
            if let Some(plaintext) = cipher.decrypt(&blob.encrypted_data) {
                if let Ok(dec) = bincode::deserialize::<DecryptedBlob>(&plaintext) {
                    // Проверяем подпись владельца
                    let sig_msg = [&dec.data[..], &dec.height.to_le_bytes()].concat();
                    if my_pubkey_obj.verify(&sig_msg, dec.signature.as_slice().try_into().unwrap_or(&[0u8; 64])) {
                        decrypted.push(dec);
                    } else {
                        tracing::warn!("Invalid signature on blob {}", hex::encode(&blob.blob_hash[..8]));
                    }
                }
            }
        }
        Ok(decrypted)
    }

    /// Реплицировать блоб на N случайных пиров
    pub fn replicate_to_peers(&self, blob_hash: &[u8; 32], peers: &crate::p2p::peers::PeersManager) -> usize {
        let mut sent = 0;
        if let Some(blob) = self.store.values().flatten().find(|b| b.blob_hash == *blob_hash) {
            if let Ok(data) = bincode::serialize(&blob) {
                let msg = crate::p2p::sync::AtpMessage::BlobResponse { blobs: vec![blob.clone()] };
                if let Ok(msg_data) = bincode::serialize(&msg) {
                    let targets = peers.random_peers(8);
                    for peer_id in &targets {
                        if peers.send_to(peer_id, msg_data.clone()) { sent += 1; }
                    }
                }
            }
        }
        sent
    }

    pub fn blob_count(&self) -> usize { self.store.values().map(|v| v.len()).sum() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevum::crypto::keys::Keypair;

    #[test]
    fn encrypt_decrypt_with_signature() {
        let kp = Keypair::generate();
        let mut rep = EncryptedReplication::new(Some(kp.private.clone()), 100);
        rep.store_blob(&kp.public, BlobType::BalanceProof, vec![1, 2, 3], 100, &kp.private).unwrap();
        let decrypted = rep.decrypt_my_blobs().unwrap();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].data, vec![1, 2, 3]);
        assert!(!decrypted[0].signature.is_empty());
    }

    #[test]
    fn reject_wrong_signature() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let mut rep = EncryptedReplication::new(Some(kp1.private.clone()), 100);
        // Сохраняем блоб подписанный kp2 (чужим ключом)
        rep.store_blob(&kp1.public, BlobType::BalanceProof, vec![1, 2, 3], 100, &kp2.private).unwrap();
        // Расшифровываем — подпись не пройдёт
        let decrypted = rep.decrypt_my_blobs().unwrap();
        assert!(decrypted.is_empty());
    }
}
