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
        EncryptedReplication {
            store: HashMap::new(),
            local_key,
            max_blobs,
        }
    }

    pub fn store_blob(
        &mut self,
        owner: &PublicKey,
        blob_type: BlobType,
        data: Vec<u8>,
        height: u64,
        owner_private: &PrivateKey,
    ) -> Result<[u8; 32], String> {
        let decrypted = DecryptedBlob {
            blob_type,
            owner: owner.to_bytes(),
            data,
            height,
            signature: vec![],
        };

        let plaintext = bincode::serialize(&decrypted)
            .map_err(|e| format!("Serialize: {}", e))?;

        let shared_secret = owner_private.diffie_hellman(owner);
        let mut cipher = crate::p2p::noise::AtpCipher::new(&shared_secret);
        let encrypted = cipher.encrypt(&plaintext);

        let blob = EncryptedBlob {
            owner: owner.to_bytes(),
            blob_hash: blake3::hash(&encrypted).into(),
            encrypted_data: encrypted,
            nonce: [0u8; 12],
            version: 1,
            created_height: height,
        };

        let hash = blob.blob_hash;
        let entry = self.store.entry(owner.to_bytes()).or_default();
        if entry.len() >= self.max_blobs {
            entry.remove(0);
        }
        entry.push(blob);

        tracing::info!("Stored encrypted blob for {}", hex::encode(&owner.to_bytes()[..8]));
        Ok(hash)
    }

    pub fn query_blobs(&self, owner: &[u8; 32]) -> Vec<&EncryptedBlob> {
        self.store.get(owner).map(|v| v.iter().collect()).unwrap_or_default()
    }

    pub fn decrypt_my_blobs(&self) -> Result<Vec<DecryptedBlob>, String> {
        let local_key = self.local_key.as_ref().ok_or("No local key")?;
        let my_pubkey = local_key.public_key().to_bytes();
        let blobs = self.query_blobs(&my_pubkey);
        let mut decrypted = Vec::new();

        for blob in blobs {
            let shared_secret = local_key.diffie_hellman(
                &PublicKey::from_bytes(blob.owner).map_err(|_| "Invalid pubkey")?
            );
            let mut cipher = crate::p2p::noise::AtpCipher::new(&shared_secret);
            if let Some(plaintext) = cipher.decrypt(&blob.encrypted_data) {
                if let Ok(dec) = bincode::deserialize::<DecryptedBlob>(&plaintext) {
                    decrypted.push(dec);
                }
            }
        }

        Ok(decrypted)
    }

    pub fn blob_count(&self) -> usize {
        self.store.values().map(|v| v.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevum::crypto::keys::Keypair;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = Keypair::generate();
        let mut rep = EncryptedReplication::new(Some(kp.private.clone()), 100);

        rep.store_blob(&kp.public, BlobType::BalanceProof, vec![1, 2, 3], 100, &kp.private).unwrap();
        let decrypted = rep.decrypt_my_blobs().unwrap();
        assert_eq!(decrypted.len(), 1);
        assert_eq!(decrypted[0].data, vec![1, 2, 3]);
        assert_eq!(decrypted[0].height, 100);
    }
}
