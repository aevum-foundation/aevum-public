use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedBlob { pub owner: [u8; 32], pub blob_hash: [u8; 32], pub encrypted_data: Vec<u8>, pub nonce: [u8; 12], pub version: u16, pub created_height: u64 }
pub struct EncryptedReplication;
impl EncryptedReplication {
    pub fn new<T>(_key: Option<T>, _max: usize) -> Self { EncryptedReplication }
    pub fn query_blobs_by_hash(&self, _hashes: &[[u8; 32]]) -> Vec<EncryptedBlob> { vec![] }
    pub fn store_received(&mut self, _blob: EncryptedBlob) {}
}
