//! GenesisBlock v1 — Initial state creation

use serde::{Deserialize, Serialize};
use crate::crypto::hash::Hash;
use crate::core::transaction::Transaction;
use crate::core::block::StateRoot;
use blake3;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub version: u32,
    pub chain_id: u32,
    pub height: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub state_root: StateRoot,
    pub total_supply: u64,
    pub block_hash: Hash,
}

impl GenesisBlock {
    pub fn compute_hash(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_GENESIS_V1");
        h.update(&self.version.to_le_bytes());
        h.update(&self.chain_id.to_le_bytes());
        h.update(&self.height.to_le_bytes());
        h.update(&self.timestamp.to_le_bytes());
        for tx in &self.transactions {
            h.update(tx.tx_hash.as_bytes());
        }
        h.update(self.state_root.0.as_bytes());
        h.update(&self.total_supply.to_le_bytes());
        Hash(h.finalize().into())
    }

    pub fn finalize(&mut self, expected_chain_id: u32) -> Result<(), &'static str> {
        if self.height != 0 { return Err("genesis height must be 0"); }
        if self.chain_id != expected_chain_id { return Err("wrong chain_id"); }
        if self.total_supply == 0 { return Err("genesis supply is zero"); }
        if self.transactions.len() != 1 || !self.transactions[0].is_coinbase() {
            return Err("genesis must have exactly one coinbase transaction");
        }
        self.block_hash = self.compute_hash();
        Ok(())
    }

    pub fn verify_internal(&self, expected_chain_id: u32) -> bool {
        self.height == 0
            && self.chain_id == expected_chain_id
            && self.total_supply > 0
            && self.transactions.len() == 1
            && self.transactions[0].is_coinbase()
            && self.block_hash == self.compute_hash()
    }
}
