//! SettlementBlock v2 — Консенсусный блок финализации эпохи
//! Строгая цепочка: Genesis → Settlement(0) → Settlement(1) → ...
//! epoch_root = Merkle(presence_root, transaction_root, state_root,
//!                     reward_root, participant_root, epoch_snapshot_root)
//! Комитет подписывает (epoch_commitment || block_hash).
use serde::{Deserialize, Serialize};

use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use crate::core::genesis::GenesisBlock;
use blake3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementBlock {
    pub total_fees: u64,
    pub total_rewards: u64,
    pub version: u32,
    pub chain_id: u32,
    pub epoch_id: u64,
    pub height: u64,
    pub previous_settlement_hash: Hash,
    pub timestamp: u64,
    pub epoch_duration_secs: u64,
    pub epoch_start_time: u64,
    pub epoch_end_time: u64,
    pub presence_root: Hash,
    pub transaction_root: Hash,
    pub state_root: Hash,
    pub reward_root: Hash,
    pub participant_root: Hash,
    pub epoch_snapshot_root: Hash,
    pub presence_record_count: u64,
    pub transaction_count: u64,
    pub participant_count: u64,
    pub epoch_root: Hash,
    pub epoch_commitment: Hash,
    pub total_supply: u64,
    pub block_hash: Hash,
    pub committee_signatures: Vec<crate::crypto::signature::SignatureBytes>,
}

impl SettlementBlock {
    /// Merkle-корень шести data roots
    pub fn compute_epoch_root(&self) -> Hash {
        let roots = [
            self.presence_root.0,
            self.transaction_root.0,
            self.state_root.0,
            self.reward_root.0,
            self.participant_root.0,
            self.epoch_snapshot_root.0,
        ];
        compute_merkle_root(&roots)
    }

    pub fn compute_commitment(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_EPOCH_COMMITMENT_V1");
        h.update(&self.epoch_id.to_le_bytes());
        h.update(self.epoch_root.as_bytes());
        h.update(&self.presence_record_count.to_le_bytes());
        h.update(&self.transaction_count.to_le_bytes());
        h.update(&self.participant_count.to_le_bytes());
        h.update(&self.total_fees.to_le_bytes());
        h.update(&self.total_rewards.to_le_bytes());
        h.update(&self.total_supply.to_le_bytes());
        Hash(h.finalize().into())
    }

    pub fn compute_hash(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_SETTLEMENT_V2");
        h.update(&self.version.to_le_bytes());
        h.update(&self.chain_id.to_le_bytes());
        h.update(&self.epoch_id.to_le_bytes());
        h.update(&self.height.to_le_bytes());
        h.update(self.previous_settlement_hash.as_bytes());
        h.update(&self.timestamp.to_le_bytes());
        h.update(&self.epoch_duration_secs.to_le_bytes());
        h.update(&self.epoch_start_time.to_le_bytes());
        h.update(&self.epoch_end_time.to_le_bytes());
        h.update(self.epoch_commitment.as_bytes());
        Hash(h.finalize().into())
    }

    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(self.epoch_commitment.as_bytes());
        msg.extend_from_slice(self.block_hash.as_bytes());
        msg
    }

    pub fn finalize(&mut self) {
        self.epoch_root = self.compute_epoch_root();
        self.epoch_commitment = self.compute_commitment();
        self.block_hash = self.compute_hash();
    }

    pub fn verify_internal(&self) -> bool {
        self.block_hash == self.compute_hash()
            && self.epoch_root == self.compute_epoch_root()
            && self.epoch_commitment == self.compute_commitment()
    }

    pub fn verify_chain(&self, prev: &SettlementBlock) -> bool {
        self.previous_settlement_hash == prev.block_hash
            && self.epoch_id == prev.epoch_id + 1
            && self.height == prev.height + 1
            && self.chain_id == prev.chain_id
            && self.version == prev.version
    }

    pub fn verify_genesis_link(&self, genesis: &GenesisBlock) -> bool {
        self.epoch_id == 0
            && self.height == 1
            && self.previous_settlement_hash == genesis.block_hash
            && self.chain_id == genesis.chain_id
    }

    pub fn verify_committee_signatures(&self, committee_pubkeys: &[[u8; 32]], threshold: usize) -> bool {
        if threshold == 0 || threshold > committee_pubkeys.len() { return false; }
        if self.committee_signatures.len() > committee_pubkeys.len() { return false; }
        let msg = self.signing_message();
        let mut used: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut valid = 0;
        for sig in &self.committee_signatures {
            if valid >= threshold { break; }
            for pk_bytes in committee_pubkeys {
                if used.contains(pk_bytes) { continue; }
                if let Ok(pubkey) = PublicKey::from_bytes(*pk_bytes) {
                    if pubkey.verify(&msg, sig.as_bytes()) { used.insert(*pk_bytes); valid += 1; break; }
                }
            }
        }
        valid >= threshold
    }

    pub fn verify_full(
        &self, prev_settlement: Option<&SettlementBlock>,
        genesis: Option<&GenesisBlock>, committee_pubkeys: &[[u8; 32]], threshold: usize,
    ) -> bool {
        if !self.verify_internal() { return false; }
        match prev_settlement {
            Some(prev) => { if !self.verify_chain(prev) { return false; } }
            None => {
                if let Some(gen) = genesis {
                    if !self.verify_genesis_link(gen) { return false; }
                } else { return false; }
            }
        }
        self.verify_committee_signatures(committee_pubkeys, threshold)
    }
}

fn compute_merkle_root(items: &[[u8; 32]]) -> Hash {
    if items.is_empty() { return Hash::zero(); }
    let mut layer: Vec<[u8; 32]> = items.to_vec();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for chunk in layer.chunks(2) {
            let mut h = blake3::Hasher::new();
            h.update(b"AEVUM_MERKLE_V1");
            h.update(&chunk[0]);
            if chunk.len() == 2 { h.update(&chunk[1]); } else { h.update(&chunk[0]); }
            next.push(h.finalize().into());
        }
        layer = next;
    }
    Hash(layer[0])
}
