//! PresenceRecord v2 — Epoch Data DAG
//! Each record references multiple parent records.
//! Resilient to loss of individual records.
//! sequence is a local node counter, NOT global ordering.
use serde::{Deserialize, Serialize};

use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use crate::core::transaction::Transaction;
use blake3;

pub const MAX_TRANSACTIONS_PER_RECORD: usize = 10_000;
pub const MAX_PARENT_RECORDS: usize = 64;
pub const MAX_RECORD_FUTURE_DRIFT_SECS: u64 = 30;

#[repr(u8)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PresenceRecordType {
    PresenceHeartbeat = 0,
    TransactionBatch = 1,
    StateUpdate = 2,
}

impl PresenceRecordType {
    pub fn as_byte(&self) -> u8 {
        match self {
            Self::PresenceHeartbeat => 0,
            Self::TransactionBatch => 1,
            Self::StateUpdate => 2,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceRecord {
    pub version: u32,
    pub chain_id: u32,
    pub epoch_id: u64,
    pub epoch_anchor_hash: Hash,
    /// NOT GLOBAL ORDERING — local node counter only. Do NOT use for consensus ordering.
    pub sequence: u64,
    pub node_id: [u8; 32],
    pub record_type: PresenceRecordType,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    /// Canonical list of parent records (sorted, deduped)
    pub parent_records: Vec<Hash>,
    pub record_hash: Hash,
    pub signature: crate::crypto::signature::SignatureBytes,
}

impl PresenceRecord {
    pub fn first_in_epoch(
        version: u32, chain_id: u32, epoch_id: u64, epoch_anchor_hash: Hash,
        node_id: [u8; 32], record_type: PresenceRecordType, timestamp: u64,
        transactions: Vec<Transaction>,
    ) -> Self {
        Self {
            version, chain_id, epoch_id, epoch_anchor_hash,
            sequence: 0, node_id, record_type, timestamp, transactions,
            parent_records: vec![epoch_anchor_hash],
            record_hash: Hash::zero(),
            signature: crate::crypto::signature::SignatureBytes::zero(),
        }
    }

    pub fn with_parents(
        version: u32, chain_id: u32, epoch_id: u64, epoch_anchor_hash: Hash,
        sequence: u64, node_id: [u8; 32], record_type: PresenceRecordType,
        timestamp: u64, transactions: Vec<Transaction>,
        mut parent_records: Vec<Hash>,
    ) -> Self {
        parent_records.sort();
        parent_records.dedup();
        Self {
            version, chain_id, epoch_id, epoch_anchor_hash,
            sequence, node_id, record_type, timestamp, transactions,
            parent_records,
            record_hash: Hash::zero(),
            signature: crate::crypto::signature::SignatureBytes::zero(),
        }
    }

    pub fn compute_hash(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_PRESENCE_RECORD_V2");
        h.update(&self.version.to_le_bytes());
        h.update(&self.chain_id.to_le_bytes());
        h.update(&self.epoch_id.to_le_bytes());
        h.update(self.epoch_anchor_hash.as_bytes());
        h.update(&self.sequence.to_le_bytes());
        h.update(&self.node_id);
        h.update(&[self.record_type.as_byte()]);
        h.update(&self.timestamp.to_le_bytes());
        for tx in &self.transactions {
            h.update(tx.tx_hash.as_bytes());
        }
        // parent_records are already canonicalized in with_parents
        for parent in &self.parent_records {
            h.update(parent.as_bytes());
        }
        Hash(h.finalize().into())
    }

    pub fn finalize(&mut self, current_time: u64) -> Result<(), &'static str> {
        if self.transactions.len() > MAX_TRANSACTIONS_PER_RECORD {
            return Err("too many transactions");
        }
        if self.parent_records.is_empty() {
            return Err("parent_records cannot be empty");
        }
        if self.parent_records.len() > MAX_PARENT_RECORDS {
            return Err("too many parent records");
        }
        if self.timestamp > current_time.saturating_add(MAX_RECORD_FUTURE_DRIFT_SECS) {
            return Err("timestamp too far in future");
        }
        // Canonicalize parent hashes
        self.parent_records.sort();
        self.parent_records.dedup();
        self.record_hash = self.compute_hash();
        Ok(())
    }

    pub fn verify_hash_integrity(&self) -> bool {
        self.record_hash == self.compute_hash()
    }

    pub fn verify_signature(&self, pubkey: &PublicKey) -> bool {
        pubkey.verify(self.record_hash.as_bytes(), self.signature.as_bytes())
    }

    pub fn verify(&self, pubkey: &PublicKey) -> bool {
        self.verify_hash_integrity() && self.verify_signature(pubkey)
    }
}

/// Verify that adding a record does not create a cycle in the epoch DAG
pub fn verify_dag_acyclic(
    record: &PresenceRecord,
    epoch_records: &std::collections::HashMap<Hash, PresenceRecord>,
) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![record.record_hash];
    while let Some(current) = stack.pop() {
        if !visited.insert(current) { continue; }
        if current == record.record_hash && !stack.is_empty() { continue; }
        if let Some(r) = epoch_records.get(&current) {
            for parent in &r.parent_records {
                if *parent == record.record_hash { return false; } // cycle detected
                stack.push(*parent);
            }
        }
    }
    true
}
