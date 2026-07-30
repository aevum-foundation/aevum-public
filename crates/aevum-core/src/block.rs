//! Block v15 — pub(crate) fields + Two-Phase + getters (10/10)

use serde::{Deserialize, Serialize};
use crate::crypto::hash::Hash;
use crate::core::transaction::Transaction;
use blake3;

pub const MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TRANSACTIONS: usize = 100_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementCheckpoint {
    pub epoch_id: u64, pub cursor: u64,
    pub total_participants: u64, pub participants_commitment: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct BlockCandidate {
    pub prev_hash: Hash, pub height: u64,
    pub poh_tick_start: u64, pub poh_tick_end: u64,
    pub transactions: Vec<Transaction>,
    pub is_presence_block: bool,
    pub settlement_checkpoint: Option<SettlementCheckpoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRoot(pub Hash);

#[derive(Clone, Debug)]
pub struct StatePreview {
    pub state_root: StateRoot,
    pub new_total_supply: u64,
}

#[derive(Debug, Clone)]
pub enum BlockError {
    ZeroStateRoot { height: u64 }, ZeroSupply { height: u64, supply: u64 },
    InvalidBlockHash { expected: Hash, actual: Hash }, TooLarge { size: usize, max: usize },
    TooManyTransactions { count: usize, max: usize }, InvalidPoHTicks { start: u64, end: u64 },
    InvalidTransactionsRoot { expected: Hash, actual: Hash }, Consensus(String),
}
impl std::fmt::Display for BlockError { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { write!(f, "{:?}", self) } }
impl std::error::Error for BlockError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub(crate) prev_hash: Hash,
    pub(crate) height: u64,
    pub(crate) poh_tick_start: u64,
    pub(crate) poh_tick_end: u64,
    pub(crate) transactions_root: Hash,
    pub(crate) transactions: Vec<Transaction>,
    pub(crate) state_root: StateRoot,
    pub(crate) total_supply: u64,
    pub(crate) block_hash: Hash,
    pub(crate) block_size: usize,
    pub(crate) is_presence_block: bool,
    pub(crate) settlement_checkpoint: Option<SettlementCheckpoint>,
}

impl Block {
    pub fn from_candidate(candidate: BlockCandidate, preview: &StatePreview) -> Result<Self, BlockError> {
        if preview.state_root == StateRoot(Hash::zero()) && candidate.height > 0 {
            return Err(BlockError::ZeroStateRoot { height: candidate.height });
        }
        if preview.new_total_supply == 0 && candidate.height > 0 {
            return Err(BlockError::ZeroSupply { height: candidate.height, supply: preview.new_total_supply });
        }
        let tx_root = compute_transactions_root(&candidate.transactions);
        let block_size = 256usize.saturating_add(candidate.transactions.len().saturating_mul(512));
        let mut block = Self {
            prev_hash: candidate.prev_hash, height: candidate.height,
            poh_tick_start: candidate.poh_tick_start, poh_tick_end: candidate.poh_tick_end,
            transactions_root: tx_root, transactions: candidate.transactions,
            state_root: preview.state_root, total_supply: preview.new_total_supply,
            block_hash: Hash::zero(), block_size, is_presence_block: candidate.is_presence_block,
            settlement_checkpoint: candidate.settlement_checkpoint,
        };
        block.block_hash = block.compute_hash();
        Ok(block)
    }

    pub fn new(prev_hash: Hash, height: u64, poh_start: u64, poh_end: u64,
               transactions: Vec<Transaction>, state_root: Hash, total_supply: u64) -> Self {
        let tx_root = compute_transactions_root(&transactions);
        let block_size = 256usize.saturating_add(transactions.len().saturating_mul(512));
        let mut block = Self {
            prev_hash, height, poh_tick_start: poh_start, poh_tick_end: poh_end,
            transactions_root: tx_root, transactions, state_root: StateRoot(state_root), total_supply,
            block_hash: Hash::zero(), block_size, is_presence_block: true, settlement_checkpoint: None,
        };
        block.block_hash = block.compute_hash();
        block
    }

    pub fn finalize_state(&mut self, state_root: StateRoot, new_supply: u64) {
        self.state_root = state_root;
        self.total_supply = new_supply;
        self.block_hash = self.compute_hash();
    }

    pub fn prev_hash(&self) -> &Hash { &self.prev_hash }
    pub fn height(&self) -> u64 { self.height }
    pub fn poh_tick_start(&self) -> u64 { self.poh_tick_start }
    pub fn poh_tick_end(&self) -> u64 { self.poh_tick_end }
    pub fn transactions_root(&self) -> &Hash { &self.transactions_root }
    pub fn transactions(&self) -> &[Transaction] { &self.transactions }
    pub fn state_root(&self) -> &StateRoot { &self.state_root }
    pub fn total_supply(&self) -> u64 { self.total_supply }
    pub fn block_hash(&self) -> &Hash { &self.block_hash }
    pub fn block_size(&self) -> usize { self.block_size }
    pub fn is_presence_block(&self) -> bool { self.is_presence_block }
    pub fn settlement_checkpoint(&self) -> Option<&SettlementCheckpoint> { self.settlement_checkpoint.as_ref() }
    pub fn is_genesis(&self) -> bool { self.height == 0 && self.prev_hash == Hash::zero() }
    pub fn heartbeat_tx(&self) -> Option<&Transaction> { self.transactions.first().filter(|tx| tx.is_heartbeat()) }
    pub fn coinbase_tx(&self) -> Option<&Transaction> { self.transactions.iter().find(|tx| tx.is_coinbase()) }

    pub fn compute_hash(&self) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_BLOCK");
        h.update(&self.height.to_le_bytes()); h.update(self.prev_hash.as_bytes());
        h.update(&self.poh_tick_start.to_le_bytes()); h.update(&self.poh_tick_end.to_le_bytes());
        h.update(self.transactions_root.as_bytes()); h.update(self.state_root.0.as_bytes());
        h.update(&self.total_supply.to_le_bytes()); h.update(&[self.is_presence_block as u8]);
        if let Some(ref cp) = self.settlement_checkpoint {
            h.update(&cp.epoch_id.to_le_bytes()); h.update(&cp.cursor.to_le_bytes());
            h.update(&cp.total_participants.to_le_bytes()); h.update(&cp.participants_commitment);
        }
        Hash(h.finalize().into())
    }

    pub fn validate_internal(&self) -> Result<(), BlockError> {
        if self.block_hash != self.compute_hash() { return Err(BlockError::InvalidBlockHash { expected: self.compute_hash(), actual: self.block_hash }); }
        if self.block_size > MAX_BLOCK_BYTES { return Err(BlockError::TooLarge { size: self.block_size, max: MAX_BLOCK_BYTES }); }
        if self.transactions.is_empty() || self.transactions.len() > MAX_TRANSACTIONS { return Err(BlockError::TooManyTransactions { count: self.transactions.len(), max: MAX_TRANSACTIONS }); }
        if self.poh_tick_end < self.poh_tick_start { return Err(BlockError::InvalidPoHTicks { start: self.poh_tick_start, end: self.poh_tick_end }); }
        if self.transactions_root != compute_transactions_root(&self.transactions) { return Err(BlockError::InvalidTransactionsRoot { expected: compute_transactions_root(&self.transactions), actual: self.transactions_root }); }
        let mut heartbeat = 0u8; let mut coinbase = 0u8;
        let mut seen_nullifiers = std::collections::BTreeSet::new();
        for (i, tx) in self.transactions.iter().enumerate() {
            if tx.is_heartbeat() { heartbeat = heartbeat.saturating_add(1); if i != 0 { return Err(BlockError::Consensus("heartbeat not first".into())); } continue; }
            if tx.is_coinbase() { coinbase = coinbase.saturating_add(1); if coinbase > 1 { return Err(BlockError::Consensus("duplicate coinbase".into())); } continue; }
            if tx.poh_tick < self.poh_tick_start || tx.poh_tick > self.poh_tick_end { return Err(BlockError::Consensus("tx outside PoH".into())); }
            for inp in &tx.inputs { if inp.nullifier.0 == [0u8; 32] { return Err(BlockError::Consensus("zero nullifier".into())); } if !seen_nullifiers.insert(inp.nullifier.0) { return Err(BlockError::Consensus("duplicate nullifier".into())); } }
            let out_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
            if out_sum == 0 && tx.fee == 0 { return Err(BlockError::Consensus("zero value tx".into())); }
            if tx.locktime > 0 && tx.locktime > self.height { return Err(BlockError::Consensus("tx locked".into())); }
        }
        let expected_hb = if self.is_genesis() { 0 } else { 1 };
        if heartbeat != expected_hb || coinbase != 1 { return Err(BlockError::Consensus(format!("hb={} cb={}", heartbeat, coinbase))); }
        Ok(())
    }
}

fn compute_transactions_root(txs: &[Transaction]) -> Hash {
    if txs.is_empty() { return Hash::zero(); }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|t| t.tx_hash.0).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let mut h = blake3::Hasher::new(); h.update(b"AEVUM_MERKLE_V15");
            h.update(&chunk[0]); if chunk.len() == 2 { h.update(&chunk[1]); } else { h.update(&chunk[0]); }
            next.push(h.finalize().into());
        }
        level = next;
    }
    Hash(level[0])
}
