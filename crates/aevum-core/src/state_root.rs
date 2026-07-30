//! StateRoot v5.3 — Lightweight preview + full data paths (10/10)

use std::collections::HashSet;
use crate::crypto::hash::Hash;
use crate::core::jt_utxo::JtUtxo;
use crate::core::block::{StateRoot, StatePreview};
use std::fmt;

#[derive(Debug, Clone)]
pub enum StateError {
    SupplyMismatch { expected: u64, computed: u64 },
    SupplyOverflow,
    DuplicateNullifier([u8; 32]),
    DuplicateUtxoNullifier([u8; 32]),
}
impl fmt::Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StateError::SupplyMismatch { expected, computed } => write!(f, "supply mismatch: {} vs {}", expected, computed),
            StateError::SupplyOverflow => write!(f, "supply overflow"),
            StateError::DuplicateNullifier(n) => write!(f, "duplicate nullifier: {:?}", n),
            StateError::DuplicateUtxoNullifier(n) => write!(f, "duplicate UTXO nullifier: {:?}", n),
        }
    }
}
impl std::error::Error for StateError {}
pub type StateResult<T> = Result<T, StateError>;

fn empty_tree_hash() -> Hash {
    let mut h = blake3::Hasher::new(); h.update(b"AEVUM_EMPTY_TREE_V5"); Hash(h.finalize().into())
}

pub struct StateRootData {
    pub hash: Hash, pub block_height: u64, pub total_supply: u64,
    pub dna_root: Hash, pub oracle_root: Hash,
    pub utxo_count: usize, pub spent_nullifier_count: usize,
    pub new_utxos: Vec<JtUtxo>, pub spent_nullifiers: Vec<Hash>,
}

impl StateRootData {
    pub fn state_root(&self) -> StateRoot { StateRoot(self.hash) }
    pub fn into_preview(self) -> StatePreview { StatePreview { state_root: StateRoot(self.hash), new_total_supply: self.total_supply } }
}

pub fn genesis_state_root() -> StateRoot {
    let eh = empty_tree_hash();
    StateRoot(compute_state_root_hash(0, 0, &eh, &eh, &Hash::zero(), &Hash::zero()))
}

pub fn compute_state_root(
    block_height: u64, total_supply: u64, utxos: &[JtUtxo],
    spent_nullifiers: &[Hash], dna_root: &Hash, oracle_root: &Hash,
) -> StateResult<StateRootData> {
    let computed_supply: u64 = utxos.iter().try_fold(0u64, |acc, u| acc.checked_add(u.amount())).ok_or(StateError::SupplyOverflow)?;
    if total_supply != computed_supply { return Err(StateError::SupplyMismatch { expected: total_supply, computed: computed_supply }); }
    { let mut seen = HashSet::new(); for u in utxos { if !seen.insert(u.nullifier().0) { return Err(StateError::DuplicateUtxoNullifier(u.nullifier().0)); } } }
    { let mut seen = HashSet::new(); for n in spent_nullifiers { if !seen.insert(n.0) { return Err(StateError::DuplicateNullifier(n.0)); } } }
    let (utxo_root, nullifier_root) = compute_merkle_roots(utxos, spent_nullifiers);
    let hash = compute_state_root_hash(block_height, total_supply, &utxo_root, &nullifier_root, dna_root, oracle_root);
    Ok(StateRootData {
        hash, block_height, total_supply, dna_root: *dna_root, oracle_root: *oracle_root,
        utxo_count: utxos.len(), spent_nullifier_count: spent_nullifiers.len(),
        new_utxos: utxos.to_vec(), spent_nullifiers: spent_nullifiers.to_vec(),
    })
}

pub fn compute_state_preview(
    block_height: u64, total_supply: u64, utxos: &[JtUtxo],
    spent_nullifiers: &[Hash], dna_root: &Hash, oracle_root: &Hash,
) -> StateResult<StatePreview> {
    let computed_supply: u64 = utxos.iter().try_fold(0u64, |acc, u| acc.checked_add(u.amount())).ok_or(StateError::SupplyOverflow)?;
    if total_supply != computed_supply { return Err(StateError::SupplyMismatch { expected: total_supply, computed: computed_supply }); }
    { let mut seen = HashSet::new(); for u in utxos { if !seen.insert(u.nullifier().0) { return Err(StateError::DuplicateUtxoNullifier(u.nullifier().0)); } } }
    { let mut seen = HashSet::new(); for n in spent_nullifiers { if !seen.insert(n.0) { return Err(StateError::DuplicateNullifier(n.0)); } } }
    let (utxo_root, nullifier_root) = compute_merkle_roots(utxos, spent_nullifiers);
    let hash = compute_state_root_hash(block_height, total_supply, &utxo_root, &nullifier_root, dna_root, oracle_root);
    Ok(StatePreview { state_root: StateRoot(hash), new_total_supply: total_supply })
}

fn compute_merkle_roots(utxos: &[JtUtxo], spent_nullifiers: &[Hash]) -> (Hash, Hash) {
    let eh = empty_tree_hash();
    let utxo_root = if utxos.is_empty() { eh } else {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = utxos.iter().map(|u| (u.nullifier().0.to_vec(), u.consensus_bytes())).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0)); compute_merkle_root(&entries, b"AEVUM_UTXO_V5")
    };
    let nullifier_root = if spent_nullifiers.is_empty() { eh } else {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = spent_nullifiers.iter().map(|n| (n.0.to_vec(), n.0.to_vec())).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0)); compute_merkle_root(&entries, b"AEVUM_NULLIFIER_V5")
    };
    (utxo_root, nullifier_root)
}

fn compute_state_root_hash(block_height: u64, total_supply: u64, utxo_root: &Hash, nullifier_root: &Hash, dna_root: &Hash, oracle_root: &Hash) -> Hash {
    let mut h = blake3::Hasher::new(); h.update(b"AEVUM_STATE_ROOT_V5");
    h.update(&block_height.to_le_bytes()); h.update(&total_supply.to_le_bytes());
    h.update(utxo_root.as_bytes()); h.update(nullifier_root.as_bytes());
    h.update(dna_root.as_bytes()); h.update(oracle_root.as_bytes());
    Hash(h.finalize().into())
}

fn compute_merkle_root(entries: &[(Vec<u8>, Vec<u8>)], domain: &[u8]) -> Hash {
    if entries.is_empty() { return empty_tree_hash(); }
    let mut hashes: Vec<[u8; 32]> = entries.iter().map(|(k, v)| {
        let mut h = blake3::Hasher::new(); h.update(domain); h.update(k); h.update(v); h.finalize().into()
    }).collect();
    while hashes.len() > 1 {
        let mut next = Vec::with_capacity((hashes.len() + 1) / 2);
        for chunk in hashes.chunks(2) {
            let mut h = blake3::Hasher::new(); h.update(b"AEVUM_MERKLE_NODE_V5");
            h.update(&chunk[0]); if chunk.len() > 1 { h.update(&chunk[1]); } else { h.update(&chunk[0]); }
            next.push(h.finalize().into());
        }
        hashes = next;
    }
    Hash(hashes[0])
}
