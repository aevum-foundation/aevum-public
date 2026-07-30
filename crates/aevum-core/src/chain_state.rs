//! Chain State v10 — Two-Phase with getters (10/10)

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use parking_lot::RwLock;
use crate::core::block::{Block, BlockCandidate, StatePreview, StateRoot};
use crate::core::jt_utxo::JtUtxo;
use crate::core::state_transition::{self, TransitionError};
use crate::core::state_root::StateRootData;
use crate::emission;
use crate::crypto::hash::Hash;

const MAX_REORG_DEPTH: u64 = 64;

#[derive(Debug, Clone)]
pub struct ApplyBlockResult {
    pub new_height: u64, pub new_supply: u64, pub state_root: Hash,
    pub utxo_count: usize, pub spent_count: usize,
}

#[derive(Debug, Clone)]
pub enum ChainStateError {
    Execution(TransitionError), BlockAlreadyApplied { height: u64, hash: Hash },
    ForkRejected { height: u64, existing: Hash, new: Hash }, BelowFinalized { height: u64, finalized: u64 },
    ReorgTooDeep { current: u64, attempted: u64, max: u64 }, InvalidBlockHash,
    PrevHashMismatch { expected: Hash, got: Hash }, HeightMismatch { expected: u64, got: u64 },
    HeightRegression { current: u64, got: u64 }, GenesisAlreadyApplied, GenesisNotApplied,
    GenesisPrevHashNotZero, GenesisNotEmpty, GenesisStateNotEmpty, PostCheckZeroAmount,
    PostCheckDuplicateUtxo, PostCheckDuplicateSpent, PostCheckSupplyMismatch { derived: u64, declared: u64 },
    CanonicalInvariantBroken, PreviewFailed(String),
}
impl std::fmt::Display for ChainStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self { Self::Execution(e) => write!(f, "execution: {}", e), Self::PreviewFailed(s) => write!(f, "preview: {}", s), _ => write!(f, "{:?}", self) }
    }
}
impl std::error::Error for ChainStateError {}
impl From<TransitionError> for ChainStateError { fn from(e: TransitionError) -> Self { ChainStateError::Execution(e) } }
pub type ChainStateResult<T> = Result<T, ChainStateError>;

pub struct ChainState { inner: RwLock<ChainStateInner> }

struct ChainStateInner {
    utxos: BTreeMap<Hash, JtUtxo>, spent_nullifiers: HashSet<Hash>,
    state_root: Hash, dna_root: Hash, oracle_root: Hash, cached_supply: u64,
    height: u64, last_block_hash: Hash, canonical_tip: Hash, canonical_height: u64,
    last_finalized_height: u64, applied_blocks: BTreeMap<u64, Hash>, genesis_applied: bool, epoch_anchor_hash: Hash, current_epoch: u64,
}

impl ChainState {
    pub fn new() -> Self {
        Self { inner: RwLock::new(ChainStateInner {
            utxos: BTreeMap::new(), spent_nullifiers: HashSet::new(),
            state_root: crate::core::state_root::genesis_state_root().0, dna_root: Hash::zero(), oracle_root: Hash::zero(),
            cached_supply: 0, height: 0, last_block_hash: Hash::zero(), canonical_tip: Hash::zero(), canonical_height: 0,
            last_finalized_height: 0, applied_blocks: BTreeMap::new(), genesis_applied: false, epoch_anchor_hash: Hash::zero(), current_epoch: 0,
        })}
    }

    pub fn preview_block(&self, candidate: &BlockCandidate) -> ChainStateResult<StatePreview> {
        let inner = self.inner.read();
        let utxo_vec: Vec<JtUtxo> = inner.utxos.values().cloned().collect();
        let spent_vec: Vec<Hash> = inner.spent_nullifiers.iter().cloned().collect();
        state_transition::preview_block_candidate(candidate, &inner.last_block_hash, &utxo_vec, &spent_vec,
            inner.cached_supply, &inner.dna_root, &inner.oracle_root).map_err(|e| ChainStateError::PreviewFailed(e.to_string()))
    }

    pub fn apply_block_checked(&self, block: &Block) -> ChainStateResult<ApplyBlockResult> {
        let computed = block.compute_hash();
        if computed != *block.block_hash() { return Err(ChainStateError::InvalidBlockHash); }
        let mut inner = self.inner.write();
        if block.height() == 0 { return self.apply_genesis(block, &mut inner); }
        if !inner.genesis_applied { return Err(ChainStateError::GenesisNotApplied); }
        if block.height() <= inner.last_finalized_height { return Err(ChainStateError::BelowFinalized { height: block.height(), finalized: inner.last_finalized_height }); }
        if block.height() < inner.height { return Err(ChainStateError::HeightRegression { current: inner.height, got: block.height() }); }
        if block.height() < inner.canonical_height {
            let depth = inner.canonical_height - block.height();
            if depth > MAX_REORG_DEPTH { return Err(ChainStateError::ReorgTooDeep { current: inner.canonical_height, attempted: block.height(), max: MAX_REORG_DEPTH }); }
        }
        let extends_tip = *block.prev_hash() == inner.canonical_tip;
        if !extends_tip {
            let expected = inner.last_block_hash;
            if *block.prev_hash() != expected { return Err(ChainStateError::PrevHashMismatch { expected, got: *block.prev_hash() }); }
        }
        if let Some(existing) = inner.applied_blocks.get(&block.height()) {
            if *existing != *block.block_hash() { return Err(ChainStateError::ForkRejected { height: block.height(), existing: *existing, new: *block.block_hash() }); }
            return Err(ChainStateError::BlockAlreadyApplied { height: block.height(), hash: *block.block_hash() });
        }
        let utxo_vec: Vec<JtUtxo> = inner.utxos.values().cloned().collect();
        let spent_vec: Vec<Hash> = inner.spent_nullifiers.iter().cloned().collect();
        let result = state_transition::apply_block(block, &inner.last_block_hash, &utxo_vec, &spent_vec,
            inner.cached_supply, &inner.dna_root, &inner.oracle_root)?;
        let derived = result.total_supply;
        inner.utxos.clear(); for u in &result.new_utxos { inner.utxos.insert(*u.nullifier(), u.clone()); }
        inner.spent_nullifiers.clear(); for n in &result.spent_nullifiers { inner.spent_nullifiers.insert(*n); }
        inner.state_root = result.hash; inner.dna_root = result.dna_root; inner.oracle_root = result.oracle_root;
        inner.cached_supply = derived;
        inner.height = block.height(); inner.last_block_hash = *block.block_hash();
        if extends_tip || block.height() > inner.canonical_height { inner.canonical_tip = *block.block_hash(); inner.canonical_height = block.height(); }
        if block.settlement_checkpoint().is_some() {
            inner.epoch_anchor_hash = *block.block_hash();
            inner.current_epoch = block.height() / emission::EPOCH_LENGTH_BLOCKS;
        }
        inner.applied_blocks.insert(block.height(), *block.block_hash());
        Ok(ApplyBlockResult { new_height: block.height(), new_supply: derived, state_root: result.hash,
            utxo_count: inner.utxos.len(), spent_count: inner.spent_nullifiers.len() })
    }

    fn apply_genesis(&self, block: &Block, inner: &mut ChainStateInner) -> ChainStateResult<ApplyBlockResult> {
        if inner.genesis_applied { return Err(ChainStateError::GenesisAlreadyApplied); }
        if *block.prev_hash() != Hash::zero() { return Err(ChainStateError::GenesisPrevHashNotZero); }
        if block.transactions().len() != 1 || !block.transactions()[0].is_coinbase() { return Err(ChainStateError::GenesisNotEmpty); }
        let result = state_transition::apply_block(block, &Hash::zero(), &[], &[], 0, &Hash::zero(), &Hash::zero())?;
        inner.state_root = result.hash; inner.dna_root = Hash::zero(); inner.oracle_root = Hash::zero();
        inner.cached_supply = result.total_supply;
        inner.height = 0; inner.last_block_hash = *block.block_hash();
        inner.canonical_tip = *block.block_hash(); inner.canonical_height = 0;
        inner.applied_blocks.insert(0, *block.block_hash()); inner.genesis_applied = true;
        inner.epoch_anchor_hash = *block.block_hash();
        inner.utxos.clear(); for u in &result.new_utxos { inner.utxos.insert(*u.nullifier(), u.clone()); }
        Ok(ApplyBlockResult { new_height: 0, new_supply: result.total_supply, state_root: result.hash,
            utxo_count: inner.utxos.len(), spent_count: 0 })
    }

    pub fn height(&self) -> u64 { self.inner.read().height }
    pub fn supply(&self) -> u64 { self.inner.read().cached_supply }
    pub fn state_root(&self) -> Hash { self.inner.read().state_root }
    pub fn last_block_hash(&self) -> Hash { self.inner.read().last_block_hash }
    pub fn epoch_anchor_hash(&self) -> Hash { self.inner.read().epoch_anchor_hash }
    pub fn current_epoch(&self) -> u64 { self.inner.read().current_epoch }
    pub fn genesis_applied(&self) -> bool { self.inner.read().genesis_applied }
    pub fn apply_presence_record(&self, block: &Block) -> ChainStateResult<ApplyBlockResult> {
        let mut inner = self.inner.write();
        if !inner.genesis_applied { return Err(ChainStateError::GenesisNotApplied); }
        let utxo_vec: Vec<JtUtxo> = inner.utxos.values().cloned().collect();
        let spent_vec: Vec<Hash> = inner.spent_nullifiers.iter().cloned().collect();
        let result = state_transition::apply_block(block, &inner.last_block_hash, &utxo_vec, &spent_vec,
            inner.cached_supply, &inner.dna_root, &inner.oracle_root)?;
        let derived = result.total_supply;
        inner.utxos.clear(); for u in &result.new_utxos { inner.utxos.insert(*u.nullifier(), u.clone()); }
        inner.spent_nullifiers.clear(); for n in &result.spent_nullifiers { inner.spent_nullifiers.insert(*n); }
        inner.state_root = result.hash; inner.dna_root = result.dna_root; inner.oracle_root = result.oracle_root;
        inner.cached_supply = derived;
        inner.height = block.height(); inner.last_block_hash = *block.block_hash();
        if *block.prev_hash() == inner.canonical_tip || block.height() > inner.canonical_height {
            inner.canonical_tip = *block.block_hash(); inner.canonical_height = block.height();
        }
        if block.settlement_checkpoint().is_some() {
            inner.epoch_anchor_hash = *block.block_hash();
            inner.current_epoch = block.height() / emission::EPOCH_LENGTH_BLOCKS;
        }
        Ok(ApplyBlockResult { new_height: block.height(), new_supply: derived, state_root: result.hash,
            utxo_count: inner.utxos.len(), spent_count: inner.spent_nullifiers.len() })
    }

    pub fn finalize_up_to(&self, height: u64) { let mut inner = self.inner.write(); if height > inner.last_finalized_height { inner.last_finalized_height = height; } }
}
pub type SharedChainState = Arc<ChainState>;
pub fn new_shared_chain_state() -> SharedChainState { Arc::new(ChainState::new()) }
