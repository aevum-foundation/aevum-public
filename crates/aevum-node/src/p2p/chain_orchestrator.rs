use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::jt_utxo::JtUtxo;
use aevum::crypto::hash::Hash;
use aevum::crypto::keys::PublicKey;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::SyncContext;
use crate::storage::Storage;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CHECKPOINT_INTERVAL: u64 = 1000;
const MAX_FORK_QUEUE: usize = 16;
const MAX_CANDIDATES_PER_PEER: usize = 2;
const FORK_CANDIDATE_TTL: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub enum OrchestratorError {
    StorageFailed { operation: String, detail: String },
    ValidationFailed { height: u64, reason: String },
    ForkQueueFull,
    InvalidBlock { height: u64, expected_hash: String, got_hash: String },
}
impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OrchestratorError::StorageFailed { operation, detail } => write!(f, "Storage {}: {}", operation, detail),
            OrchestratorError::ValidationFailed { height, reason } => write!(f, "Validation at {}: {}", height, reason),
            OrchestratorError::ForkQueueFull => write!(f, "Fork queue full"),
            OrchestratorError::InvalidBlock { height, expected_hash, got_hash } => write!(f, "Block {}: expected {} got {}", height, expected_hash, got_hash),
        }
    }
}
impl std::error::Error for OrchestratorError {}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct WalEntry { operation: String, height: u64, block_hash: Option<[u8; 32]>, timestamp: u64 }

struct WriteAheadLog { entries: VecDeque<WalEntry>, max_entries: usize }
impl WriteAheadLog {
    fn new() -> Self { WriteAheadLog { entries: VecDeque::with_capacity(1000), max_entries: 1000 } }
    fn log(&mut self, st: &mut Storage, op: &str, h: u64, hash: Option<Hash>) -> Result<(), OrchestratorError> {
        if self.entries.len() >= self.max_entries { self.entries.pop_front(); }
        let e = WalEntry { operation: op.to_string(), height: h, block_hash: hash.map(|h| h.0), timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() };
        self.entries.push_back(e.clone());
        let d = bincode::serialize(&e).map_err(|e| OrchestratorError::StorageFailed { operation: "wal_ser".into(), detail: format!("{:?}", e) })?;
        st.save_metadata("orchestrator_wal", &d).map_err(|e| OrchestratorError::StorageFailed { operation: "wal_save".into(), detail: format!("{:?}", e) })?;
        Ok(())
    }
    fn recover(st: &Storage) -> Option<Self> { let d = st.load_metadata("orchestrator_wal").ok().flatten()?; let e: WalEntry = bincode::deserialize(&d).ok()?; let mut w = WriteAheadLog::new(); w.entries.push_back(e); Some(w) }
}

struct CheckpointManager;
impl CheckpointManager {
    fn save(st: &mut Storage, h: u64, hash: Hash) -> Result<(), OrchestratorError> { st.save_metadata(&format!("cp_{}", h), &hash.0).map_err(|e| OrchestratorError::StorageFailed { operation: "cp_save".into(), detail: format!("{:?}", e) }) }
    fn get(st: &Storage, h: u64) -> Option<Hash> { st.load_metadata(&format!("cp_{}", h)).ok().flatten().and_then(|d| bincode::deserialize(&d).ok()) }
    fn finalize(st: &Storage, h: u64) -> Result<(), OrchestratorError> { st.save_metadata("finalized_cp", &h.to_le_bytes()).map_err(|e| OrchestratorError::StorageFailed { operation: "cp_fin".into(), detail: format!("{:?}", e) }) }
}

struct ForkCandidate { peer_id: [u8; 20], blocks: Vec<(u64, Vec<u8>)>, total_height: u64, timestamp: Instant }
struct ForkQueue { queue: VecDeque<ForkCandidate>, peer_counts: HashMap<[u8; 20], usize> }
impl ForkQueue {
    fn new() -> Self { ForkQueue { queue: VecDeque::with_capacity(MAX_FORK_QUEUE), peer_counts: HashMap::new() } }
    fn push(&mut self, c: ForkCandidate) -> Result<(), OrchestratorError> {
        let cnt = self.peer_counts.entry(c.peer_id).or_insert(0);
        if *cnt >= MAX_CANDIDATES_PER_PEER { return Err(OrchestratorError::ForkQueueFull); }
        if self.queue.len() >= MAX_FORK_QUEUE { return Err(OrchestratorError::ForkQueueFull); }
        *cnt += 1; self.queue.push_back(c); Ok(())
    }
    fn pop_best(&mut self) -> Option<ForkCandidate> {
        let best = self.queue.iter().enumerate().max_by_key(|(_, c)| c.total_height).map(|(i, _)| i);
        best.map(|i| { let c = self.queue.remove(i).unwrap(); self.peer_counts.entry(c.peer_id).and_modify(|e| *e = e.saturating_sub(1)); c })
    }
    fn cleanup(&mut self) { self.queue.retain(|c| { if c.timestamp.elapsed() > FORK_CANDIDATE_TTL { self.peer_counts.entry(c.peer_id).and_modify(|e| *e = e.saturating_sub(1)); false } else { true } }); }
}

#[derive(Clone, Debug, Default)]
pub struct OrchestratorMetrics {
    pub blocks_analyzed: u64, pub rewards_distributed: u64, pub miners_synchronized: u64,
    pub forks_detected: u64, pub switches_performed: u64, pub total_refunded: u64, pub last_height_processed: u64,
}

pub struct ChainOrchestrator {
    wal: WriteAheadLog, fork_queue: ForkQueue,
    pub processed_height: u64, pub metrics: OrchestratorMetrics,
    last_fork_resolved_at: Option<Instant>,
}

impl ChainOrchestrator {
    pub fn new() -> Self {
        ChainOrchestrator { wal: WriteAheadLog::new(), fork_queue: ForkQueue::new(), processed_height: 0, metrics: OrchestratorMetrics::default(), last_fork_resolved_at: None }
    }
    pub fn recover(st: &Storage) -> Self {
        let wal = WriteAheadLog::recover(st);
        let processed = st.load_metadata("orch_processed_height").ok().flatten().and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(0);
        ChainOrchestrator { wal: wal.unwrap_or_else(WriteAheadLog::new), fork_queue: ForkQueue::new(), processed_height: processed, metrics: OrchestratorMetrics::default(), last_fork_resolved_at: None }
    }

    fn save_progress(&self, st: &mut Storage) -> Result<(), OrchestratorError> {
        st.save_metadata("orch_processed_height", &bincode::serialize(&self.processed_height).unwrap_or_default()).map_err(|e| OrchestratorError::StorageFailed { operation: "save_progress".into(), detail: format!("{:?}", e) })
    }

    pub fn process_chain(&mut self, val: &mut Validator, st: &mut Storage) -> Result<u64, OrchestratorError> {
        let current = val.last_block_height();
        if current <= self.processed_height { return Ok(0); }
        let mut processed = 0u64;
        for h in (self.processed_height + 1)..=current {
            let block = match st.load_genesis_block(h) { Ok(Some(b)) => b, _ => continue };
            if !self.verify_block(&block, h, st)? { continue; }
            self.analyze(&block, h); self.distribute(&block);
            self.processed_height = h; processed += 1; self.metrics.blocks_analyzed += 1; self.metrics.last_height_processed = h;
            if h % CHECKPOINT_INTERVAL == 0 { CheckpointManager::save(st, h, block.block_hash)?; if h >= 100 { CheckpointManager::finalize(st, h - 100).ok(); } self.save_progress(st)?; }
        }
        self.save_progress(st)?;
        Ok(processed)
    }

    fn verify_block(&self, block: &Block, h: u64, st: &Storage) -> Result<bool, OrchestratorError> {
        if block.compute_hash() != block.block_hash { return Err(OrchestratorError::InvalidBlock { height: h, expected_hash: block.compute_hash().to_hex(), got_hash: block.block_hash.to_hex() }); }
        if h > 0 { if let Ok(Some(p)) = st.load_genesis_block(h - 1) { if block.prev_hash != p.block_hash { return Err(OrchestratorError::InvalidBlock { height: h, expected_hash: p.block_hash.to_hex(), got_hash: block.prev_hash.to_hex() }); } } }
        if block.transactions.is_empty() { return Err(OrchestratorError::ValidationFailed { height: h, reason: "Empty".into() }); }
        let cb = block.transactions.iter().filter(|tx| tx.inputs.is_empty()).count();
        if cb > 1 { return Err(OrchestratorError::ValidationFailed { height: h, reason: "Multi coinbase".into() }); }
        if cb == 0 { return Err(OrchestratorError::ValidationFailed { height: h, reason: "No coinbase".into() }); }
        Ok(true)
    }

    fn analyze(&mut self, block: &Block, h: u64) { let n = block.transactions.len(); let s: u64 = block.transactions.iter().flat_map(|tx| tx.outputs.iter()).map(|o| o.amount).sum(); tracing::debug!("[ORCH] Block {}: {} txs, {} AEV", h, n, s as f64 / 100_000_000.0); }
    fn distribute(&mut self, block: &Block) { for tx in &block.transactions { if tx.inputs.is_empty() { for o in &tx.outputs { self.metrics.rewards_distributed += o.amount; } } } }

    pub fn resolve_fork(&mut self, val: &mut Validator, st: &mut Storage) -> Result<u64, OrchestratorError> {
        if let Some(last) = self.last_fork_resolved_at {
            if last.elapsed() < Duration::from_secs(30) {
                tracing::info!("[ORCH] Fork resolution skipped (cooldown 30s)");
                return Ok(0);
            }
        }

        let our_height = val.last_block_height();
        if our_height == 0 {
            tracing::info!("[ORCH] Nothing to save, height=0");
            self.last_fork_resolved_at = Some(Instant::now());
            return Ok(0);
        }

        self.wal.log(st, "resolve_fork_start", our_height, None)?;
        self.metrics.forks_detected += 1;

        let mut refund = 0u64;
        let mut saved = 0u64;

        for h in 1..=our_height {
            if let Ok(Some(block)) = st.load_genesis_block(h) {
                st.save_my_block(h, &block).map_err(|e| OrchestratorError::StorageFailed { operation: "save_my".into(), detail: format!("{:?}", e) })?;
                for tx in &block.transactions {
                    if tx.inputs.is_empty() { for o in &tx.outputs { refund += o.amount; } }
                }
                st.delete_genesis_block(h).map_err(|e| OrchestratorError::StorageFailed { operation: "del".into(), detail: format!("{:?}", e) })?;
                saved += 1;
            }
        }

        if let Ok(Some(genesis)) = st.load_genesis_block(0) {
            let mut tv = Validator::new(b"aevum_genesis_seed");
            let mut g = genesis;
            if tv.validate_and_apply(&mut g).is_ok() { val.load_utxo_set(tv.utxo_set().clone()); }
            val.set_last_block(g.block_hash, 0, g.poh_tick_end);
        }

        // JT-UTXO возврат
        if refund > 0 {
            let utxo = JtUtxo::new_global_clean(
                val.utxo_set().all().next().map(|(_, u)| u.owner().clone()).unwrap_or(aevum::crypto::keys::PublicKey::from_bytes([0u8; 32]).unwrap()),
                refund, &[1u8; 32], &[1u8; 32], our_height + 1, 0, Hash::zero());
            if let Ok(u) = utxo { val.utxo_set_mut().add(u); }
        }
        self.metrics.total_refunded += refund;
        self.metrics.switches_performed += 1;
        self.processed_height = 0;
        self.last_fork_resolved_at = Some(Instant::now());

        self.wal.log(st, "resolve_fork_done", 0, None)?;
        self.save_progress(st)?;

        tracing::info!("[ORCH] Fork resolved: saved={} blocks (1..{}), refund={} satoshi ({} AEV), height=0",
            saved, our_height, refund, refund as f64 / 100_000_000.0);
        Ok(saved)
    }
}
