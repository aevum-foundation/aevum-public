use crate::storage::Storage;
use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::jt_utxo::JtUtxo;
use aevum::crypto::hash::Hash;
use aevum::crypto::keys::PublicKey;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::SyncContext;
use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CHECKPOINT_INTERVAL: u64 = 1000;
const BASE_FORK_QUEUE_SIZE: usize = 16;
const MAX_CANDIDATES_PER_PEER: usize = 2;
const FORK_CANDIDATE_TTL: Duration = Duration::from_secs(300);
const TICKS_PER_BLOCK: u64 = 30;
const SAVE_PROGRESS_INTERVAL: u64 = 500;

#[derive(Debug)]
pub enum OrchestratorError {
    StorageFailed { operation: String, detail: String },
    ValidationFailed { height: u64, reason: String },
    ForkQueueFull,
    InvalidBlock { height: u64, expected_hash: String, got_hash: String },
    DuplicateSoloChain { peer_id: String, first_block_hash: String },
    InvalidPoh { height: u64, tick_start: u64, tick_end: u64 },
}
impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OrchestratorError::StorageFailed { operation, detail } => write!(f, "Storage {}: {}", operation, detail),
            OrchestratorError::ValidationFailed { height, reason } => write!(f, "Validation at {}: {}", height, reason),
            OrchestratorError::ForkQueueFull => write!(f, "Fork queue full"),
            OrchestratorError::InvalidBlock { height, expected_hash, got_hash } => write!(f, "Block {}: expected {} got {}", height, expected_hash, got_hash),
            OrchestratorError::DuplicateSoloChain { peer_id, first_block_hash } => write!(f, "Duplicate solo chain: peer={}, first_hash={}", peer_id, first_block_hash),
            OrchestratorError::InvalidPoh { height, tick_start, tick_end } => write!(f, "Invalid PoH at block {}: start={} end={}", height, tick_start, tick_end),
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

#[derive(Clone)]
struct ForkCandidate { peer_id: [u8; 20], blocks: Vec<(u64, Vec<u8>)>, total_height: u64, timestamp: Instant }

struct ForkQueue { queue: VecDeque<ForkCandidate>, peer_counts: HashMap<[u8; 20], usize> }
impl ForkQueue {
    fn new() -> Self { ForkQueue { queue: VecDeque::with_capacity(BASE_FORK_QUEUE_SIZE), peer_counts: HashMap::new() } }
    fn max_size(&self) -> usize { BASE_FORK_QUEUE_SIZE.max(self.peer_counts.len() * 2) }

    fn push(&mut self, c: ForkCandidate) -> Result<(), OrchestratorError> {
        let peer_cnt = self.peer_counts.get(&c.peer_id).copied().unwrap_or(0);
        if peer_cnt >= MAX_CANDIDATES_PER_PEER {
            let replace_idx: Option<usize> = self.queue.iter().enumerate()
                .filter(|(_, qc)| qc.peer_id == c.peer_id && qc.total_height < c.total_height)
                .min_by_key(|(_, qc)| qc.total_height)
                .map(|(i, _)| i);
            match replace_idx {
                Some(idx) => {
                    self.queue.remove(idx);
                    self.peer_counts.entry(c.peer_id).and_modify(|e| *e = e.saturating_sub(1));
                }
                None => return Err(OrchestratorError::ForkQueueFull),
            }
        }
        let max_sz = self.max_size();
        if self.queue.len() >= max_sz {
            let remove_idx: Option<usize> = self.queue.iter().enumerate()
                .filter(|(_, qc)| qc.total_height < c.total_height)
                .min_by_key(|(_, qc)| qc.total_height)
                .map(|(i, _)| i);
            match remove_idx {
                Some(idx) => {
                    let removed = self.queue.remove(idx).unwrap();
                    self.peer_counts.entry(removed.peer_id).and_modify(|e| *e = e.saturating_sub(1));
                }
                None => return Err(OrchestratorError::ForkQueueFull),
            }
        }
        self.peer_counts.entry(c.peer_id).and_modify(|e| *e += 1).or_insert(1);
        self.queue.push_back(c);
        Ok(())
    }

    fn pop_best(&mut self) -> Option<ForkCandidate> {
        let best_idx = self.queue.iter().enumerate().max_by_key(|(_, c)| c.total_height).map(|(i, _)| i);
        best_idx.map(|i| {
            let c = self.queue.remove(i).unwrap();
            self.peer_counts.entry(c.peer_id).and_modify(|e| *e = e.saturating_sub(1));
            c
        })
    }

    fn cleanup(&mut self) {
        self.queue.retain(|c| {
            if c.timestamp.elapsed() > FORK_CANDIDATE_TTL {
                self.peer_counts.entry(c.peer_id).and_modify(|e| *e = e.saturating_sub(1));
                false
            } else { true }
        });
    }
}

#[derive(Clone, Debug, Default)]
pub struct OrchestratorMetrics {
    pub blocks_analyzed: u64, pub rewards_distributed: u64, pub miners_synchronized: u64,
    pub forks_detected: u64, pub switches_performed: u64, pub total_refunded: u64, pub last_height_processed: u64,
    pub solo_blocks_accepted: u64, pub solo_rewards_distributed: u64,
}

pub struct ChainOrchestrator {
    wal: WriteAheadLog, fork_queue: ForkQueue,
    pub processed_height: u64, pub metrics: OrchestratorMetrics,
    last_fork_resolved_at: Option<Instant>,
    in_fork_resolution: Arc<AtomicBool>,
    accepted_solo_chains: HashSet<(String, String)>,
    last_save_progress_height: u64,
}

impl ChainOrchestrator {
    pub fn new() -> Self {
        ChainOrchestrator {
            wal: WriteAheadLog::new(), fork_queue: ForkQueue::new(),
            processed_height: 0, metrics: OrchestratorMetrics::default(),
            last_fork_resolved_at: None, in_fork_resolution: Arc::new(AtomicBool::new(false)),
            accepted_solo_chains: HashSet::new(), last_save_progress_height: 0,
        }
    }
    pub fn recover(st: &Storage) -> Self {
        let wal = WriteAheadLog::recover(st);
        let processed = st.load_metadata("orch_processed_height").ok().flatten().and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(0);
        let solo_chains: HashSet<(String, String)> = st.load_metadata("orch_solo_chains").ok().flatten()
            .and_then(|d| bincode::deserialize(&d).ok()).unwrap_or_default();
        let was_in_fork = st.load_metadata("orch_in_fork").ok().flatten()
            .and_then(|d| bincode::deserialize::<bool>(&d).ok()).unwrap_or(false);
        if was_in_fork { tracing::warn!("[ORCH] Detected incomplete fork from previous run. Clearing flag."); }
        ChainOrchestrator {
            wal: wal.unwrap_or_else(WriteAheadLog::new), fork_queue: ForkQueue::new(),
            processed_height: processed, metrics: OrchestratorMetrics::default(),
            last_fork_resolved_at: None, in_fork_resolution: Arc::new(AtomicBool::new(false)),
            accepted_solo_chains: solo_chains, last_save_progress_height: 0,
        }
    }

    fn save_progress(&mut self, st: &mut Storage) -> Result<(), OrchestratorError> {
        if self.processed_height.saturating_sub(self.last_save_progress_height) < SAVE_PROGRESS_INTERVAL
            && self.processed_height > 0 && self.last_save_progress_height > 0 { return Ok(()); }
        self.last_save_progress_height = self.processed_height;
        st.save_metadata("orch_processed_height", &bincode::serialize(&self.processed_height).unwrap_or_default()).map_err(|e| OrchestratorError::StorageFailed { operation: "save_progress".into(), detail: format!("{:?}", e) })?;
        st.save_metadata("orch_solo_chains", &bincode::serialize(&self.accepted_solo_chains).unwrap_or_default()).map_err(|e| OrchestratorError::StorageFailed { operation: "save_solo_chains".into(), detail: format!("{:?}", e) })?;
        st.save_metadata("orch_in_fork", &bincode::serialize(&self.in_fork_resolution.load(Ordering::SeqCst)).unwrap_or_default()).map_err(|e| OrchestratorError::StorageFailed { operation: "save_fork_flag".into(), detail: format!("{:?}", e) })?;
        Ok(())
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
        if block.poh_tick_end <= block.poh_tick_start { return Err(OrchestratorError::InvalidPoh { height: h, tick_start: block.poh_tick_start, tick_end: block.poh_tick_end }); }
        if block.transactions.is_empty() { return Err(OrchestratorError::ValidationFailed { height: h, reason: "Empty".into() }); }
        let cb = block.transactions.iter().filter(|tx| tx.inputs.is_empty()).count();
        if cb > 1 { return Err(OrchestratorError::ValidationFailed { height: h, reason: "Multi coinbase".into() }); }
        if cb == 0 { return Err(OrchestratorError::ValidationFailed { height: h, reason: "No coinbase".into() }); }
        Ok(true)
    }

    /// Облегчённая проверка для соло-блоков — без проверки prev_hash
    fn verify_block_solo(&self, block: &Block, h: u64) -> Result<bool, OrchestratorError> {
        if block.compute_hash() != block.block_hash { return Err(OrchestratorError::InvalidBlock { height: h, expected_hash: block.compute_hash().to_hex(), got_hash: block.block_hash.to_hex() }); }
        if block.poh_tick_end <= block.poh_tick_start { return Err(OrchestratorError::InvalidPoh { height: h, tick_start: block.poh_tick_start, tick_end: block.poh_tick_end }); }
        if block.transactions.is_empty() { return Err(OrchestratorError::ValidationFailed { height: h, reason: "Empty".into() }); }
        let cb = block.transactions.iter().filter(|tx| tx.inputs.is_empty()).count();
        if cb > 1 { return Err(OrchestratorError::ValidationFailed { height: h, reason: "Multi coinbase".into() }); }
        if cb == 0 { return Err(OrchestratorError::ValidationFailed { height: h, reason: "No coinbase".into() }); }
        Ok(true)
    }

    fn analyze(&mut self, block: &Block, h: u64) { let n = block.transactions.len(); let s: u64 = block.transactions.iter().flat_map(|tx| tx.outputs.iter()).map(|o| o.amount).sum(); tracing::debug!("[ORCH] Block {}: {} txs, {} AEV", h, n, s as f64 / 100_000_000.0); }
    fn distribute(&mut self, block: &Block) { for tx in &block.transactions { if tx.inputs.is_empty() { for o in &tx.outputs { self.metrics.rewards_distributed += o.amount; } } } }

    pub fn resolve_fork(&mut self, val: &mut Validator, st: &mut Storage) -> Result<u64, OrchestratorError> {
        if self.in_fork_resolution.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            tracing::warn!("[ORCH] Fork resolution already in progress, skipping");
            return Ok(0);
        }
        if let Some(last) = self.last_fork_resolved_at {
            if last.elapsed() < Duration::from_secs(30) {
                tracing::info!("[ORCH] Fork resolution skipped (cooldown 30s)");
                self.in_fork_resolution.store(false, Ordering::SeqCst);
                return Ok(0);
            }
        }
        let our_height = val.last_block_height();
        if our_height == 0 {
            tracing::info!("[ORCH] Nothing to save, height=0");
            self.last_fork_resolved_at = Some(Instant::now());
            self.in_fork_resolution.store(false, Ordering::SeqCst);
            return Ok(0);
        }

        self.wal.log(st, "resolve_fork_start", our_height, None)?;
        self.metrics.forks_detected += 1;
        st.save_metadata("orch_in_fork", &bincode::serialize(&true).unwrap_or_default()).map_err(|e| OrchestratorError::StorageFailed { operation: "save_fork_flag".into(), detail: format!("{:?}", e) })?;

        let result = (|| -> Result<u64, OrchestratorError> {
            let mut refund = 0u64;
            let mut saved = 0u64;
            for h in 1..=our_height {
                if let Ok(Some(block)) = st.load_genesis_block(h) {
                    if let Ok(Some(main_block)) = st.load_my_block(h) {
                        if main_block.block_hash == block.block_hash { continue; }
                    }
                    st.save_my_block(h, &block).map_err(|e| OrchestratorError::StorageFailed { operation: "save_my".into(), detail: format!("{:?}", e) })?;
                    for tx in &block.transactions { if tx.inputs.is_empty() { for o in &tx.outputs { refund += o.amount; } } }
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
            if refund > 0 {
                let owner = val.utxo_set().all().next().map(|(_, u)| u.owner().clone()).unwrap_or(aevum::crypto::keys::PublicKey::from_bytes([0u8; 32]).unwrap());
                let utxo = JtUtxo::new_global_clean(owner, refund, &[1u8; 32], &[1u8; 32], our_height + 1, 0, Hash::zero());
                if let Ok(u) = utxo { val.utxo_set_mut().add(u); }
            }
            self.metrics.total_refunded += refund;
            self.metrics.switches_performed += 1;
            self.processed_height = 0;
            self.last_save_progress_height = 0;
            Ok(saved)
        })();

        match &result {
            Ok(saved) => {
                self.last_fork_resolved_at = Some(Instant::now());
                self.wal.log(st, "resolve_fork_done", 0, None)?;
                self.save_progress(st)?;
                tracing::info!("[ORCH] Fork resolved: saved={} blocks (1..{}), height=0", saved, our_height);
            }
            Err(e) => {
                self.wal.log(st, "resolve_fork_failed", our_height, None)?;
                tracing::error!("[ORCH] Fork resolution failed: {}", e);
            }
        }
        self.in_fork_resolution.store(false, Ordering::SeqCst);
        st.save_metadata("orch_in_fork", &bincode::serialize(&false).unwrap_or_default()).ok();
        result
    }

    // ========================================================================
    // ИСПРАВЛЕННАЯ accept_solo_chain
    // ========================================================================
    pub fn accept_solo_chain(&mut self, peer_id: &[u8; 20], blocks: &[Block], val: &mut Validator, st: &mut Storage) -> Result<(u64, u64, f64), OrchestratorError> {
        if blocks.is_empty() { return Err(OrchestratorError::ValidationFailed { height: 0, reason: "Empty solo chain".into() }); }
        let first_hash = blocks[0].block_hash.0;
        let chain_key = (hex::encode(peer_id), hex::encode(&first_hash));
        if self.accepted_solo_chains.contains(&chain_key) {
            return Err(OrchestratorError::DuplicateSoloChain { peer_id: hex::encode(peer_id), first_block_hash: hex::encode(&first_hash) });
        }

        let our_height = val.last_block_height();
        let mut total_poh_ticks: u64 = 0;
        let mut coinbase_amount: u64 = 0;
        let mut miner_key: Option<PublicKey> = None;
        let mut unique_blocks: u64 = 0;
        let mut max_height: u64 = our_height;

        for block in blocks {
            let h = block.height;
            // 🔥 ПРОПУСКАЕМ блоки не выше нашей высоты
            if h <= our_height { continue; }
            // 🔥 ИСПОЛЬЗУЕМ облегчённую проверку БЕЗ prev_hash
            if !self.verify_block_solo(block, h)? { continue; }
            // Пропускаем дубликаты
            if let Ok(Some(existing)) = st.load_my_block(h) { if existing.block_hash == block.block_hash { continue; } }
            let block_ticks = block.poh_tick_end.saturating_sub(block.poh_tick_start);
            total_poh_ticks = total_poh_ticks.saturating_add(block_ticks);
            unique_blocks += 1;
            if h > max_height { max_height = h; }
            for tx in &block.transactions {
                if tx.inputs.is_empty() {
                    for o in &tx.outputs {
                        coinbase_amount = coinbase_amount.saturating_add(o.amount);
                        if miner_key.is_none() { miner_key = Some(o.owner.clone()); }
                    }
                }
            }
        }

        if unique_blocks == 0 { return Err(OrchestratorError::ValidationFailed { height: 0, reason: "All blocks below our height or duplicate".into() }); }
        let miner = miner_key.ok_or(OrchestratorError::ValidationFailed { height: 0, reason: "No miner found".into() })?;

        let normative_ticks = unique_blocks.saturating_mul(TICKS_PER_BLOCK);
        let fairness_coefficient: f64 = if total_poh_ticks > 0 { (normative_ticks as f64 / total_poh_ticks as f64).min(1.0) } else { 1.0 };
        let standard_reward_per_block: u64 = 50_0000_0000;
        let standard_total = unique_blocks.saturating_mul(standard_reward_per_block);
        let fair_reward = (standard_total as f64 * fairness_coefficient) as u64;

        // Сохраняем только новые блоки
        for block in blocks {
            if block.height > our_height {
                st.save_my_block(block.height, block).map_err(|e| OrchestratorError::StorageFailed { operation: "save_solo".into(), detail: format!("{:?}", e) })?;
            }
        }

        // Начисляем награду
        if fair_reward > 0 {
            let utxo = JtUtxo::new_global_clean(miner, fair_reward, &[1u8; 32], &[1u8; 32], max_height, 0, Hash::zero())
                .map_err(|_| OrchestratorError::ValidationFailed { height: 0, reason: "Failed to create reward UTXO".into() })?;
            val.utxo_set_mut().add(utxo);
        }

        // 🔥 КРИТИЧЕСКИЙ ФИКС: обновляем высоту валидатора
        if max_height > our_height {
            if let Some(last_block) = blocks.iter().find(|b| b.height == max_height) {
                val.set_last_block(last_block.block_hash, max_height, last_block.poh_tick_end);
                tracing::info!("[ORCH] Validator height updated: {} -> {}", our_height, max_height);
            }
        }

        self.accepted_solo_chains.insert(chain_key);
        self.metrics.solo_blocks_accepted = self.metrics.solo_blocks_accepted.saturating_add(unique_blocks);
        self.metrics.solo_rewards_distributed = self.metrics.solo_rewards_distributed.saturating_add(fair_reward);
        self.metrics.miners_synchronized = self.metrics.miners_synchronized.saturating_add(1);
        self.wal.log(st, "accept_solo_chain", max_height, None)?;
        self.save_progress(st)?;

        tracing::info!("[ORCH] Solo chain accepted: peer={}, blocks={}, unique={}, poh_ticks={}, normative={}, coeff={:.4}, reward={} ({} AEV), height: {} -> {}",
            hex::encode(peer_id), blocks.len(), unique_blocks, total_poh_ticks, normative_ticks, fairness_coefficient, fair_reward, fair_reward as f64 / 100_000_000.0, our_height, max_height);
        Ok((unique_blocks, fair_reward, fairness_coefficient))
    }
}
