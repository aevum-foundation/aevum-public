use crate::core::compute::{ComputeTask, SubTask, BlockSolution};
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use std::collections::{HashMap, HashSet, VecDeque};

const PPLNS_WINDOW: usize = 1_000_000;
const MIN_PAYOUT: u64 = 100;
const MAX_WORKERS: usize = 10_000;
const MAX_SHARES_PER_BLOCK: u64 = 100;
const MAX_POOL_FEE_BPS: u16 = 10_000;
const BLOCK_FINDER_BONUS_BPS: u16 = 200;
const MAX_SHARE_HISTORY: usize = 1_000_000;
const NONCE_WINDOW: u64 = 1000;

#[derive(Clone, Debug)]
struct ShareEntry {
    miner_key: [u8; 32],
    task_id: Hash,
    share_hash: Hash,
    height: u64,
}

#[derive(Clone, Debug)]
pub struct PoolWorker {
    pub shares_submitted: u64,
    pub reward_earned: u64,
    pub pending_balance: u64,
    pub last_share_height: u64,
    pub shares_this_block: u64,
    pub blocks_found: u64,
    pub blocks_submitted: u64,
    pub task_shares: HashMap<Hash, u64>,
}

pub struct ComputePool {
    pub pool_id: Hash,
    pub tasks: HashMap<Hash, ComputeTask>,
    pub workers: HashMap<[u8; 32], PoolWorker>,
    pub task_total_shares: HashMap<Hash, u64>,
    pub total_reward: u64,
    pub is_active: bool,
    pub created_at: u64,
    pub share_log: VecDeque<ShareEntry>,
    pub submitted_share_hashes: HashSet<Hash>,
    pub pool_fee_bps: u16,
    pub share_difficulty: u8,
    pub input_data_hashes: HashMap<Hash, Hash>,
}

impl ComputePool {
    pub fn new(pool_fee_bps: u16, share_difficulty: u8) -> Self {
        assert!(pool_fee_bps <= MAX_POOL_FEE_BPS);
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_POOL_V5");
        hasher.update(&pool_fee_bps.to_le_bytes());
        ComputePool {
            pool_id: Hash(hasher.finalize().into()),
            tasks: HashMap::new(),
            workers: HashMap::new(),
            task_total_shares: HashMap::new(),
            total_reward: 0,
            is_active: true,
            created_at: 0,
            share_log: VecDeque::with_capacity(PPLNS_WINDOW),
            submitted_share_hashes: HashSet::with_capacity(MAX_SHARE_HISTORY),
            pool_fee_bps,
            share_difficulty,
            input_data_hashes: HashMap::new(),
        }
    }

    pub fn add_task(&mut self, task: ComputeTask, created_at: u64) -> Result<(), &'static str> {
        let tid = task.task_id;
        if self.tasks.contains_key(&tid) { return Err("Task already in pool"); }
        let input_hash = {
            let mut h = blake3::Hasher::new();
            h.update(b"AEVUM_POOL_INPUT");
            h.update(&task.input_data);
            Hash(h.finalize().into())
        };
        self.input_data_hashes.insert(tid, input_hash);
        self.tasks.insert(tid, task);
        self.task_total_shares.insert(tid, 0);
        if self.created_at == 0 { self.created_at = created_at; }
        Ok(())
    }

    pub fn join(&mut self, miner: &PublicKey) -> Result<(), &'static str> {
        if !self.is_active { return Err("Pool is not active"); }
        if self.workers.len() >= MAX_WORKERS { return Err("Pool is full"); }
        let key = miner.to_bytes();
        if self.workers.contains_key(&key) { return Err("Already in pool"); }
        self.workers.insert(key, PoolWorker {
            shares_submitted: 0, reward_earned: 0, pending_balance: 0,
            last_share_height: 0, shares_this_block: 0,
            blocks_found: 0, blocks_submitted: 0,
            task_shares: HashMap::new(),
        });
        Ok(())
    }

    pub fn leave(&mut self, miner: &PublicKey) -> Result<u64, &'static str> {
        let key = miner.to_bytes();
        let worker = self.workers.remove(&key).ok_or("Not in pool")?;
        Ok(worker.pending_balance)
    }

    pub fn claim_pending(&mut self, miner: &PublicKey) -> Result<u64, &'static str> {
        let key = miner.to_bytes();
        let worker = self.workers.get_mut(&key).ok_or("Not in pool")?;
        let amount = worker.pending_balance;
        worker.pending_balance = 0;
        Ok(amount)
    }

    pub fn submit_share(
        &mut self,
        miner: &PublicKey,
        share: &SubTask,
        solution: &[u8],
        block_height: u64,
    ) -> Result<(), &'static str> {
        if !self.is_active { return Err("Pool is not active"); }
        let key = miner.to_bytes();
        let worker = self.workers.get_mut(&key).ok_or("Not in pool")?;

        if share.nonce < block_height.saturating_sub(NONCE_WINDOW) || share.nonce > block_height {
            return Err("Stale or future nonce");
        }

        if block_height == worker.last_share_height {
            if worker.shares_this_block >= MAX_SHARES_PER_BLOCK { return Err("Rate limit exceeded"); }
        } else {
            worker.shares_this_block = 0;
        }

        let task = self.tasks.get(&share.task_id).ok_or("Task not in pool")?;
        let input_hash = self.input_data_hashes.get(&share.task_id).ok_or("Input hash not found")?;

        if !Self::verify_share(input_hash, share, solution, self.share_difficulty) {
            return Err("Invalid share: PoW verification failed");
        }

        let share_hash = {
            let mut h = blake3::Hasher::new();
            h.update(b"AEVUM_SHARE_V4");
            h.update(task.task_id.as_bytes());
            h.update(&key);
            h.update(&share.range_start.to_le_bytes());
            h.update(&share.range_end.to_le_bytes());
            h.update(solution);
            h.update(&block_height.to_le_bytes());
            h.update(&share.nonce.to_le_bytes());
            Hash(h.finalize().into())
        };

        if self.submitted_share_hashes.contains(&share_hash) { return Err("Duplicate share"); }
        if self.submitted_share_hashes.len() >= MAX_SHARE_HISTORY { self.submitted_share_hashes.clear(); }
        self.submitted_share_hashes.insert(share_hash);

        worker.shares_submitted += 1;
        worker.last_share_height = block_height;
        worker.shares_this_block += 1;
        *worker.task_shares.entry(share.task_id).or_insert(0) += 1;
        *self.task_total_shares.entry(share.task_id).or_insert(0) += 1;

        if self.share_log.len() >= PPLNS_WINDOW { self.share_log.pop_front(); }
        self.share_log.push_back(ShareEntry { miner_key: key, task_id: share.task_id, share_hash, height: block_height });

        Ok(())
    }

    fn verify_share(input_hash: &Hash, share: &SubTask, solution: &[u8], difficulty: u8) -> bool {
        if solution.is_empty() { return false; }
        if difficulty == 0 { return true; }
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_SHARE_POW_V4");
        h.update(input_hash.as_bytes());
        h.update(&share.range_start.to_le_bytes());
        h.update(&share.range_end.to_le_bytes());
        h.update(&share.nonce.to_le_bytes());
        h.update(solution);
        Self::meets_difficulty(h.finalize().as_bytes(), difficulty)
    }

    fn meets_difficulty(hash: &[u8], difficulty: u8) -> bool {
        let full_bytes = (difficulty / 8) as usize;
        let rem_bits = difficulty % 8;
        if full_bytes > 0 && hash[..full_bytes].iter().any(|&b| b != 0) { return false; }
        if rem_bits > 0 {
            let mask = 0xFFu8 << (8 - rem_bits);
            if hash[full_bytes] & mask != 0 { return false; }
        }
        true
    }

    pub fn distribute_reward(&self, task_id: &Hash, reward: u64) -> HashMap<[u8; 32], u64> {
        let pool_fee = (reward as u128 * self.pool_fee_bps as u128 / 10_000u128) as u64;
        let reward_pool = reward.saturating_sub(pool_fee);
        if reward_pool == 0 { return HashMap::new(); }
        let total_shares = self.task_total_shares.get(task_id).copied().unwrap_or(0);
        if total_shares == 0 { return HashMap::new(); }
        let mut payouts = HashMap::new();
        for (key, worker) in &self.workers {
            let task_shares = worker.task_shares.get(task_id).copied().unwrap_or(0);
            if task_shares == 0 { continue; }
            let amount = (reward_pool as u128 * task_shares as u128 / total_shares as u128) as u64;
            if amount >= MIN_PAYOUT { payouts.insert(*key, amount); }
        }
        payouts
    }

    pub fn distribute_reward_pplns(&self, task_id: &Hash, reward: u64) -> HashMap<[u8; 32], u64> {
        let window: Vec<&ShareEntry> = self.share_log.iter().filter(|e| e.task_id == *task_id).rev().take(PPLNS_WINDOW).collect();
        if window.is_empty() { return HashMap::new(); }
        let mut miner_shares: HashMap<[u8; 32], u64> = HashMap::new();
        for entry in &window { *miner_shares.entry(entry.miner_key).or_insert(0) += 1; }
        let total_window = miner_shares.values().sum::<u64>();
        if total_window == 0 { return HashMap::new(); }
        let pool_fee = (reward as u128 * self.pool_fee_bps as u128 / 10_000u128) as u64;
        let reward_pool = reward.saturating_sub(pool_fee);
        let mut payouts = HashMap::new();
        for (key, shares) in &miner_shares {
            let amount = (reward_pool as u128 * *shares as u128 / total_window as u128) as u64;
            if amount >= MIN_PAYOUT { payouts.insert(*key, amount); }
        }
        payouts
    }

    pub fn finalize_task(&mut self, solution: &BlockSolution) -> Result<HashMap<[u8; 32], u64>, &'static str> {
        let task_id = solution.task.task_id;
        if !self.tasks.contains_key(&task_id) { return Err("Task not in pool"); }
        if !solution.verify() { return Err("Invalid solution"); }
        let reward = solution.task.reward;
        let mut payouts = self.distribute_reward(&task_id, reward);
        let finder_key = solution.miner_address;
        if self.workers.contains_key(&finder_key) {
            let bonus = (reward as u128 * BLOCK_FINDER_BONUS_BPS as u128 / 10_000u128) as u64;
            if bonus > 0 {
                if let Some(w) = self.workers.get_mut(&finder_key) {
                    w.reward_earned = w.reward_earned.saturating_add(bonus);
                    w.blocks_submitted += 1;
                }
                *payouts.entry(finder_key).or_insert(0) += bonus;
            }
        }
        self.tasks.remove(&task_id);
        self.task_total_shares.remove(&task_id);
        self.input_data_hashes.remove(&task_id);
        self.total_reward = self.total_reward.saturating_add(reward);
        Ok(payouts)
    }

    pub fn worker_count(&self) -> usize { self.workers.len() }
    pub fn task_count(&self) -> usize { self.tasks.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::compute::TaskType;
    use crate::crypto::keys::PrivateKey;

    fn dummy_task(id: u8) -> ComputeTask {
        ComputeTask {
            task_id: Hash([id; 32]), task_type: TaskType::DrugDiscovery,
            input_data: vec![1, 2, 3], reward: 1000, deadline: 0,
            verification_key: Hash::zero(), issuer: [0u8; 32],
            total_combinations: 1_000_000, chunk_size: 1000,
        }
    }

    fn dummy_subtask(task_id: Hash) -> SubTask {
        SubTask { task_id, range_start: 0, range_end: 1000, assigned_to: None, reward_share: 10, nonce: 100 }
    }

    fn random_key() -> PublicKey { PrivateKey::generate().public_key() }

    #[test]
    fn join_pool() {
        let mut pool = ComputePool::new(100, 1);
        assert!(pool.join(&random_key()).is_ok());
        assert_eq!(pool.worker_count(), 1);
    }

    #[test]
    fn add_task_works() {
        let mut pool = ComputePool::new(100, 1);
        assert!(pool.add_task(dummy_task(1), 0).is_ok());
        assert_eq!(pool.task_count(), 1);
    }

    #[test]
    fn submit_share_no_difficulty() {
        let mut pool = ComputePool::new(100, 0);
        let m = random_key();
        pool.join(&m).unwrap();
        pool.add_task(dummy_task(1), 0).unwrap();
        match pool.submit_share(&m, &dummy_subtask(Hash([1u8; 32])), &[0u8; 32], 100) {
            Ok(_) => {},
            Err(e) => panic!("submit_share failed: {}", e),
        }
    }

    #[test]
    fn distribute_reward_works() {
        let mut pool = ComputePool::new(100, 0);
        let m = random_key();
        pool.join(&m).unwrap();
        pool.add_task(dummy_task(1), 0).unwrap();
        pool.submit_share(&m, &dummy_subtask(Hash([1u8; 32])), &[0u8; 32], 100).unwrap();
        let payouts = pool.distribute_reward(&Hash([1u8; 32]), 500);
        assert!(!payouts.is_empty());
    }
}
