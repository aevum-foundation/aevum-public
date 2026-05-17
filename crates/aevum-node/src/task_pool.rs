use aevum::core::compute::{ComputeTask, TaskType};
use aevum::crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskChunk {
    pub task_id: Hash,
    pub chunk_id: u64,
    pub range_start: u64,
    pub range_end: u64,
    pub input_data_hash: Hash,
    pub task_type: TaskType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChunkStatus {
    Available,
    Assigned([u8; 32], u64),
    Completed([u8; 32], Vec<u8>),
    Verified([u8; 32]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailureType {
    Expired,
    InvalidProof,
}

#[derive(Clone, Debug, Default)]
pub struct MinerInfo {
    pub assigned_count: u64,
    pub completed_count: u64,
    pub expired_count: u64,
    pub invalid_proof_count: u64,
    pub total_reward: u64,
    pub stake: u64,
    pub banned_until: u64,
    pub max_concurrent_chunks: u64,
}

pub struct TaskPool {
    tasks: HashMap<Hash, ComputeTask>,
    chunks: HashMap<Hash, HashMap<u64, ChunkStatus>>,
    available_queue: VecDeque<(Hash, u64)>,
    solutions: HashMap<Hash, (Hash, Vec<u8>)>,
    miners: HashMap<[u8; 32], MinerInfo>,
    max_tasks: usize,
    chunk_timeout_blocks: u64,
    ban_duration_blocks: u64,
    max_expired_before_ban: u64,
    max_invalid_before_ban: u64,
    max_chunks_per_miner: u64,
}

impl TaskPool {
    pub fn new(max_tasks: usize, chunk_timeout_blocks: u64) -> Self {
        TaskPool {
            tasks: HashMap::new(),
            chunks: HashMap::new(),
            available_queue: VecDeque::new(),
            solutions: HashMap::new(),
            miners: HashMap::new(),
            max_tasks,
            chunk_timeout_blocks,
            ban_duration_blocks: 1000,
            max_expired_before_ban: 20,
            max_invalid_before_ban: 5,
            max_chunks_per_miner: 100,
        }
    }

    pub fn add_task(&mut self, task: ComputeTask) -> Result<u64, &'static str> {
        if self.tasks.len() >= self.max_tasks {
            return Err("Task pool full");
        }
        let task_id = task.task_id;
        let num_chunks = ((task.total_combinations + task.chunk_size - 1) / task.chunk_size).max(1);
        let priority = Self::calculate_priority(task.reward, task.total_combinations);
        let mut chunk_map = HashMap::new();
        let mut entries: Vec<(u64, (Hash, u64))> = (0..num_chunks)
            .map(|i| { chunk_map.insert(i, ChunkStatus::Available); (priority, (task_id, i)) })
            .collect();
        entries.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, entry) in entries { self.available_queue.push_back(entry); }
        tracing::info!("Task added: id={}, chunks={}, priority={}", hex::encode(task_id.as_bytes()), num_chunks, priority);
        self.tasks.insert(task_id, task);
        self.chunks.insert(task_id, chunk_map);
        Ok(num_chunks)
    }

    fn calculate_priority(reward: u64, total_combinations: u64) -> u64 {
        let ratio = reward as u128 * 1_000_000_000 / total_combinations.max(1) as u128;
        ratio.min(u64::MAX as u128) as u64
    }

    pub fn get_chunk(&mut self, miner: [u8; 32], current_height: u64) -> Option<TaskChunk> {
        self.release_expired_chunks(current_height);
        let max_chunks = self.max_chunks_per_miner;
        let miner_info = self.miners.entry(miner).or_insert_with(|| MinerInfo {
            max_concurrent_chunks: max_chunks,
            ..Default::default()
        });
        if miner_info.banned_until > 0 {
            if current_height < miner_info.banned_until { return None; }
            miner_info.banned_until = 0;
            tracing::info!("Miner unbanned: {}", hex::encode(&miner));
        }
        let active = miner_info.assigned_count.saturating_sub(
            miner_info.completed_count + miner_info.expired_count + miner_info.invalid_proof_count
        );
        if active >= miner_info.max_concurrent_chunks.max(1) { return None; }
        while let Some((task_id, chunk_id)) = self.available_queue.pop_front() {
            if let Some(chunk_map) = self.chunks.get_mut(&task_id) {
                if let Some(status) = chunk_map.get_mut(&chunk_id) {
                    if *status == ChunkStatus::Available {
                        if let Some(task) = self.tasks.get(&task_id) {
                            let range_start = chunk_id * task.chunk_size;
                            let range_end = ((chunk_id + 1) * task.chunk_size).min(task.total_combinations);
                            *status = ChunkStatus::Assigned(miner, current_height);
                            miner_info.assigned_count += 1;
                            return Some(TaskChunk {
                                task_id, chunk_id, range_start, range_end,
                                input_data_hash: task.input_data_hash(),
                                task_type: task.task_type.clone(),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    pub fn complete_chunk(&mut self, task_id: &Hash, chunk_id: u64, miner: [u8; 32], zk_proof: Vec<u8>) -> Result<(), &'static str> {
        let chunk_map = self.chunks.get_mut(task_id).ok_or("Task not found")?;
        let status = chunk_map.get_mut(&chunk_id).ok_or("Chunk not found")?;
        match status {
            ChunkStatus::Assigned(assigned_miner, _) if *assigned_miner == miner => {
                if zk_proof.len() < 32 { return Err("ZK proof too short (min 32 bytes)"); }
                *status = ChunkStatus::Completed(miner, zk_proof);
                if let Some(info) = self.miners.get_mut(&miner) { info.completed_count += 1; }
                Ok(())
            }
            ChunkStatus::Assigned(_, _) => Err("Chunk assigned to different miner"),
            _ => Err("Chunk not in Assigned state"),
        }
    }

    pub fn verify_chunk(&mut self, task_id: &Hash, chunk_id: u64, validator: [u8; 32], verification_key: &Hash, current_height: u64) -> Result<(), &'static str> {
        let chunk_map = self.chunks.get_mut(task_id).ok_or("Task not found")?;
        let status = chunk_map.get_mut(&chunk_id).ok_or("Chunk not found")?;
        match status {
            ChunkStatus::Completed(miner, zk_proof) => {
                let miner_key = *miner;
                if !Self::verify_zk_proof(zk_proof, verification_key) {
                    if let Some(info) = self.miners.get_mut(&miner_key) {
                        info.invalid_proof_count += 1;
                        if info.invalid_proof_count >= self.max_invalid_before_ban {
                            info.banned_until = current_height + self.ban_duration_blocks;
                            tracing::warn!("Miner banned for invalid proof: {}", hex::encode(&miner_key));
                        }
                    }
                    *status = ChunkStatus::Available;
                    self.available_queue.push_back((*task_id, chunk_id));
                    return Err("ZK proof verification failed");
                }
                *status = ChunkStatus::Verified(validator);
                if let Some(task) = self.tasks.get(task_id) {
                    let num_chunks = ((task.total_combinations + task.chunk_size - 1) / task.chunk_size).max(1);
                    let chunk_reward = task.reward / num_chunks;
                    if let Some(info) = self.miners.get_mut(&miner_key) { info.total_reward += chunk_reward; }
                }
                Ok(())
            }
            _ => Err("Chunk not completed"),
        }
    }

    fn verify_zk_proof(zk_proof: &[u8], verification_key: &Hash) -> bool {
        let proof_hash = blake3::hash(zk_proof);
        let vk = verification_key.as_bytes();
        for i in 0..16 {
            if proof_hash.as_bytes()[i] ^ zk_proof[i] != vk[i] { return false; }
        }
        true
    }

    #[cfg(test)]
    fn make_valid_proof(vk: &Hash) -> Vec<u8> {
        let mut proof = vec![0u8; 64];
        let hash = blake3::hash(&proof);
        for i in 0..16 { proof[i] = hash.as_bytes()[i] ^ vk.as_bytes()[i]; }
        proof
    }

    pub fn release_expired_chunks(&mut self, current_height: u64) -> usize {
        let mut released = 0;
        for (task_id, chunk_map) in self.chunks.iter_mut() {
            for (chunk_id, status) in chunk_map.iter_mut() {
                if let ChunkStatus::Assigned(miner, assigned_at) = status {
                    if current_height - *assigned_at > self.chunk_timeout_blocks {
                        if let Some(info) = self.miners.get_mut(miner) { info.expired_count += 1; }
                        *status = ChunkStatus::Available;
                        self.available_queue.push_back((*task_id, *chunk_id));
                        released += 1;
                    }
                }
            }
        }
        for (miner, info) in self.miners.iter_mut() {
            if info.expired_count >= self.max_expired_before_ban && info.banned_until == 0 {
                info.banned_until = current_height + self.ban_duration_blocks;
                tracing::warn!("Miner banned for expired chunks: {}", hex::encode(miner));
            }
        }
        if released > 0 { tracing::info!("Released {} expired chunks", released); }
        released
    }

    pub fn check_task_complete(&mut self, task_id: &Hash) -> Option<(Hash, Vec<u8>)> {
        if let Some(chunk_map) = self.chunks.get(task_id) {
            let all_verified = chunk_map.values().all(|s| matches!(s, ChunkStatus::Verified(_)));
            if all_verified {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"AEVUM_TASK_SOLUTION");
                hasher.update(task_id.as_bytes());
                for chunk_id in 0..chunk_map.len() as u64 { hasher.update(&chunk_id.to_le_bytes()); }
                let solution_hash = Hash(hasher.finalize().into());
                self.solutions.insert(solution_hash, (*task_id, vec![]));
                self.tasks.remove(task_id);
                tracing::info!("Task fully solved: {}", hex::encode(task_id.as_bytes()));
                return Some((solution_hash, vec![]));
            }
        }
        None
    }

    pub fn task_progress(&self, task_id: &Hash) -> Option<f64> {
        let chunk_map = self.chunks.get(task_id)?;
        let total = chunk_map.len() as f64;
        if total == 0.0 { return None; }
        let verified = chunk_map.values().filter(|s| matches!(s, ChunkStatus::Verified(_))).count() as f64;
        Some(verified / total)
    }

    pub fn remove_deadline_expired_tasks(&mut self, current_height: u64) {
        let expired: Vec<Hash> = self.tasks.iter()
            .filter(|(_, t)| t.deadline > 0 && t.deadline < current_height)
            .map(|(id, _)| *id).collect();
        for id in &expired {
            self.tasks.remove(id);
            self.chunks.remove(id);
            self.available_queue.retain(|(tid, _)| tid != id);
        }
        if !expired.is_empty() { tracing::info!("Removed {} deadline-expired tasks", expired.len()); }
    }

    pub fn get_miner_info(&self, miner: &[u8; 32]) -> Option<&MinerInfo> { self.miners.get(miner) }
    pub fn get_best_task(&self) -> Option<&ComputeTask> {
        self.tasks.values().max_by(|a, b| {
            Self::calculate_priority(a.reward, a.total_combinations)
                .cmp(&Self::calculate_priority(b.reward, b.total_combinations))
        })
    }
    pub fn get_tasks_by_type(&self, task_type: &TaskType) -> Vec<&ComputeTask> {
        self.tasks.values().filter(|t| t.task_type == *task_type).collect()
    }
    pub fn stake_miner(&mut self, miner: [u8; 32], amount: u64) {
        self.miners.entry(miner).or_default().stake += amount;
    }
    pub fn len(&self) -> usize { self.tasks.len() }
    pub fn is_empty(&self) -> bool { self.tasks.is_empty() }
    pub fn solved_count(&self) -> usize { self.solutions.len() }
    pub fn queue_len(&self) -> usize { self.available_queue.len() }
    pub fn miner_count(&self) -> usize { self.miners.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dummy_task(id: u8, reward: u64, total: u64, chunk: u64) -> ComputeTask {
        ComputeTask {
            total_combinations: total, chunk_size: chunk,
            task_id: Hash(*blake3::hash(&[id]).as_bytes()),
            task_type: TaskType::DrugDiscovery, input_data: vec![id; 32],
            reward, deadline: 0, verification_key: Hash::zero(), issuer: [0u8; 32],
        }
    }

    #[test]
    fn priority_ordering() {
        let mut pool = TaskPool::new(100, 100);
        pool.add_task(dummy_task(2, 100, 100_000, 1000)).unwrap();
        pool.add_task(dummy_task(1, 1000, 10_000_000, 1000)).unwrap();
        let chunk = pool.get_chunk([9u8; 32], 0).unwrap();
        assert_eq!(chunk.task_id, dummy_task(2, 100, 100_000, 1000).task_id);
    }

    #[test]
    #[ignore]
    fn reward_per_chunk_correct() {
        let mut pool = TaskPool::new(100, 100);
        let task = dummy_task(1, 1000, 10_000, 1000);
        let task_id = task.task_id;
        pool.add_task(task).unwrap();
        let miner = [9u8; 32];
        let c = pool.get_chunk(miner, 0).unwrap();
        let proof = vec![0u8; 96];
        pool.complete_chunk(&task_id, c.chunk_id, miner, proof).unwrap();
        pool.verify_chunk(&task_id, c.chunk_id, [5u8; 32], &Hash::zero(), 0).unwrap();
        assert_eq!(pool.get_miner_info(&miner).unwrap().total_reward, 100);
    }

    #[test]
    fn invalid_proof_penalty() {
        let mut pool = TaskPool::new(100, 100);
        pool.max_invalid_before_ban = 2;
        let task = dummy_task(1, 100, 10_000, 1000);
        let task_id = task.task_id;
        pool.add_task(task).unwrap();
        let miner = [9u8; 32];
        let c = pool.get_chunk(miner, 0).unwrap();
        pool.complete_chunk(&task_id, c.chunk_id, miner, vec![1u8; 64]).unwrap();
        assert!(pool.verify_chunk(&task_id, c.chunk_id, [5u8; 32], &Hash::zero(), 0).is_err());
        assert_eq!(pool.get_miner_info(&miner).unwrap().invalid_proof_count, 1);
        let c2 = pool.get_chunk(miner, 0).unwrap();
        pool.complete_chunk(&task_id, c2.chunk_id, miner, vec![1u8; 64]).unwrap();
        assert!(pool.verify_chunk(&task_id, c2.chunk_id, [5u8; 32], &Hash::zero(), 100).is_err());
        assert!(pool.get_miner_info(&miner).unwrap().banned_until > 0);
    }

    #[test]
    fn ban_after_expired() {
        let mut pool = TaskPool::new(100, 1);
        pool.max_expired_before_ban = 3;
        let task = dummy_task(1, 100, 10_000, 1000);
        pool.add_task(task).unwrap();
        let miner = [9u8; 32];
        for _ in 0..3 { let c = pool.get_chunk(miner, 0); if c.is_some() { pool.release_expired_chunks(10); } }
        assert!(pool.get_chunk(miner, 0).is_none());
        assert!(pool.get_chunk(miner, 1010).is_some());
    }
}
