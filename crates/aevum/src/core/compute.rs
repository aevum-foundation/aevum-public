use crate::crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskType {
    DrugDiscovery,
    ClimateModeling,
    AiTraining,
    ZkProofGeneration,
    ImageGeneration,
    VideoGeneration,
    AudioProcessing,
    MolecularDocking,
    Custom(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeTask {
    pub task_id: Hash,
    pub task_type: TaskType,
    pub input_data: Vec<u8>,
    pub reward: u64,
    pub deadline: u64,
    pub verification_key: Hash,
    pub issuer: [u8; 32],
    pub total_combinations: u64,
    pub chunk_size: u64,
}

impl ComputeTask {
    pub fn new(
        task_type: TaskType, input_data: Vec<u8>, reward: u64, deadline: u64,
        verification_key: Hash, issuer: [u8; 32], total_combinations: u64,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_COMPUTE_TASK_V2");
        hasher.update(&input_data);
        hasher.update(&reward.to_le_bytes());
        hasher.update(&deadline.to_le_bytes());
        hasher.update(verification_key.as_bytes());
        hasher.update(&issuer);
        hasher.update(&total_combinations.to_le_bytes());
        ComputeTask {
            task_id: Hash(hasher.finalize().into()),
            task_type, input_data, reward, deadline, verification_key, issuer,
            total_combinations, chunk_size: total_combinations / 1000,
        }
    }

    pub fn get_chunk(&self, worker_index: u64, total_workers: u64) -> Option<(u64, u64)> {
        if total_workers == 0 || worker_index >= total_workers { return None; }
        let per_worker = self.total_combinations / total_workers;
        let start = worker_index * per_worker;
        let end = if worker_index == total_workers - 1 { self.total_combinations } else { start + per_worker };
        Some((start, end))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubTask {
    pub task_id: Hash,
    pub range_start: u64,
    pub range_end: u64,
    pub assigned_to: Option<[u8; 32]>,
    pub reward_share: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSolution {
    pub task: ComputeTask,
    pub solution: Vec<u8>,
    pub zk_proof: Vec<u8>,
    pub block_height: u64,
    pub miner_address: [u8; 32],
    pub worker_range: Option<(u64, u64)>,
    pub pool_id: Option<Hash>,
}

impl BlockSolution {
    pub fn new(task: ComputeTask, solution: Vec<u8>, block_height: u64, miner_address: [u8; 32]) -> Self {
        BlockSolution { task, solution, zk_proof: Vec::new(), block_height, miner_address, worker_range: None, pool_id: None }
    }

    pub fn verify(&self) -> bool {
        if self.solution.is_empty() { return false; }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_SOLUTION_V2");
        hasher.update(&self.solution);
        let hash = Hash(hasher.finalize().into());
        hash == self.task.verification_key
    }
}

pub struct ComputeEngine {
    pub active_tasks: Vec<ComputeTask>,
    pub sub_tasks: HashMap<Hash, SubTask>,
}

impl ComputeEngine {
    pub fn new() -> Self { ComputeEngine { active_tasks: Vec::new(), sub_tasks: HashMap::new() } }
    pub fn add_task(&mut self, task: ComputeTask) { self.active_tasks.push(task); }

    pub fn get_highest_reward_task(&self) -> Option<&ComputeTask> {
        self.active_tasks.iter().max_by_key(|t| t.reward)
    }

    pub fn try_solve_range(&self, task: &ComputeTask, start: u64, end: u64) -> Option<Vec<u8>> {
        for counter in start..end {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AEVUM_SOLUTION_V2");
            hasher.update(&counter.to_le_bytes());
            if Hash(hasher.finalize().into()) == task.verification_key {
                return Some(counter.to_le_bytes().to_vec());
            }
        }
        None
    }

    pub fn create_subtask(&mut self, task: &ComputeTask, worker_index: u64, total_workers: u64) -> Option<SubTask> {
        let (start, end) = task.get_chunk(worker_index, total_workers)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_SUBTASK");
        hasher.update(task.task_id.as_bytes());
        hasher.update(&start.to_le_bytes());
        hasher.update(&end.to_le_bytes());
        let subtask = SubTask {
            task_id: task.task_id,
            range_start: start, range_end: end, assigned_to: None,
            reward_share: task.reward / total_workers,
            nonce: 0,
        };
        self.sub_tasks.insert(Hash(hasher.finalize().into()), subtask.clone());
        Some(subtask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_task() -> ComputeTask {
        ComputeTask {
            total_combinations: 1_000_000, chunk_size: 1000,
            task_id: Hash::zero(), task_type: TaskType::DrugDiscovery,
            input_data: vec![1,2,3], reward: 1000, deadline: 0,
            verification_key: Hash::zero(), issuer: [0u8; 32],
        }
    }

    #[test]
    fn task_chunking() {
        let task = dummy_task();
        let (start, end) = task.get_chunk(0, 10).unwrap();
        assert_eq!(start, 0);
        assert_eq!(end, 100_000);
    }

    #[test]
    fn subtask_creation() {
        let mut engine = ComputeEngine::new();
        let task = dummy_task();
        let st = engine.create_subtask(&task, 0, 100).unwrap();
        assert_eq!(st.reward_share, 10);
        assert_eq!(st.range_start, 0);
    }

    #[test]
    fn try_solve_range() {
        let engine = ComputeEngine::new();
        let mut task = dummy_task();
        task.total_combinations = 100;
        // Ищем решение с counter=42
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_SOLUTION_V2");
        hasher.update(&42u64.to_le_bytes());
        task.verification_key = Hash(hasher.finalize().into());

        let result = engine.try_solve_range(&task, 0, 100);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 42u64.to_le_bytes().to_vec());
    }
}

impl ComputeTask {
    pub fn input_data_hash(&self) -> crate::crypto::hash::Hash {
        crate::crypto::hash::Hash(blake3::hash(&self.input_data).into())
    }
}
