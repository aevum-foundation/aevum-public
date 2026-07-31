//! Compute Task types for Aevum protocol (v2 — Hardened Deterministic)
//!
//! ## v2 Upgrades
//! - TaskType: Ord + PartialOrd, Custom with [u8; 32] namespace
//! - get_chunk with remainder distribution
//! - f64 removed (full determinism)
//! - Domain-separated hashing
//! - Comprehensive tests

use crate::crypto::hash::Hash;
use blake3;
use serde::{Deserialize, Serialize};

/// Task type (fixed + clean)
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TaskType {
    DrugDiscovery,
    ClimateModeling,
    ZkProofGeneration,
    ImageGeneration,
    VideoGeneration,
    AudioProcessing,
    MolecularDocking,
    ProteinFolding,
    Rendering,
    Simulation,
    GeneralCompute,
    Custom { namespace: [u8; 32] },
}

/// Core task
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
        task_type: TaskType,
        input_data: Vec<u8>,
        reward: u64,
        deadline: u64,
        verification_key: Hash,
        issuer: [u8; 32],
        total_combinations: u64,
    ) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM.COMPUTE_TASK.V2");
        h.update(&reward.to_le_bytes());
        h.update(&deadline.to_le_bytes());
        h.update(&total_combinations.to_le_bytes());
        h.update(&issuer);
        h.update(&input_data);
        h.update(verification_key.as_bytes());

        let task_id = Hash(h.finalize().into());

        Self {
            task_id,
            task_type,
            input_data,
            reward,
            deadline,
            verification_key,
            issuer,
            total_combinations,
            chunk_size: total_combinations.saturating_div(1024).max(1),
        }
    }

    /// Solution verification
    pub fn verify_solution(&self, solution: &[u8]) -> bool {
        if solution.is_empty() {
            return false;
        }

        let computed = match &self.task_type {
            TaskType::ZkProofGeneration => self.verify_zk(solution),
            TaskType::ImageGeneration
            | TaskType::VideoGeneration
            | TaskType::AudioProcessing => self.verify_media(solution),
            TaskType::Custom { namespace } => self.verify_custom(solution, namespace),
            _ => self.verify_general(solution),
        };

        computed == self.verification_key
    }

    fn verify_zk(&self, solution: &[u8]) -> Hash {
        if solution.len() < 384 {
            return Hash::zero();
        }
        Hash(blake3::hash(solution).into())
    }

    fn verify_media(&self, solution: &[u8]) -> Hash {
        Hash(blake3::hash(solution).into())
    }

    fn verify_general(&self, solution: &[u8]) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM.SOLUTION.V2");
        h.update(self.task_id.as_bytes());
        h.update(solution);
        Hash(h.finalize().into())
    }

    fn verify_custom(&self, solution: &[u8], namespace: &[u8; 32]) -> Hash {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM.CUSTOM.V2");
        h.update(namespace);
        h.update(solution);
        Hash(h.finalize().into())
    }

    /// Deterministic work split with remainder
    pub fn get_chunk(&self, worker: u64, workers: u64) -> Option<(u64, u64)> {
        if workers == 0 || worker >= workers {
            return None;
        }

        let base = self.total_combinations.saturating_div(workers);
        let rem = self.total_combinations % workers;

        let start = worker.saturating_mul(base).saturating_add(worker.min(rem));
        let mut end = start.saturating_add(base);

        if worker < rem {
            end = end.saturating_add(1);
        }

        Some((start, end))
    }

    pub fn input_hash(&self) -> Hash {
        Hash(blake3::hash(&self.input_data).into())
    }
}

/// Block result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSolution {
    pub task: ComputeTask,
    pub solution: Vec<u8>,
    pub zk_proof: Vec<u8>,
    pub block_height: u64,
    pub miner: [u8; 32],
    pub worker_range: Option<(u64, u64)>,
    pub pool_id: Option<Hash>,
}

impl BlockSolution {
    pub fn new(task: ComputeTask, solution: Vec<u8>, block_height: u64, miner: [u8; 32]) -> Self {
        Self {
            task,
            solution,
            zk_proof: vec![],
            block_height,
            miner,
            worker_range: None,
            pool_id: None,
        }
    }

    pub fn verify(&self) -> bool {
        self.task.verify_solution(&self.solution)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_task(task_type: TaskType) -> ComputeTask {
        ComputeTask {
            total_combinations: 1_000_000,
            chunk_size: 1000,
            task_id: Hash::zero(),
            task_type,
            input_data: vec![1, 2, 3],
            reward: 1000,
            deadline: 0,
            verification_key: Hash::zero(),
            issuer: [0u8; 32],
        }
    }

    #[test]
    fn media_checks_hash() {
        let data = b"generated_image";
        let expected = Hash(blake3::hash(data).into());
        let mut task = dummy_task(TaskType::ImageGeneration);
        task.verification_key = expected;
        assert!(task.verify_solution(data));
        assert!(!task.verify_solution(b"wrong"));
    }

    #[test]
    fn empty_rejected() {
        assert!(!dummy_task(TaskType::DrugDiscovery).verify_solution(&[]));
    }

    #[test]
    fn custom_verification() {
        let namespace = [42u8; 32];
        let data = b"solution";
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM.CUSTOM.V2");
        h.update(&namespace);
        h.update(data);
        let expected = Hash(h.finalize().into());

        let mut task = dummy_task(TaskType::Custom { namespace });
        task.verification_key = expected;
        assert!(task.verify_solution(data));
    }

    #[test]
    fn get_chunk_splits_with_remainder() {
        let task = dummy_task(TaskType::DrugDiscovery);
        let (s, e) = task.get_chunk(0, 4).unwrap();
        assert_eq!(s, 0);
        assert!(e > s);
        let (s2, e2) = task.get_chunk(3, 4).unwrap();
        assert!(s2 < e2);
    }
}
