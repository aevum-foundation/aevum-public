use crate::core::block::Block;
use crate::core::compute::BlockSolution;
use crate::core::transaction::Transaction;
use crate::crypto::hash::Hash;
use crate::crypto::zk::{ZkProof, ZkProofType};

pub struct Verifier;

impl Verifier {
    pub fn verify_useful_solution(solution: &BlockSolution) -> bool {
        if !solution.verify() {
            return false;
        }
        if solution.task.deadline > 0 && solution.block_height > solution.task.deadline {
            return false;
        }
        true
    }

    pub fn verify_transaction_zk(_tx: &Transaction) -> bool {
        true
    }

    pub fn verify_jurisdiction_tag(proof: &ZkProof) -> bool {
        proof.verify() && proof.proof_type == ZkProofType::JurisdictionTag
    }

    pub fn verify_transaction_balance(proof: &ZkProof) -> bool {
        proof.verify() && proof.proof_type == ZkProofType::TransactionBalance
    }

    pub fn verify_useful_solution_zk(proof: &ZkProof) -> bool {
        proof.verify() && proof.proof_type == ZkProofType::UsefulSolution
    }

    pub fn verify_block_full(block: &Block) -> Result<(), &'static str> {
        if let Some(ref solution) = block.useful_solution {
            if !Self::verify_useful_solution(solution) {
                return Err("Invalid useful solution");
            }
        }
        for tx in &block.transactions {
            if !Self::verify_transaction_zk(tx) {
                return Err("Invalid transaction zk proof");
            }
        }
        Ok(())
    }

    pub fn score_solution(solution: &BlockSolution) -> f64 {
        if solution.verify() {
            solution.task.reward as f64 / (solution.block_height as f64 + 1.0)
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::compute::{ComputeTask, TaskType};

    fn dummy_task() -> ComputeTask {
        ComputeTask {
            total_combinations: 1_000_000, chunk_size: 1000,
            task_id: Hash::zero(),
            task_type: TaskType::DrugDiscovery,
            input_data: vec![1, 2, 3],
            reward: 100,
            deadline: 0,
            verification_key: Hash::zero(),
            issuer: [0u8; 32],
        }
    }

    fn valid_key_for_solution(solution: &[u8]) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_SOLUTION_V2"); hasher.update(solution);
        Hash(hasher.finalize().into())
    }

    #[test]
    fn verify_valid_solution() {
        let sol_data = vec![0u8; 8];
        let key = valid_key_for_solution(&sol_data);
        let mut task = dummy_task();
        task.verification_key = key;
        let solution = BlockSolution::new(task, sol_data, 100, [0u8; 32]);
        assert!(Verifier::verify_useful_solution(&solution));
    }

    #[test]
    fn verify_expired_solution() {
        let sol_data = vec![0u8; 8];
        let key = valid_key_for_solution(&sol_data);
        let mut task = dummy_task();
        task.verification_key = key;
        task.deadline = 50;
        let solution = BlockSolution::new(task, sol_data, 100, [0u8; 32]);
        assert!(!Verifier::verify_useful_solution(&solution));
    }

    #[test]
    fn verify_zk_proof() {
        let proof =
            crate::crypto::zk::ZkProver::prove_jurisdiction_tag(Hash([1u8; 32]), Hash([2u8; 32]));
        assert!(Verifier::verify_jurisdiction_tag(&proof));
    }

    #[test]
    fn score_solution() {
        let sol_data = vec![0u8; 8];
        let key = valid_key_for_solution(&sol_data);
        let mut task = dummy_task();
        task.reward = 500;
        task.verification_key = key;
        let solution = BlockSolution::new(task, sol_data, 10, [0u8; 32]);
        let score = Verifier::score_solution(&solution);
        assert!(score > 0.0);
    }
}
