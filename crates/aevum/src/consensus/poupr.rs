use crate::consensus::poh::PohGenerator;
use crate::crypto::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsefulWork {
    ZkProofGeneration {
        tx_hash: Hash,
        input_count: u16,
        output_count: u16,
    },
    StorageShard {
        shard_id: u64,
        size_bytes: u64,
        poh_tick_start: u64,
    },
    AiInference {
        model_hash: Hash,
        input_hash: Hash,
    },
}

#[derive(Clone, Debug)]
pub struct PouprProof {
    pub work: UsefulWork,
    pub poh_tick_start: u64,
    pub poh_tick_end: u64,
    pub proof_hash: Hash,
}

impl PouprProof {
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_POUPR_PROOF_V1";

    pub fn new_zk_proof(
        tx_hash: Hash,
        input_count: u16,
        output_count: u16,
        poh_tick_start: u64,
        poh_tick_end: u64,
    ) -> Self {
        let work = UsefulWork::ZkProofGeneration {
            tx_hash,
            input_count,
            output_count,
        };
        let proof_hash = Self::compute_hash(&work, poh_tick_start, poh_tick_end);
        PouprProof {
            work,
            poh_tick_start,
            poh_tick_end,
            proof_hash,
        }
    }

    pub fn new_storage(
        shard_id: u64,
        size_bytes: u64,
        poh_tick_start: u64,
        poh_tick_end: u64,
    ) -> Self {
        let work = UsefulWork::StorageShard {
            shard_id,
            size_bytes,
            poh_tick_start,
        };
        let proof_hash = Self::compute_hash(&work, poh_tick_start, poh_tick_end);
        PouprProof {
            work,
            poh_tick_start,
            poh_tick_end,
            proof_hash,
        }
    }

    pub fn new_ai_inference(
        model_hash: Hash,
        input_hash: Hash,
        poh_tick_start: u64,
        poh_tick_end: u64,
    ) -> Self {
        let work = UsefulWork::AiInference {
            model_hash,
            input_hash,
        };
        let proof_hash = Self::compute_hash(&work, poh_tick_start, poh_tick_end);
        PouprProof {
            work,
            poh_tick_start,
            poh_tick_end,
            proof_hash,
        }
    }

    pub fn verify_time_bounds(&self, poh: &PohGenerator) -> bool {
        if self.poh_tick_end < self.poh_tick_start {
            return false;
        }
        self.poh_tick_end <= poh.current_tick_number()
    }

    pub fn verify_proof_hash(&self) -> bool {
        let expected = Self::compute_hash(&self.work, self.poh_tick_start, self.poh_tick_end);
        expected == self.proof_hash
    }

    fn compute_hash(work: &UsefulWork, poh_tick_start: u64, poh_tick_end: u64) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&poh_tick_start.to_le_bytes());
        hasher.update(&poh_tick_end.to_le_bytes());
        match work {
            UsefulWork::ZkProofGeneration {
                tx_hash,
                input_count,
                output_count,
            } => {
                hasher.update(&[0x00]);
                hasher.update(tx_hash.as_bytes());
                hasher.update(&input_count.to_le_bytes());
                hasher.update(&output_count.to_le_bytes());
            }
            UsefulWork::StorageShard {
                shard_id,
                size_bytes,
                poh_tick_start,
            } => {
                hasher.update(&[0x01]);
                hasher.update(&shard_id.to_le_bytes());
                hasher.update(&size_bytes.to_le_bytes());
                hasher.update(&poh_tick_start.to_le_bytes());
            }
            UsefulWork::AiInference {
                model_hash,
                input_hash,
            } => {
                hasher.update(&[0x02]);
                hasher.update(model_hash.as_bytes());
                hasher.update(input_hash.as_bytes());
            }
        }
        Hash(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zk_proof_creation_and_verification() {
        let proof = PouprProof::new_zk_proof(Hash([1u8; 32]), 2, 3, 0, 10);
        assert!(proof.verify_proof_hash());
    }

    #[test]
    fn storage_proof_creation_and_verification() {
        let proof = PouprProof::new_storage(42, 1024 * 1024, 10, 20);
        assert!(proof.verify_proof_hash());
    }

    #[test]
    fn ai_inference_proof_creation_and_verification() {
        let proof = PouprProof::new_ai_inference(Hash([2u8; 32]), Hash([3u8; 32]), 5, 15);
        assert!(proof.verify_proof_hash());
    }

    #[test]
    fn proof_hash_detects_tampering() {
        let mut proof = PouprProof::new_zk_proof(Hash([1u8; 32]), 2, 3, 0, 10);
        proof.work = UsefulWork::ZkProofGeneration {
            tx_hash: Hash([1u8; 32]),
            input_count: 999,
            output_count: 3,
        };
        assert!(!proof.verify_proof_hash());
    }

    #[test]
    fn verify_time_bounds_rejects_inverse_ticks() {
        let proof = PouprProof::new_zk_proof(Hash([1u8; 32]), 1, 1, 10, 5);
        let poh = PohGenerator::new(b"test");
        assert!(!proof.verify_time_bounds(&poh));
    }

    #[test]
    fn verify_time_bounds_rejects_future_work() {
        let proof = PouprProof::new_zk_proof(Hash([1u8; 32]), 1, 1, 0, 999999);
        let poh = PohGenerator::new(b"test");
        assert!(!proof.verify_time_bounds(&poh));
    }

    #[test]
    fn different_work_types_have_different_hashes() {
        let a = PouprProof::new_zk_proof(Hash([1u8; 32]), 1, 1, 0, 10);
        let b = PouprProof::new_storage(0, 1024, 10, 20);
        let c = PouprProof::new_ai_inference(Hash([2u8; 32]), Hash([3u8; 32]), 5, 15);
        assert_ne!(a.proof_hash, b.proof_hash);
        assert_ne!(a.proof_hash, c.proof_hash);
        assert_ne!(b.proof_hash, c.proof_hash);
    }
}
