use crate::crypto::hash::Hash;
use crate::vm::inference::InferenceResult;

#[derive(Clone, Debug)]
pub struct ZkVmProof {
    pub model_hash: Hash,
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub success: bool,
    pub proof_data: Vec<u8>,
}

impl ZkVmProof {
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_ZK_VM_V1";

    pub fn prove(result: &InferenceResult) -> Self {
        ZkVmProof {
            model_hash: result.model_hash,
            input_hash: result.input_hash,
            output_hash: result.output_hash,
            success: result.success,
            proof_data: Vec::new(),
        }
    }

    pub fn verify(&self, result: &InferenceResult) -> bool {
        self.model_hash == result.model_hash
            && self.input_hash == result.input_hash
            && self.output_hash == result.output_hash
            && self.success == result.success
    }

    /// Проверить по частям. self.success должен быть true.
    pub fn verify_parts(&self, model_hash: &Hash, input_hash: &Hash, output_hash: &Hash) -> bool {
        self.model_hash == *model_hash
            && self.input_hash == *input_hash
            && self.output_hash == *output_hash
            && self.success
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify() {
        let result = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        let proof = ZkVmProof::prove(&result);
        assert!(proof.verify(&result));
    }

    #[test]
    fn verify_rejects_wrong_result() {
        let result = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        let proof = ZkVmProof::prove(&result);
        let wrong = InferenceResult::new(Hash([9u8; 32]), Hash([2u8; 32]));
        assert!(!proof.verify(&wrong));
    }

    #[test]
    fn verify_parts_works() {
        let result = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        let proof = ZkVmProof::prove(&result);
        assert!(proof.verify_parts(&Hash([1u8; 32]), &Hash([2u8; 32]), &result.output_hash));
    }

    #[test]
    fn verify_parts_rejects_wrong() {
        let result = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        let proof = ZkVmProof::prove(&result);
        assert!(!proof.verify_parts(&Hash([9u8; 32]), &Hash([2u8; 32]), &result.output_hash));
    }
}
