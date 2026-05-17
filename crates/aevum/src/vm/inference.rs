use crate::crypto::hash::Hash;

#[derive(Clone, Debug)]
pub struct InferenceResult {
    pub model_hash: Hash,
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub success: bool,
    pub gas_used: u64,
}

impl InferenceResult {
    pub fn new(model_hash: Hash, input_hash: Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(model_hash.as_bytes());
        hasher.update(input_hash.as_bytes());
        hasher.update(b"output");
        let output_hash = Hash(hasher.finalize().into());
        InferenceResult {
            model_hash,
            input_hash,
            output_hash,
            success: true,
            gas_used: 0,
        }
    }

    pub fn verify(&self, expected_model_hash: &Hash, expected_input_hash: &Hash) -> bool {
        self.model_hash == *expected_model_hash
            && self.input_hash == *expected_input_hash
            && self.success
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_result_creation() {
        let r = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        assert!(r.success);
        assert!(r.verify(&Hash([1u8; 32]), &Hash([2u8; 32])));
    }

    #[test]
    fn verify_rejects_wrong_model() {
        let r = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        assert!(!r.verify(&Hash([9u8; 32]), &Hash([2u8; 32])));
    }

    #[test]
    fn verify_rejects_wrong_input() {
        let r = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        assert!(!r.verify(&Hash([1u8; 32]), &Hash([9u8; 32])));
    }

    #[test]
    fn different_inputs_different_outputs() {
        let r1 = InferenceResult::new(Hash([1u8; 32]), Hash([2u8; 32]));
        let r2 = InferenceResult::new(Hash([1u8; 32]), Hash([3u8; 32]));
        assert_ne!(r1.output_hash, r2.output_hash);
    }
}
