use crate::crypto::hash::Hash;
use std::collections::HashMap;

/// Результат ONNX-инференса
#[derive(Clone, Debug)]
pub struct InferenceResult {
    pub model_hash: Hash,
    pub input_hash: Hash,
    pub output_data: Vec<u8>,
    pub output_hash: Hash,
    pub gas_used: u64,
    pub confidence: f64,
}

/// ONNX-исполнитель для AI-моделей
pub struct OnnxExecutor {
    /// Загруженные модели (model_hash → onnx_bytes)
    models: HashMap<Hash, Vec<u8>>,
    /// Использовать GPU если доступен
    use_gpu: bool,
}

impl OnnxExecutor {
    pub fn new() -> Self {
        OnnxExecutor {
            models: HashMap::new(),
            use_gpu: false,
        }
    }

    /// Загрузить ONNX-модель
    pub fn load_model(&mut self, model_bytes: &[u8]) -> Result<Hash, &'static str> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_ONNX_MODEL");
        hasher.update(model_bytes);
        let model_hash = Hash(hasher.finalize().into());
        self.models.insert(model_hash, model_bytes.to_vec());
        Ok(model_hash)
    }

    /// Выполнить инференс
    pub fn infer(
        &self,
        model_hash: &Hash,
        input_data: &[u8],
    ) -> Result<InferenceResult, &'static str> {
        let _model_bytes = self.models.get(model_hash).ok_or("Model not found")?;

        let mut input_hasher = blake3::Hasher::new();
        input_hasher.update(b"AEVUM_INFERENCE_INPUT");
        input_hasher.update(input_data);
        let input_hash = Hash(input_hasher.finalize().into());

        // v0.2: заглушка — XOR с моделью
        let output_data: Vec<u8> = input_data
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ (i as u8))
            .collect();

        let mut output_hasher = blake3::Hasher::new();
        output_hasher.update(b"AEVUM_INFERENCE_OUTPUT");
        output_hasher.update(&output_data);
        let output_hash = Hash(output_hasher.finalize().into());

        Ok(InferenceResult {
            model_hash: *model_hash,
            input_hash,
            output_data,
            output_hash,
            gas_used: 1000,
            confidence: 0.95,
        })
    }

    /// Проверить что модель загружена
    pub fn is_loaded(&self, model_hash: &Hash) -> bool {
        self.models.contains_key(model_hash)
    }

    /// Количество загруженных моделей
    pub fn model_count(&self) -> usize {
        self.models.len()
    }

    /// Включить/выключить GPU
    pub fn set_gpu(&mut self, enabled: bool) {
        self.use_gpu = enabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_infer() {
        let mut executor = OnnxExecutor::new();
        let hash = executor.load_model(b"dummy model").unwrap();
        assert!(executor.is_loaded(&hash));

        let result = executor.infer(&hash, b"test input").unwrap();
        assert!(!result.output_data.is_empty());
        assert!(result.confidence > 0.0);
        assert!(result.gas_used > 0);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let mut executor = OnnxExecutor::new();
        let hash = executor.load_model(b"model").unwrap();

        let r1 = executor.infer(&hash, b"input1").unwrap();
        let r2 = executor.infer(&hash, b"input2").unwrap();
        assert_ne!(r1.output_hash, r2.output_hash);
    }

    #[test]
    fn model_not_found() {
        let executor = OnnxExecutor::new();
        assert!(executor.infer(&Hash::zero(), b"input").is_err());
    }
}
