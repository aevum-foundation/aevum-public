use crate::crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelInfo {
    pub model_hash: Hash,
    pub name: String,
    pub version: String,
    pub model_type: ModelType,
    pub size_bytes: u64,
    pub uploader: [u8; 32],
    pub price_per_inference: u64,
    pub usage_count: u64,
    pub rating: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelType {
    ImageGeneration,
    ImageRecognition,
    TextGeneration,
    TextAnalysis,
    AudioSynthesis,
    AudioRecognition,
    MolecularDocking,
    ClimateModeling,
    Custom(String),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ModelRegistryError {
    ModelNotFound,
    ModelAlreadyRegistered,
}

impl fmt::Display for ModelRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ModelNotFound => write!(f, "Model not found in registry"),
            Self::ModelAlreadyRegistered => write!(f, "Model already registered"),
        }
    }
}

impl std::error::Error for ModelRegistryError {}

pub struct ModelRegistry {
    models: HashMap<Hash, ModelInfo>,
}

impl ModelRegistry {
    pub fn new() -> Self {
        ModelRegistry {
            models: HashMap::new(),
        }
    }

    pub fn register(&mut self, info: ModelInfo) -> Result<(), ModelRegistryError> {
        if self.models.contains_key(&info.model_hash) {
            return Err(ModelRegistryError::ModelAlreadyRegistered);
        }
        self.models.insert(info.model_hash, info);
        Ok(())
    }

    pub fn remove(&mut self, model_hash: &Hash) -> Result<ModelInfo, ModelRegistryError> {
        self.models
            .remove(model_hash)
            .ok_or(ModelRegistryError::ModelNotFound)
    }

    pub fn update(
        &mut self,
        model_hash: &Hash,
        price: Option<u64>,
        rating: Option<u8>,
    ) -> Result<(), ModelRegistryError> {
        let info = self
            .models
            .get_mut(model_hash)
            .ok_or(ModelRegistryError::ModelNotFound)?;
        if let Some(p) = price {
            info.price_per_inference = p;
        }
        if let Some(r) = rating {
            info.rating = r;
        }
        Ok(())
    }

    pub fn get(&self, model_hash: &Hash) -> Option<&ModelInfo> {
        self.models.get(model_hash)
    }

    pub fn search_by_type(&self, model_type: &ModelType) -> Vec<&ModelInfo> {
        self.models
            .values()
            .filter(|m| m.model_type == *model_type)
            .collect()
    }

    pub fn most_used(&self, limit: usize) -> Vec<&ModelInfo> {
        let mut sorted: Vec<&ModelInfo> = self.models.values().collect();
        sorted.sort_by_key(|m| std::cmp::Reverse(m.usage_count));
        sorted.truncate(limit);
        sorted
    }

    pub fn cheapest(&self, limit: usize) -> Vec<&ModelInfo> {
        let mut sorted: Vec<&ModelInfo> = self.models.values().collect();
        sorted.sort_by_key(|m| m.price_per_inference);
        sorted.truncate(limit);
        sorted
    }

    pub fn list_all(&self) -> Vec<&ModelInfo> {
        self.models.values().collect()
    }

    pub fn increment_usage(&mut self, model_hash: &Hash) {
        if let Some(info) = self.models.get_mut(model_hash) {
            info.usage_count += 1;
        }
    }

    pub fn count(&self) -> usize {
        self.models.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_model(id: u8) -> ModelInfo {
        ModelInfo {
            model_hash: Hash([id; 32]),
            name: format!("Model {}", id),
            version: "1.0".to_string(),
            model_type: ModelType::ImageGeneration,
            size_bytes: 1024,
            uploader: [0u8; 32],
            price_per_inference: 100,
            usage_count: 0,
            rating: 50,
        }
    }

    #[test]
    fn register_and_retrieve() {
        let mut r = ModelRegistry::new();
        let m = dummy_model(1);
        let h = m.model_hash;
        r.register(m).unwrap();
        assert!(r.get(&h).is_some());
    }

    #[test]
    fn duplicate_rejected() {
        let mut r = ModelRegistry::new();
        r.register(dummy_model(1)).unwrap();
        assert!(r.register(dummy_model(1)).is_err());
    }

    #[test]
    fn search_by_type() {
        let mut r = ModelRegistry::new();
        let mut m1 = dummy_model(1);
        m1.model_type = ModelType::ImageGeneration;
        let mut m2 = dummy_model(2);
        m2.model_type = ModelType::TextGeneration;
        r.register(m1).unwrap();
        r.register(m2).unwrap();
        assert_eq!(r.search_by_type(&ModelType::ImageGeneration).len(), 1);
    }

    #[test]
    fn increment_usage() {
        let mut r = ModelRegistry::new();
        let h = dummy_model(1).model_hash;
        r.register(dummy_model(1)).unwrap();
        r.increment_usage(&h);
        assert_eq!(r.get(&h).unwrap().usage_count, 1);
    }

    #[test]
    fn update_price_and_rating() {
        let mut r = ModelRegistry::new();
        let h = dummy_model(1).model_hash;
        r.register(dummy_model(1)).unwrap();
        r.update(&h, Some(200), Some(80)).unwrap();
        let m = r.get(&h).unwrap();
        assert_eq!(m.price_per_inference, 200);
        assert_eq!(m.rating, 80);
    }

    #[test]
    fn most_used_sorts() {
        let mut r = ModelRegistry::new();
        for i in 0..5 {
            let mut m = dummy_model(i);
            m.usage_count = i as u64;
            r.register(m).unwrap();
        }
        let top = r.most_used(3);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].usage_count, 4);
    }

    #[test]
    fn cheapest_sorts() {
        let mut r = ModelRegistry::new();
        for i in 0..3 {
            let mut m = dummy_model(i);
            m.price_per_inference = (i as u64 + 1) * 100;
            r.register(m).unwrap();
        }
        let cheap = r.cheapest(2);
        assert_eq!(cheap[0].price_per_inference, 100);
    }

    #[test]
    fn remove_model() {
        let mut r = ModelRegistry::new();
        let h = dummy_model(1).model_hash;
        r.register(dummy_model(1)).unwrap();
        assert!(r.remove(&h).is_ok());
        assert!(r.get(&h).is_none());
    }

    #[test]
    fn remove_nonexistent() {
        assert!(ModelRegistry::new().remove(&Hash::zero()).is_err());
    }

    #[test]
    fn list_all() {
        let mut r = ModelRegistry::new();
        r.register(dummy_model(1)).unwrap();
        r.register(dummy_model(2)).unwrap();
        assert_eq!(r.list_all().len(), 2);
    }
}
