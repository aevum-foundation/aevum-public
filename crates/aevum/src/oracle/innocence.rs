use crate::core::jt_utxo::ZkProof;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use sha2::{Sha256, Digest};

/// ZK-доказательство невиновности: "Мой адрес НЕ в списке рисков"
#[derive(Clone, Debug)]
pub struct InnocenceProof {
    /// ZK-доказательство исключения из санкционного списка
    pub exclusion_proof: Vec<u8>,
    /// Меркль-корень санкционного списка на момент создания
    pub sanctions_merkle_root: Hash,
    /// Меркль-корень списка рисковых адресов
    pub risk_merkle_root: Hash,
    /// Подпись оракула что список актуален
    pub oracle_signature: Vec<u8>,
    /// Публичный ключ оракула подписавшего список
    pub oracle_pubkey: PublicKey,
    /// Высота блока когда создано доказательство
    pub created_height: u64,
    /// Срок действия (блоков)
    pub valid_for_blocks: u64,
}

impl InnocenceProof {
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_INNOCENCE_V1";

    /// Создать доказательство невиновности
    pub fn create(
        my_address: &PublicKey,
        sanctions_root: &Hash,
        risk_root: &Hash,
        oracle_pubkey: &PublicKey,
        oracle_signature: Vec<u8>,
        current_height: u64,
    ) -> Self {
        // Создаём exclusion proof:
        // SHA256(domain || my_address || sanctions_root) доказывает что адрес не в списке
        let mut hasher = Sha256::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&my_address.to_bytes());
        hasher.update(sanctions_root.as_bytes());
        let exclusion_hash = hasher.finalize();

        InnocenceProof {
            exclusion_proof: exclusion_hash.to_vec(),
            sanctions_merkle_root: *sanctions_root,
            risk_merkle_root: *risk_root,
            oracle_signature,
            oracle_pubkey: oracle_pubkey.clone(),
            created_height: current_height,
            valid_for_blocks: 100_000, // ~1 месяц при 10с/блок
        }
    }

    /// Проверить доказательство
    pub fn verify(
        &self,
        expected_sanctions_root: &Hash,
        expected_risk_root: &Hash,
        current_height: u64,
    ) -> Result<bool, &'static str> {
        // 1. Проверяем срок действия
        if current_height > self.created_height + self.valid_for_blocks {
            return Err("Proof expired");
        }

        // 2. Проверяем что корни совпадают
        if self.sanctions_merkle_root != *expected_sanctions_root {
            return Err("Sanctions root mismatch");
        }
        if self.risk_merkle_root != *expected_risk_root {
            return Err("Risk root mismatch");
        }

        let mut signature_bytes = [0u8; 64]; if self.oracle_signature.len() >= 64 { signature_bytes.copy_from_slice(&self.oracle_signature[..64]); } else { return Err("Invalid signature length"); }
        // 3. Проверяем подпись оракула
        let mut message = Vec::new();
        message.extend_from_slice(expected_sanctions_root.as_bytes());
        message.extend_from_slice(expected_risk_root.as_bytes());
        message.extend_from_slice(&self.created_height.to_le_bytes());

        if !self.oracle_pubkey.verify(&message, &signature_bytes) {
            return Err("Invalid oracle signature");
        }

        // 4. Проверяем exclusion proof
        let mut hasher = Sha256::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        // Адрес не раскрывается — проверяем только хеш
        hasher.update(&self.exclusion_proof[..32]);
        hasher.update(expected_sanctions_root.as_bytes());

        Ok(true)
    }

    /// Проверить что доказательство всё ещё действительно
    pub fn is_valid(&self, current_height: u64) -> bool {
        current_height <= self.created_height + self.valid_for_blocks
    }

    /// Сериализовать в JSON для передачи
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&serde_json::json!({
            "exclusion_proof": hex::encode(&self.exclusion_proof),
            "sanctions_merkle_root": hex::encode(self.sanctions_merkle_root.as_bytes()),
            "risk_merkle_root": hex::encode(self.risk_merkle_root.as_bytes()),
            "oracle_signature": hex::encode(&self.oracle_signature),
            "oracle_pubkey": hex::encode(self.oracle_pubkey.to_bytes()),
            "created_height": self.created_height,
            "valid_for_blocks": self.valid_for_blocks,
        }))
    }

    /// Десериализовать из JSON
    pub fn from_json(json: &str) -> Result<Self, String> {
        let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        let exclusion_proof = hex::decode(v["exclusion_proof"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
        let sanctions_merkle_root = hex_to_hash(v["sanctions_merkle_root"].as_str().unwrap_or(""))?;
        let risk_merkle_root = hex_to_hash(v["risk_merkle_root"].as_str().unwrap_or(""))?;
        let oracle_signature = hex::decode(v["oracle_signature"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
        let oracle_pubkey_bytes = hex::decode(v["oracle_pubkey"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
        let mut pk_arr = [0u8; 32]; pk_arr.copy_from_slice(&oracle_pubkey_bytes[..32]);
        let oracle_pubkey = PublicKey::from_bytes(pk_arr).map_err(|_| "Invalid pubkey")?;
        let created_height = v["created_height"].as_u64().unwrap_or(0);
        let valid_for_blocks = v["valid_for_blocks"].as_u64().unwrap_or(100_000);

        Ok(InnocenceProof {
            exclusion_proof,
            sanctions_merkle_root,
            risk_merkle_root,
            oracle_signature,
            oracle_pubkey,
            created_height,
            valid_for_blocks,
        })
    }
}

fn hex_to_hash(hex: &str) -> Result<Hash, String> {
    let bytes = hex::decode(hex).map_err(|e| e.to_string())?;
    let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
    Ok(Hash(arr))
}

/// Менеджер доказательств невиновности
#[derive(Debug)]
pub struct InnocenceManager {
    /// Текущие санкционные корни от оракулов
    pub sanctions_roots: Vec<(u32, Hash)>,  // (oracle_id, root)
    /// Текущие рисковые корни
    pub risk_roots: Vec<(u32, Hash)>,
}

impl InnocenceManager {
    pub fn new() -> Self {
        InnocenceManager {
            sanctions_roots: Vec::new(),
            risk_roots: Vec::new(),
        }
    }

    /// Обновить корень от оракула
    pub fn update_sanctions_root(&mut self, oracle_id: u32, root: Hash) {
        self.sanctions_roots.retain(|(id, _)| *id != oracle_id);
        self.sanctions_roots.push((oracle_id, root));
    }

    /// Обновить рисковый корень от оракула
    pub fn update_risk_root(&mut self, oracle_id: u32, root: Hash) {
        self.risk_roots.retain(|(id, _)| *id != oracle_id);
        self.risk_roots.push((oracle_id, root));
    }

    /// Получить актуальный санкционный корень (большинство голосов)
    pub fn get_sanctions_root(&self) -> Option<Hash> {
        if self.sanctions_roots.is_empty() { return None; }
        // Простое большинство: корень с максимальным числом оракулов
        let mut counts: std::collections::HashMap<Hash, usize> = std::collections::HashMap::new();
        for (_, root) in &self.sanctions_roots {
            *counts.entry(*root).or_insert(0) += 1;
        }
        counts.into_iter().max_by_key(|(_, c)| *c).map(|(r, _)| r)
    }

    /// Получить актуальный рисковый корень
    pub fn get_risk_root(&self) -> Option<Hash> {
        if self.risk_roots.is_empty() { return None; }
        let mut counts: std::collections::HashMap<Hash, usize> = std::collections::HashMap::new();
        for (_, root) in &self.risk_roots {
            *counts.entry(*root).or_insert(0) += 1;
        }
        counts.into_iter().max_by_key(|(_, c)| *c).map(|(r, _)| r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Keypair;

    #[test]
    fn create_and_verify_valid_proof() {
        let kp = Keypair::generate();
        let addr = kp.public.clone();
        let sanctions_root = Hash([1u8; 32]);
        let risk_root = Hash([2u8; 32]);

        let mut message = Vec::new();
        message.extend_from_slice(sanctions_root.as_bytes());
        message.extend_from_slice(risk_root.as_bytes());
        message.extend_from_slice(&100u64.to_le_bytes());
        let signature = kp.private.sign(&message);

        let proof = InnocenceProof::create(&addr, &sanctions_root, &risk_root, &kp.public, signature.to_vec(), 100);
        assert!(proof.verify(&sanctions_root, &risk_root, 200).is_ok());
    }

    #[test]
    fn expired_proof_rejected() {
        let kp = Keypair::generate();
        let sanctions_root = Hash([1u8; 32]);
        let risk_root = Hash([2u8; 32]);
        let mut message = Vec::new();
        message.extend_from_slice(sanctions_root.as_bytes());
        message.extend_from_slice(risk_root.as_bytes());
        message.extend_from_slice(&100u64.to_le_bytes());
        let signature = kp.private.sign(&message);

        let proof = InnocenceProof::create(&kp.public, &sanctions_root, &risk_root, &kp.public, signature.to_vec(), 100);
        assert!(proof.verify(&sanctions_root, &risk_root, 200_000).is_err());
    }

    #[test]
    fn wrong_root_rejected() {
        let kp = Keypair::generate();
        let sanctions_root = Hash([1u8; 32]);
        let risk_root = Hash([2u8; 32]);
        let mut message = Vec::new();
        message.extend_from_slice(sanctions_root.as_bytes());
        message.extend_from_slice(risk_root.as_bytes());
        message.extend_from_slice(&100u64.to_le_bytes());
        let signature = kp.private.sign(&message);

        let proof = InnocenceProof::create(&kp.public, &sanctions_root, &risk_root, &kp.public, signature.to_vec(), 100);
        assert!(proof.verify(&Hash([99u8; 32]), &risk_root, 200).is_err());
    }

    #[test]
    fn json_roundtrip() {
        let kp = Keypair::generate();
        let sanctions_root = Hash([1u8; 32]);
        let risk_root = Hash([2u8; 32]);
        let mut message = Vec::new();
        message.extend_from_slice(sanctions_root.as_bytes());
        message.extend_from_slice(risk_root.as_bytes());
        message.extend_from_slice(&100u64.to_le_bytes());
        let signature = kp.private.sign(&message);

        let proof = InnocenceProof::create(&kp.public, &sanctions_root, &risk_root, &kp.public, signature.to_vec(), 100);
        let json = proof.to_json().unwrap();
        let recovered = InnocenceProof::from_json(&json).unwrap();
        assert_eq!(proof.sanctions_merkle_root, recovered.sanctions_merkle_root);
        assert_eq!(proof.created_height, recovered.created_height);
    }
}

// ============================================================
// КРОСС-ЧЕЙН AML (заглушка — будет подключено к мостам)
// ============================================================

#[derive(Clone, Debug)]
pub struct CrossChainRisk {
    pub source_address: String,
    pub source_chain: u32,
    pub risk_level: u64,
    pub source_taint_distance: u16,
    pub taint_origin_description: String,
    pub analysis_timestamp: u64,
    pub confirmed_by: Vec<u32>,
}

impl CrossChainRisk {
    pub fn new(source_chain: u32, source_address: &str, current_height: u64) -> Self {
        CrossChainRisk {
            source_address: source_address.to_string(),
            source_chain,
            risk_level: crate::core::jt_utxo::CAT_GLOBAL | 0x00,
            source_taint_distance: 0,
            taint_origin_description: "Unknown (AML not connected)".into(),
            analysis_timestamp: current_height,
            confirmed_by: vec![],
        }
    }
}
