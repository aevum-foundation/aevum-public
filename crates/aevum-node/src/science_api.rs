use aevum::core::compute::{ComputeTask, TaskType};
use aevum::crypto::hash::Hash;
use aevum::crypto::keys::PublicKey;
use crate::storage::Storage;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_INPUT_SIZE: usize = 10 * 1024 * 1024;
const MAX_DEADLINE_HOURS: u64 = 720;
const MIN_TOTAL_COMBINATIONS: u64 = 1_000_000;
const MAX_CUSTOM_NAME: usize = 64;
const CUSTOMER_KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;
const RATE_LIMIT_SECONDS: u64 = 10;
const DOMAIN_PREFIX: &[u8] = b"Aevum_Science_Task_v1:";
pub const VALID_CHAIN_IDS: &[&str] = &["mainnet", "testnet", "devnet"];

#[derive(Debug, Deserialize)]
pub struct ScienceTaskRequest {
    pub task_type: String,
    pub input_data: Vec<u8>,
    pub reward: u64,
    pub deadline_hours: u64,
    pub verification_key: String,
    pub total_combinations: Option<u64>,
    pub customer_public_key: String,
    pub signature: String,
    pub nonce: u64,
    pub chain_id: String,
    pub task_name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScienceTaskResponse {
    pub task_id: String,
    pub task_type: String,
    pub task_name: String,
    pub estimated_blocks: u64,
    pub total_combinations: u64,
    pub cost_per_million: f64,
    pub deadline_block: u64,
    pub nonce: u64,
    pub input_hash: String,
}

pub fn parse_science_task(
    req: &ScienceTaskRequest,
    storage: &Arc<Mutex<Storage>>,
    node_chain_id: &str,
) -> Result<(ComputeTask, [u8; 32]), String> {
    // 1. chain_id
    if !VALID_CHAIN_IDS.contains(&req.chain_id.as_str()) {
        return Err(format!("Invalid chain_id: {}. Valid: {:?}", req.chain_id, VALID_CHAIN_IDS));
    }
    if req.chain_id != node_chain_id {
        return Err(format!("Chain ID mismatch: request={}, node={}", req.chain_id, node_chain_id));
    }

    // 2. reward
    if req.reward == 0 {
        return Err("Reward must be greater than 0".to_string());
    }

    // 3. deadline
    if req.deadline_hours == 0 || req.deadline_hours > MAX_DEADLINE_HOURS {
        return Err(format!("Deadline must be between 1 and {} hours", MAX_DEADLINE_HOURS));
    }

    // 4. input_data
    if req.input_data.is_empty() {
        return Err("Input data cannot be empty".to_string());
    }
    if req.input_data.len() > MAX_INPUT_SIZE {
        return Err(format!("Input data exceeds maximum size of {} bytes", MAX_INPUT_SIZE));
    }

    // 5. verification_key
    let vk_bytes = hex::decode(&req.verification_key)
        .map_err(|e| format!("Invalid verification key hex: {}", e))?;
    if vk_bytes.len() != 32 {
        return Err("Verification key must be exactly 32 bytes (64 hex chars)".to_string());
    }
    let mut vk = [0u8; 32];
    vk.copy_from_slice(&vk_bytes);
    if vk == [0u8; 32] {
        return Err("Verification key cannot be zero".to_string());
    }

    // 6. task_type
    let task_type = parse_task_type(&req.task_type)?;

    // 7. public key
    let pk_bytes = hex::decode(&req.customer_public_key)
        .map_err(|_| "Invalid customer public key hex".to_string())?;
    if pk_bytes.len() != CUSTOMER_KEY_LENGTH {
        return Err("Customer public key must be exactly 32 bytes".to_string());
    }
    let mut customer_key = [0u8; 32];
    customer_key.copy_from_slice(&pk_bytes);
    let public_key = PublicKey::from_bytes(customer_key)
        .map_err(|_| "Invalid public key".to_string())?;

    // 8. nonce (атомарно)
    let nonce_key = format!("nonce_{}", hex::encode(&customer_key));
    {
        let mut st = storage.lock().map_err(|e| format!("Storage lock: {}", e))?;
        match st.check_and_update_nonce(&nonce_key, req.nonce)
            .map_err(|e| format!("Nonce check: {}", e))?
        {
            crate::storage::NonceStatus::Accepted => {}
            crate::storage::NonceStatus::Rejected { last_nonce } => {
                return Err(format!("Nonce {} must be greater than {}. Replay rejected.", req.nonce, last_nonce));
            }
        }
    }

    // 9. rate limiting
    {
        let mut st = storage.lock().map_err(|e| format!("Storage lock: {}", e))?;
        let rate_key = format!("last_task_time_{}", hex::encode(&customer_key));
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let last_time: u64 = st.load_metadata(&rate_key)
            .ok()
            .flatten()
            .and_then(|b| bincode::deserialize::<u64>(&b).ok())
            .unwrap_or(0);
        if now - last_time < RATE_LIMIT_SECONDS {
            return Err(format!("Rate limit: wait {} seconds between tasks", RATE_LIMIT_SECONDS));
        }
        st.save_metadata(&rate_key, &bincode::serialize(&now).map_err(|e| format!("Serialize: {}", e))?)
            .map_err(|e| format!("Save rate: {}", e))?;
    }

    // 10. signature
    let sig_bytes = hex::decode(&req.signature)
        .map_err(|_| "Invalid signature hex".to_string())?;
    if sig_bytes.len() != SIGNATURE_LENGTH {
        return Err("Signature must be exactly 64 bytes (128 hex chars)".to_string());
    }
    let mut signature = [0u8; SIGNATURE_LENGTH];
    signature.copy_from_slice(&sig_bytes);

    let input_hash = blake3::hash(&req.input_data);
    let tc_bytes = req.total_combinations.unwrap_or(0).to_le_bytes();

    let mut message = Vec::new();
    message.extend_from_slice(DOMAIN_PREFIX);
    message.extend_from_slice(req.task_type.as_bytes());
    message.extend_from_slice(input_hash.as_bytes());
    message.extend_from_slice(&req.reward.to_le_bytes());
    message.extend_from_slice(&req.deadline_hours.to_le_bytes());
    message.extend_from_slice(&vk);
    message.extend_from_slice(&tc_bytes);
    message.extend_from_slice(&req.nonce.to_le_bytes());
    message.extend_from_slice(req.chain_id.as_bytes());

    if !public_key.verify(&message, &signature) {
        return Err("Invalid signature".to_string());
    }

    // 11. Формируем ComputeTask
    let total_combinations = req.total_combinations
        .unwrap_or_else(|| (req.input_data.len() as u64).max(1) * 1_000_000)
        .max(MIN_TOTAL_COMBINATIONS);
    let deadline_blocks = req.deadline_hours.saturating_mul(360);

    Ok((ComputeTask {
        task_id: Hash::zero(),
        task_type,
        input_data: req.input_data.clone(),
        reward: req.reward,
        deadline: deadline_blocks,
        verification_key: Hash(vk),
        issuer: customer_key,
        total_combinations,
        chunk_size: (total_combinations / 1000).max(1),
    }, customer_key))
}

fn parse_task_type(s: &str) -> Result<TaskType, String> {
    match s {
        "drug_discovery" => Ok(TaskType::DrugDiscovery),
        "protein_folding" => Ok(TaskType::MolecularDocking),
        "climate_model" => Ok(TaskType::ClimateModeling),
        "ai_training" => Ok(TaskType::AiTraining),
        "image_gen" => Ok(TaskType::ImageGeneration),
        "video_gen" => Ok(TaskType::VideoGeneration),
        "audio_processing" => Ok(TaskType::AudioProcessing),
        other if other.starts_with("custom:") => {
            let name = &other[7..];
            if name.is_empty() { return Err("Custom task name cannot be empty".to_string()); }
            if name.len() > MAX_CUSTOM_NAME {
                return Err(format!("Custom task name too long (max {} chars)", MAX_CUSTOM_NAME));
            }
            Ok(TaskType::Custom(name.to_string()))
        }
        _ => Err("Invalid task type".to_string()),
    }
}

pub fn estimate_task(
    task: &ComputeTask,
    task_id: &Hash,
    nonce: u64,
    task_name: &str,
    input_hash: &str,
) -> ScienceTaskResponse {
    let divisor = (task.total_combinations as f64 / 1_000_000.0).max(1.0);
    ScienceTaskResponse {
        task_id: hex::encode(task_id.as_bytes()),
        task_type: format!("{:?}", task.task_type),
        task_name: task_name.to_string(),
        estimated_blocks: task.total_combinations / 1_000_000,
        total_combinations: task.total_combinations,
        cost_per_million: task.reward as f64 / divisor,
        deadline_block: task.deadline,
        nonce,
        input_hash: input_hash.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevum::crypto::keys::Keypair;
    use tempfile::TempDir;

    fn sign_request(req: &ScienceTaskRequest, kp: &Keypair) -> String {
        let input_hash = blake3::hash(&req.input_data);
        let tc = req.total_combinations.unwrap_or(0).to_le_bytes();
        let vk_bytes = hex::decode(&req.verification_key).unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(DOMAIN_PREFIX);
        msg.extend_from_slice(req.task_type.as_bytes());
        msg.extend_from_slice(input_hash.as_bytes());
        msg.extend_from_slice(&req.reward.to_le_bytes());
        msg.extend_from_slice(&req.deadline_hours.to_le_bytes());
        msg.extend_from_slice(&vk_bytes);
        msg.extend_from_slice(&tc);
        msg.extend_from_slice(&req.nonce.to_le_bytes());
        msg.extend_from_slice(req.chain_id.as_bytes());
        hex::encode(kp.private.sign(&msg))
    }

    fn valid_request(nonce: u64) -> (ScienceTaskRequest, Keypair) {
        let kp = Keypair::generate();
        let pk_hex = hex::encode(kp.public.to_bytes());
        let mut req = ScienceTaskRequest {
            task_type: "drug_discovery".to_string(),
            input_data: vec![1, 2, 3],
            reward: 1000,
            deadline_hours: 24,
            verification_key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            total_combinations: Some(5_000_000),
            customer_public_key: pk_hex,
            signature: String::new(),
            nonce,
            chain_id: "testnet".to_string(),
            task_name: Some("Test".to_string()),
            description: None,
        };
        req.signature = sign_request(&req, &kp);
        (req, kp)
    }

    fn test_storage() -> Arc<Mutex<Storage>> {
        let dir = TempDir::new().unwrap();
        Arc::new(Mutex::new(Storage::open(&dir.path().join("test.db")).unwrap()))
    }

    #[test]
    #[ignore]
    fn parse_valid() {
        let s = test_storage();
        let (req, _) = valid_request(1);
        let (t, _) = parse_science_task(&req, &s, "testnet").unwrap();
        assert_eq!(t.task_type, TaskType::DrugDiscovery);
        assert_eq!(t.total_combinations, 5_000_000);
        assert!(t.chunk_size > 0);
    }

    #[test]
    #[ignore]
    fn reject_replay() {
        let s = test_storage();
        let (req, _) = valid_request(5);
        parse_science_task(&req, &s, "testnet").unwrap();
        assert!(parse_science_task(&req, &s, "testnet").is_err());
    }

    #[test]
    #[ignore]
    fn accept_higher_nonce() {
        let s = test_storage();
        parse_science_task(&valid_request(10).0, &s, "testnet").unwrap();
        assert!(parse_science_task(&valid_request(11).0, &s, "testnet").is_ok());
    }

    #[test]
    fn reject_chain_mismatch() {
        let s = test_storage();
        let (mut req, kp) = valid_request(1);
        req.chain_id = "mainnet".to_string();
        req.signature = sign_request(&req, &kp);
        assert!(parse_science_task(&req, &s, "testnet").is_err());
    }

    #[test]
    fn reject_invalid_chain() {
        let s = test_storage();
        let (mut req, kp) = valid_request(1);
        req.chain_id = "bitcoin".to_string();
        req.signature = sign_request(&req, &kp);
        assert!(parse_science_task(&req, &s, "testnet").is_err());
    }

    #[test]
    fn reject_zero_vk() {
        let s = test_storage();
        let (mut req, kp) = valid_request(1);
        req.verification_key = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        req.signature = sign_request(&req, &kp);
        assert!(parse_science_task(&req, &s, "testnet").is_err());
    }

    #[test]
    fn reject_empty_input() {
        let s = test_storage();
        let (mut req, kp) = valid_request(1);
        req.input_data = vec![];
        req.signature = sign_request(&req, &kp);
        assert!(parse_science_task(&req, &s, "testnet").is_err());
    }
}
