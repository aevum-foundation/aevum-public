use serde::{Deserialize, Serialize};
use crate::crypto::hash::{Hash, AmountCommitment, TagCommitment};
use crate::crypto::keys::PublicKey;
use crate::core::jt_utxo::{ZkProof, ProofScheme};
use crate::core::compute::{BlockSolution, ComputeTask, TaskType};

pub const WIRE_VERSION: u16 = 1;
pub const MAX_SIGNATURE_SIZE: usize = 65536;

#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    InvalidPublicKey,
    SignatureTooLarge(usize),
    UnknownProofScheme(u16),
    UnknownTaskType(u8),
    DeserializationFailed(String),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WireError::InvalidPublicKey => write!(f, "Invalid public key"),
            WireError::SignatureTooLarge(s) => write!(f, "Signature too large: {} bytes", s),
            WireError::UnknownProofScheme(c) => write!(f, "Unknown proof scheme: {}", c),
            WireError::UnknownTaskType(t) => write!(f, "Unknown task type: {}", t),
            WireError::DeserializationFailed(e) => write!(f, "Deserialization failed: {}", e),
        }
    }
}
impl std::error::Error for WireError {}

pub trait WireFormat<T>: Sized {
    fn to_core(&self) -> Result<T, WireError>;
    fn from_core(core: &T) -> Result<Self, WireError>;
}

// ============================================================
// TASK TYPE CODEC
// ============================================================

impl TaskType {
    pub fn to_wire_code(&self) -> u8 {
        match self {
            TaskType::DrugDiscovery => 0,
            TaskType::ClimateModeling => 1,
            TaskType::AiTraining => 2,
            TaskType::ZkProofGeneration => 3,
            TaskType::ImageGeneration => 4,
            TaskType::VideoGeneration => 5,
            TaskType::AudioProcessing => 6,
            TaskType::MolecularDocking => 7,
            TaskType::Custom(_) => 255,
        }
    }

    pub fn from_wire_code(code: u8) -> Result<Self, WireError> {
        match code {
            0 => Ok(TaskType::DrugDiscovery),
            1 => Ok(TaskType::ClimateModeling),
            2 => Ok(TaskType::AiTraining),
            3 => Ok(TaskType::ZkProofGeneration),
            4 => Ok(TaskType::ImageGeneration),
            5 => Ok(TaskType::VideoGeneration),
            6 => Ok(TaskType::AudioProcessing),
            7 => Ok(TaskType::MolecularDocking),
            255 => Ok(TaskType::Custom(String::new())),
            _ => Err(WireError::UnknownTaskType(code)),
        }
    }
}

// ============================================================
// PROOF SCHEME CODEC
// ============================================================

impl ProofScheme {
    pub fn to_wire_code(&self) -> u16 {
        match self { ProofScheme::Halo2 => 0, ProofScheme::Stark => 1 }
    }
    pub fn from_wire_code(code: u16) -> Result<Self, WireError> {
        match code {
            0 => Ok(ProofScheme::Halo2),
            1 => Ok(ProofScheme::Stark),
            _ => Err(WireError::UnknownProofScheme(code)),
        }
    }
}

// ============================================================
// COMPUTE TASK WIRE
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComputeTaskWire {
    pub task_id: [u8; 32],
    pub task_type: u8,
    pub custom_name: Option<String>,
    pub input_data: Vec<u8>,
    pub reward: u64,
    pub deadline: u64,
    pub verification_key: [u8; 32],
    pub issuer: [u8; 32],
    pub total_combinations: u64,
    pub chunk_size: u64,
}

impl ComputeTaskWire {
    fn to_core(&self) -> Result<ComputeTask, WireError> {
        let task_type = TaskType::from_wire_code(self.task_type)?;
        Ok(ComputeTask {
            task_id: Hash(self.task_id),
            task_type,
            input_data: self.input_data.clone(),
            reward: self.reward,
            deadline: self.deadline,
            verification_key: Hash(self.verification_key),
            issuer: self.issuer,
            total_combinations: self.total_combinations,
            chunk_size: self.chunk_size,
        })
    }

    fn from_core(task: &ComputeTask) -> Self {
        ComputeTaskWire {
            task_id: task.task_id.0,
            task_type: task.task_type.to_wire_code(),
            custom_name: match &task.task_type {
                TaskType::Custom(name) => Some(name.clone()),
                _ => None,
            },
            input_data: task.input_data.clone(),
            reward: task.reward,
            deadline: task.deadline,
            verification_key: task.verification_key.0,
            issuer: task.issuer,
            total_combinations: task.total_combinations,
            chunk_size: task.chunk_size,
        }
    }
}

// ============================================================
// BLOCK SOLUTION WIRE
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSolutionWire {
    pub task: ComputeTaskWire,
    pub solution: Vec<u8>,
    pub zk_proof: Vec<u8>,
    pub block_height: u64,
    pub miner_address: [u8; 32],
    pub worker_range_start: Option<u64>,
    pub worker_range_end: Option<u64>,
    pub pool_id: Option<[u8; 32]>,
}

impl BlockSolutionWire {
    fn to_core(&self) -> Result<BlockSolution, WireError> {
        Ok(BlockSolution {
            task: self.task.to_core()?,
            solution: self.solution.clone(),
            zk_proof: self.zk_proof.clone(),
            block_height: self.block_height,
            miner_address: self.miner_address,
            worker_range: match (self.worker_range_start, self.worker_range_end) {
                (Some(s), Some(e)) => Some((s, e)),
                _ => None,
            },
            pool_id: self.pool_id.map(Hash),
        })
    }

    fn from_core(sol: &BlockSolution) -> Self {
        BlockSolutionWire {
            task: ComputeTaskWire::from_core(&sol.task),
            solution: sol.solution.clone(),
            zk_proof: sol.zk_proof.clone(),
            block_height: sol.block_height,
            miner_address: sol.miner_address,
            worker_range_start: sol.worker_range.map(|(s, _)| s),
            worker_range_end: sol.worker_range.map(|(_, e)| e),
            pool_id: sol.pool_id.map(|h| h.0),
        }
    }
}

// ============================================================
// BLOCK WIRE
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockWire {
    pub wire_version: u16,
    pub version: u8,
    pub block_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub height: u64,
    pub poh_tick_start: u64,
    pub poh_tick_end: u64,
    pub transactions: Vec<TxWire>,
    pub state_root: [u8; 32],
    pub total_supply: u64,
    pub useful_solution: Option<BlockSolutionWire>,
}

impl WireFormat<crate::core::block::Block> for BlockWire {
    fn to_core(&self) -> Result<crate::core::block::Block, WireError> {
        let txs: Result<Vec<_>, _> = self.transactions.iter().map(|t| t.to_core()).collect();
        let solution = match &self.useful_solution {
            Some(s) => Some(s.to_core()?),
            None => None,
        };
        Ok(crate::core::block::Block {
            version: self.version,
            prev_hash: Hash(self.prev_hash),
            block_hash: Hash(self.block_hash),
            height: self.height,
            poh_tick_start: self.poh_tick_start,
            poh_tick_end: self.poh_tick_end,
            transactions: txs?,
            state_root: Hash(self.state_root),
            total_supply: self.total_supply,
            useful_solution: solution,
        })
    }

    fn from_core(block: &crate::core::block::Block) -> Result<Self, WireError> {
        let txs: Result<Vec<_>, _> = block.transactions.iter().map(|t| TxWire::from_core(t)).collect();
        let solution = match &block.useful_solution {
            Some(s) => Some(BlockSolutionWire::from_core(s)),
            None => None,
        };
        Ok(BlockWire {
            wire_version: WIRE_VERSION,
            version: block.version,
            block_hash: block.block_hash.0,
            prev_hash: block.prev_hash.0,
            height: block.height,
            poh_tick_start: block.poh_tick_start,
            poh_tick_end: block.poh_tick_end,
            transactions: txs?,
            state_root: block.state_root.0,
            total_supply: block.total_supply,
            useful_solution: solution,
        })
    }
}

// ============================================================
// TX WIRE
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxWire {
    pub wire_version: u16,
    pub version: u32,
    pub chain_id: u32,
    pub inputs: Vec<TxInputWire>,
    pub outputs: Vec<TxOutputWire>,
    pub fee: u64,
    pub tx_hash: [u8; 32],
    pub poh_tick: u64,
    pub locktime: u64,
}

impl WireFormat<crate::core::transaction::Transaction> for TxWire {
    fn to_core(&self) -> Result<crate::core::transaction::Transaction, WireError> {
        let inputs: Result<Vec<_>, _> = self.inputs.iter().map(|i| i.to_core()).collect();
        let outputs: Result<Vec<_>, _> = self.outputs.iter().map(|o| o.to_core()).collect();
        Ok(crate::core::transaction::Transaction {
            version: self.version,
            chain_id: self.chain_id,
            inputs: inputs?,
            outputs: outputs?,
            fee: self.fee,
            tx_hash: Hash(self.tx_hash),
            poh_tick: self.poh_tick,
            locktime: self.locktime,
        })
    }

    fn from_core(tx: &crate::core::transaction::Transaction) -> Result<Self, WireError> {
        let inputs: Result<Vec<_>, _> = tx.inputs.iter().map(|i| TxInputWire::from_core(i)).collect();
        let outputs: Result<Vec<_>, _> = tx.outputs.iter().map(|o| TxOutputWire::from_core(o)).collect();
        Ok(TxWire {
            wire_version: WIRE_VERSION,
            version: tx.version,
            chain_id: tx.chain_id,
            inputs: inputs?,
            outputs: outputs?,
            fee: tx.fee,
            tx_hash: tx.tx_hash.0,
            poh_tick: tx.poh_tick,
            locktime: tx.locktime,
        })
    }
}

// ============================================================
// TX INPUT WIRE
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInputWire {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    pub nullifier: [u8; 32],
    pub public_key: [u8; 32],
    pub signature: Vec<u8>,
    pub signed_hash: [u8; 32],
    pub nonce: u64,
}

impl WireFormat<crate::core::transaction::TxInput> for TxInputWire {
    fn to_core(&self) -> Result<crate::core::transaction::TxInput, WireError> {
        if self.signature.len() > MAX_SIGNATURE_SIZE {
            return Err(WireError::SignatureTooLarge(self.signature.len()));
        }
        Ok(crate::core::transaction::TxInput {
            tx_hash: Hash(self.tx_hash),
            output_index: self.output_index,
            nullifier: Hash(self.nullifier),
            signature: self.signature.clone(),
            public_key: PublicKey::from_bytes(self.public_key).map_err(|_| WireError::InvalidPublicKey)?,
            signed_hash: Hash(self.signed_hash),
            nonce: self.nonce,
        })
    }

    fn from_core(input: &crate::core::transaction::TxInput) -> Result<Self, WireError> {
        if input.signature.len() > MAX_SIGNATURE_SIZE {
            return Err(WireError::SignatureTooLarge(input.signature.len()));
        }
        Ok(TxInputWire {
            tx_hash: input.tx_hash.0,
            output_index: input.output_index,
            nullifier: input.nullifier.0,
            public_key: input.public_key.to_bytes(),
            signature: input.signature.clone(),
            signed_hash: input.signed_hash.0,
            nonce: input.nonce,
        })
    }
}

// ============================================================
// TX OUTPUT WIRE
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutputWire {
    pub amount: u64,
    pub owner: [u8; 32],
    pub amount_commitment_bytes: [u8; 32],
    pub tag_commitment_bytes: [u8; 32],
    pub nullifier: [u8; 32],
    pub serial: u64,
    pub zk_proof_data: Vec<u8>,
    pub zk_proof_scheme: u16,
    pub zk_proof_version: u16,
    pub tx_hash: [u8; 32],
    pub view_key_public: [u8; 32],
    pub encrypted_amount: [u8; 8],
    pub auth_tag: [u8; 8],
    pub restriction_level: u64,
    pub output_index: u32,
}

impl WireFormat<crate::core::transaction::TxOutput> for TxOutputWire {
    fn to_core(&self) -> Result<crate::core::transaction::TxOutput, WireError> {
        Ok(crate::core::transaction::TxOutput {
            amount: self.amount,
            owner: PublicKey::from_bytes(self.owner).map_err(|_| WireError::InvalidPublicKey)?,
            amount_commitment: AmountCommitment::dummy(),
            tag_commitment: TagCommitment::dummy(),
            nullifier: Hash(self.nullifier),
            serial: self.serial,
            zk_proof: ZkProof {
                scheme: ProofScheme::from_wire_code(self.zk_proof_scheme)?,
                version: self.zk_proof_version,
                data: self.zk_proof_data.clone(),
            },
            tx_hash: Hash(self.tx_hash),
            view_key_public: self.view_key_public,
            encrypted_amount: self.encrypted_amount,
            auth_tag: self.auth_tag,
            restriction_level: self.restriction_level,
            output_index: self.output_index,
        })
    }

    fn from_core(output: &crate::core::transaction::TxOutput) -> Result<Self, WireError> {
        Ok(TxOutputWire {
            amount: output.amount,
            owner: output.owner.to_bytes(),
            amount_commitment_bytes: output.amount_commitment.dummy_or_bytes(),
            tag_commitment_bytes: [0u8; 32],
            nullifier: output.nullifier.0,
            serial: output.serial,
            zk_proof_data: output.zk_proof.data.clone(),
            zk_proof_scheme: output.zk_proof.scheme.to_wire_code(),
            zk_proof_version: output.zk_proof.version,
            tx_hash: output.tx_hash.0,
            view_key_public: output.view_key_public,
            encrypted_amount: output.encrypted_amount,
            auth_tag: output.auth_tag,
            restriction_level: output.restriction_level,
            output_index: output.output_index,
        })
    }
}

// ============================================================
// HASH CODEC TRAIT
// ============================================================

trait HashCodec {
    fn to_wire(&self) -> [u8; 32];
    fn from_wire(bytes: [u8; 32]) -> Self;
}

impl HashCodec for Hash {
    fn to_wire(&self) -> [u8; 32] { self.0 }
    fn from_wire(bytes: [u8; 32]) -> Self { Hash(bytes) }
}

// ============================================================
// AMOUNT COMMITMENT HELPER
// ============================================================

impl AmountCommitment {
    fn dummy_or_bytes(&self) -> [u8; 32] {
        [0u8; 32]
    }
}

// ============================================================
// МИГРАЦИЯ WIRE ВЕРСИЙ
// ============================================================

pub fn detect_wire_version(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 2 { return None; }
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub fn migrate_block(bytes: &[u8]) -> Result<BlockWire, WireError> {
    let version = detect_wire_version(bytes).ok_or(WireError::DeserializationFailed("too short".into()))?;
    match version {
        WIRE_VERSION => bincode::deserialize::<BlockWire>(bytes).map_err(|e| WireError::DeserializationFailed(e.to_string())),
        _ => Err(WireError::DeserializationFailed(format!("unsupported wire version: {}", version))),
    }
}
