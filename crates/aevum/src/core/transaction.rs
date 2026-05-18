use serde::{Deserialize, Serialize};
use crate::crypto::hash::{AmountCommitment, Hash, TagCommitment};
use crate::crypto::keys::PublicKey;
use crate::core::jt_utxo::{JtUtxo, ZkProof};

// Chain ID для защиты от cross-chain replay
pub const CHAIN_ID_MAINNET: u32 = 1;
pub const CHAIN_ID_TESTNET: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub tx_hash: Hash,
    pub output_index: u32,
    pub nullifier: Hash,
    pub signature: Vec<u8>,
    pub public_key: PublicKey,
    pub signed_hash: Hash,
    pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub amount: u64,
    pub owner: PublicKey,
    pub amount_commitment: AmountCommitment,
    pub tag_commitment: TagCommitment,
    pub nullifier: Hash,
    pub serial: u64,
    pub zk_proof: ZkProof,
    pub tx_hash: Hash,
    pub view_key_public: [u8; 32],
    pub encrypted_amount: [u8; 8],
    pub auth_tag: [u8; 8],
    pub restriction_level: u64,
    pub output_index: u32,
}

impl TxOutput {
    pub fn from_jt_utxo(utxo: &JtUtxo, index: u32) -> Self {
        TxOutput {
            amount: utxo.amount(),
            owner: utxo.owner().clone(),
            amount_commitment: *utxo.amount_commitment(),
            tag_commitment: utxo.tag_commitment().clone(),
            nullifier: *utxo.nullifier(),
            serial: utxo.serial(),
            zk_proof: utxo.zk_proof().clone(),
            tx_hash: *utxo.tx_hash(),
            view_key_public: [0u8; 32],     // TODO: view key (Aevum HIP-0001)
            encrypted_amount: [0u8; 8],     // TODO: шифрование суммы для получателя
            auth_tag: [0u8; 8],             // TODO: аутентификация зашифрованных данных
            restriction_level: utxo.restriction_level(),
            output_index: index,
        }
    }

    pub fn new(
        owner: PublicKey, amount: u64,
        amount_commitment: AmountCommitment, tag_commitment: TagCommitment,
        nullifier: Hash, serial: u64, zk_proof: ZkProof, tx_hash: Hash,
        restriction_level: u64, output_index: u32,
    ) -> Self {
        TxOutput {
            amount, owner, amount_commitment, tag_commitment,
            nullifier, serial, zk_proof, tx_hash,
            view_key_public: [0u8; 32],
            encrypted_amount: [0u8; 8],
            auth_tag: [0u8; 8],
            restriction_level, output_index,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,          // Форвард-совместимость
    pub chain_id: u32,         // Защита от cross-chain replay
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
    pub tx_hash: Hash,
    pub poh_tick: u64,         // Proof of History tick (для временной привязки)
    pub locktime: u64,         // Блокировка по времени/высоте (HTLC)
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>, fee: u64) -> Self {
        let mut tx = Transaction {
            version: 1,
            chain_id: CHAIN_ID_TESTNET,  // По умолчанию testnet
            inputs, outputs, fee,
            tx_hash: Hash::zero(),
            poh_tick: 0,
            locktime: 0,
        };
        tx.compute_hash();
        tx
    }

    pub fn with_chain_id(mut self, chain_id: u32) -> Self {
        self.chain_id = chain_id;
        self.compute_hash();
        self
    }

    pub fn compute_hash(&mut self) {
        let mut hasher = blake3::Hasher::new();
        
        // Включаем chain_id и version в хеш (защита от replay + форвард-совместимость)
        hasher.update(&self.chain_id.to_le_bytes());
        hasher.update(&self.version.to_le_bytes());
        
        for input in &self.inputs {
            hasher.update(input.tx_hash.as_bytes());
            hasher.update(&input.output_index.to_le_bytes());
            hasher.update(input.nullifier.as_bytes());
        }
        for output in &self.outputs {
            hasher.update(&output.amount.to_le_bytes());
            hasher.update(&output.owner.to_bytes());
            hasher.update(output.amount_commitment.as_bytes());
            hasher.update(output.tag_commitment.as_bytes());
            hasher.update(output.nullifier.as_bytes());
            hasher.update(&output.serial.to_le_bytes());
            hasher.update(&output.restriction_level.to_le_bytes());  // ВКЛЮЧЁН
            hasher.update(&output.output_index.to_le_bytes());       // ВКЛЮЧЁН
        }
        hasher.update(&self.fee.to_le_bytes());
        hasher.update(&self.poh_tick.to_le_bytes());
        hasher.update(&self.locktime.to_le_bytes());
        
        self.tx_hash = Hash(hasher.finalize().into());
    }

    pub fn sign_input(
        &mut self,
        tx_hash: &Hash,
        input_index: usize,
        signature: Vec<u8>,
        public_key: PublicKey,
    ) -> Result<(), String> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds".into());
        }
        let input = &mut self.inputs[input_index];
        input.signature = signature;
        input.public_key = public_key;
        input.signed_hash = *tx_hash;
        Ok(())
    }
}

impl TxInput {
    pub fn verify_signature(&self) -> bool {
        if self.signature.is_empty() { return false; }
        // Поддержка разных схем подписи (Ed25519: 64 байта, Schnorr: 64 байта, MuSig: >64)
        if self.signature.len() < 64 { return false; }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature[..64]);
        self.public_key.verify(self.signed_hash.as_bytes(), &sig_bytes)
    }
}
