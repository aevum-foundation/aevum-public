use serde::{Deserialize, Serialize};
use crate::core::jt_utxo::{JtUtxo, ZkProof};
use crate::crypto::hash::{AmountCommitment, Hash, TagCommitment};
use crate::crypto::keys::PublicKey;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub tx_hash: Hash,
    pub output_index: u16,
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
}

impl TxOutput {
    pub fn from_jt_utxo(utxo: &JtUtxo) -> Self {
        TxOutput {
            amount: utxo.amount,
            owner: utxo.owner().clone(),
            amount_commitment: *utxo.amount_commitment(),
            tag_commitment: utxo.tag_commitment().clone(),
            nullifier: *utxo.nullifier(),
            serial: utxo.serial(),
            zk_proof: utxo.zk_proof().clone(),
            tx_hash: utxo.tx_hash,
            view_key_public: [0u8; 32],
            encrypted_amount: [0u8; 8],
            auth_tag: [0u8; 8],
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u8,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub tx_hash: Hash,
    pub poh_tick: u64,
}

impl Transaction {
    pub const CURRENT_VERSION: u8 = 0x01;
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_TRANSACTION_V1";

    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>, poh_tick: u64) -> Self {
        let mut tx = Transaction { version: Self::CURRENT_VERSION, inputs, outputs, tx_hash: Hash::zero(), poh_tick };
        tx.tx_hash = tx.compute_hash();
        tx
    }

    pub fn sign_input(&mut self, prev_tx_hash: &Hash, output_index: u16, signature: Vec<u8>, public_key: PublicKey) -> Result<(), &'static str> {
        for input in &mut self.inputs {
            if input.tx_hash == *prev_tx_hash && input.output_index == output_index {
                input.signature = signature;
                input.public_key = public_key;
                input.signed_hash = self.tx_hash;
                return Ok(());
            }
        }
        Err("Input not found")
    }

    fn compute_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&[self.version]);
        hasher.update(&self.poh_tick.to_le_bytes());
        for input in &self.inputs {
            hasher.update(input.tx_hash.as_bytes());
            hasher.update(&input.output_index.to_le_bytes());
        }
        for output in &self.outputs {
            hasher.update(output.owner.as_bytes());
            hasher.update(output.amount_commitment.as_bytes());
            hasher.update(output.tag_commitment.as_bytes());
            hasher.update(output.nullifier.as_bytes());
            hasher.update(&output.serial.to_le_bytes());
        }
        Hash(hasher.finalize().into())
    }

    pub fn verify_balance(&self) -> bool { !self.outputs.is_empty() }
    pub fn output_count(&self) -> usize { self.outputs.len() }
    pub fn input_count(&self) -> usize { self.inputs.len() }
}
