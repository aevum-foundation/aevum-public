//! Wire v9 — Two-Phase with StateRoot newtype (10/10)

use serde::{Serialize, Deserialize, Serializer, Deserializer};
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use crate::core::dna::TokenDNA;
use crate::core::transaction::TransactionType;
use crate::core::block::{SettlementCheckpoint, StateRoot, StatePreview, BlockCandidate, Block};

pub const WIRE_VERSION: u16 = 9;
pub const MAX_TX_INPUTS: usize = 1024;
pub const MAX_TX_OUTPUTS: usize = 1024;
pub const MAX_WITNESSES: usize = 32;
pub const MAX_WIRE_BLOCK_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_TXS_PER_BLOCK: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockWire {
    pub wire_version: u16, pub block_hash: [u8; 32], pub prev_hash: [u8; 32],
    pub height: u64, pub poh_tick_start: u64, pub poh_tick_end: u64,
    pub transactions_root: [u8; 32],
    pub transactions: BoundedVec<TxWire, MAX_TXS_PER_BLOCK>,
    pub state_root: [u8; 32], pub total_supply: u64,
    pub is_presence_block: bool, pub block_size: usize,
    pub settlement_checkpoint: Option<SettlementCheckpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxWire {
    pub version: u32, pub chain_id: u32, pub tx_type: u8,
    pub inputs: BoundedVec<TxInputWire, MAX_TX_INPUTS>,
    pub outputs: BoundedVec<TxOutputWire, MAX_TX_OUTPUTS>,
    pub fee: u64, pub poh_tick: u64, pub locktime: u64,
    pub heartbeat_witnesses: BoundedVec<Vec<u8>, MAX_WITNESSES>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInputWire {
    pub tx_hash: [u8; 32], pub output_index: u32, pub nullifier: [u8; 32],
    pub signature: Vec<u8>, pub public_key: [u8; 32],
    pub signed_hash: [u8; 32], pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutputWire {
    pub amount: u64, pub owner: [u8; 32],
    pub amount_commitment: [u8; 32], pub tag_commitment: [u8; 32],
    pub nullifier: [u8; 32], pub serial: u64, pub zk_proof: Vec<u8>,
    pub tx_hash: [u8; 32], pub view_key_public: [u8; 32],
    pub encrypted_amount: [u8; 8], pub auth_tag: [u8; 8],
    pub restriction_level: u64, pub output_index: u32,
    pub taint_distance: u16, pub taint_origin: u64, pub taint_timestamp: u64,
    pub dna: TokenDNA,
}

#[derive(Debug)]
pub enum WireError { VersionMismatch, BlockTooLarge, TxTooLarge, TooManyTx, TooManyInputs, TooManyOutputs, InvalidTxType, Deserialization(String) }
impl std::fmt::Display for WireError { fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { match self { Self::VersionMismatch => write!(f, "wire version mismatch"), _ => write!(f, "{:?}", self) } } }
impl std::error::Error for WireError {}

#[derive(Clone, Debug)]
pub struct BoundedVec<T, const MAX: usize> { pub items: Vec<T> }
impl<T, const MAX: usize> Serialize for BoundedVec<T, MAX> where T: Serialize { fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> { self.items.serialize(s) } }
impl<'de, T, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX> where T: Deserialize<'de> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let items = Vec::<T>::deserialize(d)?;
        if items.len() > MAX { return Err(serde::de::Error::custom("bounded vec overflow")); }
        Ok(Self { items })
    }
}

pub trait WireDecode<T> { fn wire_decode(&self) -> Result<T, WireError>; }

impl WireDecode<Block> for BlockWire {
    fn wire_decode(&self) -> Result<Block, WireError> {
        if self.wire_version != WIRE_VERSION { return Err(WireError::VersionMismatch); }
        if self.block_size > MAX_WIRE_BLOCK_SIZE { return Err(WireError::BlockTooLarge); }
        let txs = self.transactions.items.iter().map(|t| t.wire_decode()).collect::<Result<Vec<_>, _>>()?;
        let candidate = BlockCandidate {
            prev_hash: Hash(self.prev_hash), height: self.height,
            poh_tick_start: self.poh_tick_start, poh_tick_end: self.poh_tick_end,
            transactions: txs, is_presence_block: self.is_presence_block,
            settlement_checkpoint: self.settlement_checkpoint.clone(),
        };
        let preview = StatePreview { state_root: StateRoot(Hash(self.state_root)), new_total_supply: self.total_supply };
        let block = Block::from_candidate(candidate, &preview).map_err(|e| WireError::Deserialization(e.to_string()))?;
        if block.block_hash().0 != self.block_hash { return Err(WireError::Deserialization("block hash mismatch".into())); }
        Ok(block)
    }
}

impl WireDecode<crate::core::transaction::Transaction> for TxWire {
    fn wire_decode(&self) -> Result<crate::core::transaction::Transaction, WireError> {
        let tx_type = match self.tx_type { 0 => TransactionType::Standard, 1 => TransactionType::Coinbase, 2 => TransactionType::Heartbeat, _ => return Err(WireError::InvalidTxType) };
        let inputs = self.inputs.items.iter().map(|i| i.wire_decode()).collect::<Result<Vec<_>, _>>()?;
        let outputs = self.outputs.items.iter().map(|o| o.wire_decode()).collect::<Result<Vec<_>, _>>()?;
        let mut tx = crate::core::transaction::Transaction {
            version: self.version, chain_id: self.chain_id, tx_type,
            inputs, outputs, fee: self.fee,
            tx_hash: Hash::zero(), poh_tick: self.poh_tick, locktime: self.locktime,
            heartbeat_witnesses: self.heartbeat_witnesses.items.clone(),
        };
        tx.tx_hash = tx.recompute_hash();
        Ok(tx)
    }
}

impl WireDecode<crate::core::transaction::TxInput> for TxInputWire {
    fn wire_decode(&self) -> Result<crate::core::transaction::TxInput, WireError> {
        Ok(crate::core::transaction::TxInput {
            tx_hash: Hash(self.tx_hash), output_index: self.output_index,
            nullifier: Hash(self.nullifier), signature: self.signature.clone(),
            public_key: PublicKey::from_bytes(self.public_key).map_err(|_| WireError::Deserialization("invalid input pubkey".into()))?,
            signed_hash: Hash(self.signed_hash), nonce: self.nonce,
        })
    }
}

impl WireDecode<crate::core::transaction::TxOutput> for TxOutputWire {
    fn wire_decode(&self) -> Result<crate::core::transaction::TxOutput, WireError> {
        Ok(crate::core::transaction::TxOutput {
            amount: self.amount,
            owner: PublicKey::from_bytes(self.owner).map_err(|_| WireError::Deserialization("invalid output owner".into()))?,
            amount_commitment: crate::crypto::hash::AmountCommitment(self.amount_commitment),
            tag_commitment: crate::crypto::hash::TagCommitment(self.tag_commitment),
            nullifier: Hash(self.nullifier), serial: self.serial,
            zk_proof: crate::core::jt_utxo::ZkProof { scheme: crate::core::jt_utxo::ProofScheme::Halo2, version: 1, data: self.zk_proof.clone() },
            tx_hash: Hash(self.tx_hash),
            view_key_public: self.view_key_public,
            encrypted_amount: self.encrypted_amount, auth_tag: self.auth_tag,
            restriction_level: self.restriction_level, output_index: self.output_index,
            taint_distance: self.taint_distance, taint_origin: self.taint_origin, taint_timestamp: self.taint_timestamp,
            dna: self.dna.clone(),
            dna_range_id: None,
        })
    }
}
