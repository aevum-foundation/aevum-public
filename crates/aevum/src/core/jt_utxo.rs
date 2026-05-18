use serde::{Deserialize, Serialize};
use crate::crypto::hash::{AmountCommitment, Hash, TagCommitment};
use crate::crypto::keys::PublicKey;
use std::sync::Arc;

// ============================================================
// ЕДИНЫЕ КОНСТАНТЫ RESTRICTION LEVEL
// ============================================================

pub const CATEGORY_MASK: u64 = 0xF00;

pub const CAT_COINBASE: u64    = 0x000;
pub const CAT_JURISDICTION: u64 = 0x100;
pub const CAT_GLOBAL: u64      = 0x200;
pub const CAT_COMPUTE: u64     = 0x300;
pub const CAT_SPECIAL: u64     = 0xF00;

pub const RESTRICTION_COINBASE: u64       = CAT_COINBASE | 0x01;
pub const RESTRICTION_GLOBAL_CLEAN: u64   = CAT_GLOBAL | 0x00;
pub const RESTRICTION_PROVENANCE_NULL: u64 = CAT_SPECIAL | 0xFF;
pub const RESTRICTION_COMPUTE_BASE: u64    = CAT_COMPUTE | 0x01;

pub fn is_coinbase(level: u64) -> bool { level & CATEGORY_MASK == CAT_COINBASE }
pub fn is_jurisdiction(level: u64) -> bool { level & CATEGORY_MASK == CAT_JURISDICTION }
pub fn is_global(level: u64) -> bool { level & CATEGORY_MASK == CAT_GLOBAL }
pub fn is_compute(level: u64) -> bool { level & CATEGORY_MASK == CAT_COMPUTE }
pub fn is_spendable(level: u64, current_height: u64, created_height: u64, maturity_blocks: u64) -> bool {
    if is_coinbase(level) {
        current_height.saturating_sub(created_height) >= maturity_blocks
    } else {
        true
    }
}

// ============================================================
// ТИПЫ
// ============================================================

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RestrictionLevel {
    GlobalClean,
    Restricted { allowed: Vec<JurisdictionCode> },
    ProvenanceNull,
}

impl RestrictionLevel {
    pub fn serialize(&self) -> Vec<u8> { serialize_level(self) }
    
    pub fn to_u64(&self) -> u64 {
        match self {
            RestrictionLevel::GlobalClean => RESTRICTION_GLOBAL_CLEAN,
            RestrictionLevel::ProvenanceNull => RESTRICTION_PROVENANCE_NULL,
            RestrictionLevel::Restricted { allowed } => {
                if let Some(first) = allowed.first() {
                    CAT_JURISDICTION | ((first[0] as u64) & 0xFF)
                } else {
                    CAT_JURISDICTION
                }
            }
        }
    }
}

pub type JurisdictionCode = [u8; 4];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofScheme { Halo2 = 0, Stark = 1 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof {
    pub scheme: ProofScheme,
    pub version: u16,
    pub data: Vec<u8>,
}

impl ZkProof {
    pub fn empty() -> Self {
        ZkProof { scheme: ProofScheme::Halo2, version: 0, data: Vec::new() }
    }
    
    pub fn is_valid(&self) -> bool {
        !self.data.is_empty() && self.version > 0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UtxoError {
    #[error("Amount must be positive, got {0}")]
    ZeroAmount(u64),
    #[error("Blinding factor cannot be zero")]
    ZeroBlinding,
    #[error("Tag blinding factor cannot be zero")]
    ZeroTagBlinding,
    #[error("Owner key cannot be zero")]
    ZeroKey,
    #[error("Duplicate nullifier")]
    DuplicateNullifier,
}

// ============================================================
// JT-UTXO (ПОЛНАЯ ИНКАПСУЛЯЦИЯ)
// ============================================================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JtUtxo {
    // Публичные поля (только для чтения снаружи)
    pub(crate) amount_commitment: AmountCommitment,
    pub(crate) tag_commitment: TagCommitment,
    pub(crate) serial: u64,
    pub(crate) nullifier: Hash,
    pub(crate) tx_hash: Hash,
    pub(crate) output_index: usize,
    pub(crate) owner: PublicKey,
    pub(crate) zk_proof: ZkProof,
    
    // Приватные поля (для кошелька)
    pub(crate) amount: u64,
    pub(crate) restriction_level: u64,
    pub(crate) created_height: u64,
}

// Локальная запись для сохранения в БД (с полной сериализацией)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalUtxoRecord {
    pub utxo: JtUtxo,
    pub amount: u64,
    pub restriction_level: u64,
    pub created_height: u64,
    pub output_index: usize,
}

impl JtUtxo {
    fn build(
        owner: PublicKey,
        amount: u64,
        amount_blinding: &[u8; 32],
        tag_blinding: &[u8; 32],
        serial: u64,
        created_height: u64,
        level: RestrictionLevel,
        tx_hash: Hash,
    ) -> Result<Self, UtxoError> {
        if amount == 0 { return Err(UtxoError::ZeroAmount(amount)); }
        if amount_blinding == &[0u8; 32] { return Err(UtxoError::ZeroBlinding); }
        if tag_blinding == &[0u8; 32] { return Err(UtxoError::ZeroTagBlinding); }
        if owner.to_bytes() == [0u8; 32] { return Err(UtxoError::ZeroKey); }
        
        let amount_commitment = AmountCommitment::commit(amount, amount_blinding);
        let serialized = level.serialize();
        let tag_commitment = TagCommitment::commit(&serialized, tag_blinding);
        let nullifier = Hash::from_utxo_components(&owner, &amount_commitment, &tag_commitment, serial);
        let restriction_u64 = level.to_u64();
        
        Ok(Self {
            amount, restriction_level: restriction_u64, created_height,
            amount_commitment, tag_commitment, serial, nullifier,
            tx_hash, output_index: 0, owner, zk_proof: ZkProof::empty(),
        })
    }

    pub fn new_global_clean(
        owner: PublicKey, amount: u64, amount_blinding: &[u8; 32],
        tag_blinding: &[u8; 32], serial: u64, created_height: u64, tx_hash: Hash,
    ) -> Result<Self, UtxoError> {
        Self::build(owner, amount, amount_blinding, tag_blinding, serial, created_height, RestrictionLevel::GlobalClean, tx_hash)
    }

    pub fn new_restricted(
        owner: PublicKey, amount: u64, amount_blinding: &[u8; 32],
        tag_blinding: &[u8; 32], serial: u64, created_height: u64,
        allowed: Vec<JurisdictionCode>, tx_hash: Hash,
    ) -> Result<Self, UtxoError> {
        Self::build(owner, amount, amount_blinding, tag_blinding, serial, created_height, RestrictionLevel::Restricted { allowed }, tx_hash)
    }

    pub fn new_provenance_null(
        owner: PublicKey, amount: u64, amount_blinding: &[u8; 32],
        tag_blinding: &[u8; 32], serial: u64, created_height: u64, tx_hash: Hash,
    ) -> Result<Self, UtxoError> {
        Self::build(owner, amount, amount_blinding, tag_blinding, serial, created_height, RestrictionLevel::ProvenanceNull, tx_hash)
    }

    pub fn from_parts(
        tx_hash: Hash, owner: PublicKey, amount: u64,
        amount_commitment: AmountCommitment, tag_commitment: TagCommitment,
        serial: u64, created_height: u64, nullifier: Hash, zk_proof: ZkProof,
        restriction_level: u64, output_index: usize,
    ) -> Self {
        JtUtxo {
            amount, restriction_level, created_height,
            amount_commitment, tag_commitment, serial, nullifier,
            tx_hash, output_index, owner, zk_proof,
        }
    }

    pub fn from_tx_output(
        output: &crate::core::transaction::TxOutput, tx_hash: Hash, created_height: u64,
    ) -> Self {
        JtUtxo::from_parts(
            tx_hash, output.owner.clone(), output.amount,
            output.amount_commitment, output.tag_commitment.clone(),
            output.serial, created_height, output.nullifier, output.zk_proof.clone(),
            output.restriction_level, output.output_index as usize,
        )
    }

    // Геттеры (единственный способ доступа к полям)
    pub fn owner(&self) -> &PublicKey { &self.owner }
    pub fn amount(&self) -> u64 { self.amount }
    pub fn restriction_level(&self) -> u64 { self.restriction_level }
    pub fn created_height(&self) -> u64 { self.created_height }
    pub fn amount_commitment(&self) -> &AmountCommitment { &self.amount_commitment }
    pub fn tag_commitment(&self) -> &TagCommitment { &self.tag_commitment }
    pub fn serial(&self) -> u64 { self.serial }
    pub fn nullifier(&self) -> &Hash { &self.nullifier }
    pub fn tx_hash(&self) -> &Hash { &self.tx_hash }
    pub fn output_index(&self) -> usize { self.output_index }
    pub fn zk_proof(&self) -> &ZkProof { &self.zk_proof }
    
    pub fn is_spendable(&self, current_height: u64, maturity_blocks: u64) -> bool {
        is_spendable(self.restriction_level, current_height, self.created_height, maturity_blocks)
    }

    /// Для сохранения в локальную БД кошелька (полная сериализация)
    pub fn to_local_record(&self) -> LocalUtxoRecord {
        LocalUtxoRecord {
            amount: self.amount,
            restriction_level: self.restriction_level,
            created_height: self.created_height,
            output_index: self.output_index,
            utxo: self.clone(),
        }
    }

    /// Восстановление из локальной БД кошелька
    pub fn from_local_record(record: LocalUtxoRecord) -> Self {
        let mut utxo = record.utxo;
        utxo.amount = record.amount;
        utxo.restriction_level = record.restriction_level;
        utxo.created_height = record.created_height;
        utxo.output_index = record.output_index;
        utxo
    }
}

pub fn serialize_level(level: &RestrictionLevel) -> Vec<u8> {
    match level {
        RestrictionLevel::GlobalClean => vec![0x00],
        RestrictionLevel::ProvenanceNull => vec![0xFF],
        RestrictionLevel::Restricted { allowed } => {
            let mut data = vec![0x01, allowed.len() as u8];
            for code in allowed { data.extend_from_slice(code); }
            data
        }
    }
}
