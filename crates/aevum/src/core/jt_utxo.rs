use serde::{Deserialize, Serialize};
use crate::crypto::hash::{AmountCommitment, Hash, TagCommitment};
use crate::crypto::keys::PublicKey;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RestrictionLevel {
    GlobalClean,
    Restricted { allowed: Vec<JurisdictionCode> },
    ProvenanceNull,
}

impl RestrictionLevel { pub fn serialize(&self) -> Vec<u8> { serialize_level(self) } }

pub type JurisdictionCode = [u8; 4];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofScheme { Halo2 = 0, Stark = 1 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof { pub scheme: ProofScheme, pub version: u16, pub data: Vec<u8> }

impl ZkProof { pub fn empty() -> Self { ZkProof { scheme: ProofScheme::Halo2, version: 0, data: Vec::new() } } }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JtUtxo {
    pub amount: u64,
    pub tx_hash: Hash,
    owner: PublicKey,
    amount_commitment: AmountCommitment,
    tag_commitment: TagCommitment,
    serial: u64,
    nullifier: Hash,
    zk_proof: ZkProof,
}

impl JtUtxo {
    fn build(owner: PublicKey, amount: u64, amount_blinding: &[u8; 32], tag_blinding: &[u8; 32], serial: u64, level: RestrictionLevel, tx_hash: Hash) -> Self {
        let amount_commitment = AmountCommitment::commit(amount, amount_blinding);
        let serialized = level.serialize();
        let tag_commitment = TagCommitment::commit(&serialized, tag_blinding);
        let nullifier = Hash::from_utxo_components(&owner, &amount_commitment, &tag_commitment, serial);
        Self { amount, tx_hash, owner, amount_commitment, tag_commitment, serial, nullifier, zk_proof: ZkProof::empty() }
    }

    pub fn new_global_clean(owner: PublicKey, amount: u64, amount_blinding: &[u8; 32], tag_blinding: &[u8; 32], serial: u64, tx_hash: Hash) -> Self {
        Self::build(owner, amount, amount_blinding, tag_blinding, serial, RestrictionLevel::GlobalClean, tx_hash)
    }

    pub fn new_restricted(owner: PublicKey, amount: u64, amount_blinding: &[u8; 32], tag_blinding: &[u8; 32], serial: u64, allowed: Vec<JurisdictionCode>, tx_hash: Hash) -> Self {
        Self::build(owner, amount, amount_blinding, tag_blinding, serial, RestrictionLevel::Restricted { allowed }, tx_hash)
    }

    pub fn new_provenance_null(owner: PublicKey, amount: u64, amount_blinding: &[u8; 32], tag_blinding: &[u8; 32], serial: u64, tx_hash: Hash) -> Self {
        Self::build(owner, amount, amount_blinding, tag_blinding, serial, RestrictionLevel::ProvenanceNull, tx_hash)
    }

    pub fn from_parts(tx_hash: Hash, owner: PublicKey, amount: u64, amount_commitment: AmountCommitment, tag_commitment: TagCommitment, serial: u64, nullifier: Hash, zk_proof: ZkProof) -> Self {
        JtUtxo { amount, tx_hash, owner, amount_commitment, tag_commitment, serial, nullifier, zk_proof }
    }

    pub fn from_tx_output(output: &crate::core::transaction::TxOutput, tx_hash: Hash) -> Self {
        JtUtxo::from_parts(tx_hash, output.owner.clone(), output.amount, output.amount_commitment, output.tag_commitment.clone(), output.serial, output.nullifier, output.zk_proof.clone())
    }

    pub fn owner(&self) -> &PublicKey { &self.owner }
    pub fn amount_commitment(&self) -> &AmountCommitment { &self.amount_commitment }
    pub fn tag_commitment(&self) -> &TagCommitment { &self.tag_commitment }
    pub fn serial(&self) -> u64 { self.serial }
    pub fn nullifier(&self) -> &Hash { &self.nullifier }
    pub fn zk_proof(&self) -> &ZkProof { &self.zk_proof }
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
