use serde::{Deserialize, Serialize};
use crate::crypto::hash::{AmountCommitment, Hash, TagCommitment};
use crate::crypto::keys::PublicKey;

pub const CATEGORY_MASK: u64       = 0xF000;
pub const SUBCATEGORY_MASK: u64    = 0x0FF0;
pub const JURISDICTION_MASK: u64   = 0x000F;

pub const CAT_COINBASE: u64        = 0x0000;
pub const CAT_JURISDICTION: u64    = 0x1000;
pub const CAT_GLOBAL: u64          = 0x2000;
pub const CAT_COMPUTE: u64         = 0x3000;
pub const CAT_RISK_TAG: u64        = 0x4000;
pub const CAT_SPECIAL: u64         = 0xF000;

pub const RISK_SANCTIONS: u64      = 0x010;
pub const RISK_DARKNET: u64        = 0x020;
pub const RISK_RANSOMWARE: u64     = 0x030;
pub const RISK_STOLEN: u64         = 0x040;
pub const RISK_SCAM: u64           = 0x050;
pub const RISK_MIXER: u64          = 0x060;
pub const RISK_GAMBLING: u64       = 0x070;
pub const RISK_NO_KYC_EXCHANGE: u64 = 0x080;
pub const RISK_FRAUD_SHOP: u64     = 0x090;
pub const RISK_CHILD_ABUSE: u64    = 0x0A0;
pub const RISK_HUMAN_TRAFFICKING: u64 = 0x0B0;

pub const RESTRICTION_COINBASE: u64       = CAT_COINBASE | 0x01;
pub const RESTRICTION_GLOBAL_CLEAN: u64   = CAT_GLOBAL | 0x00;
pub const RESTRICTION_PROVENANCE_NULL: u64 = CAT_SPECIAL | 0xFF;
pub const RESTRICTION_COMPUTE_BASE: u64    = CAT_COMPUTE | 0x01;
pub const RISK_SANCTIONS_IRAN: u64   = CAT_RISK_TAG | RISK_SANCTIONS | 0x03;

pub const TAINT_DECAY_INTERVAL: u64 = 100_000;

pub fn is_coinbase(level: u64) -> bool { level & CATEGORY_MASK == CAT_COINBASE }
pub fn is_jurisdiction(level: u64) -> bool { level & CATEGORY_MASK == CAT_JURISDICTION }
pub fn is_global(level: u64) -> bool { level & CATEGORY_MASK == CAT_GLOBAL }
pub fn is_compute(level: u64) -> bool { level & CATEGORY_MASK == CAT_COMPUTE }
pub fn is_risk_tag(level: u64) -> bool { level & CATEGORY_MASK == CAT_RISK_TAG }
pub fn is_spendable(level: u64, h: u64, ch: u64, m: u64) -> bool { if is_coinbase(level) { h.saturating_sub(ch) >= m } else { true } }
pub fn get_risk_subcategory(level: u64) -> u64 { (level & SUBCATEGORY_MASK) >> 4 }
pub fn get_jurisdiction_code(level: u64) -> u8 { (level & JURISDICTION_MASK) as u8 }
pub fn decay_taint(td: u16, tt: u64, ch: u64) -> u16 { td.saturating_sub((ch.saturating_sub(tt) / TAINT_DECAY_INTERVAL) as u16) }

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RestrictionLevel { GlobalClean, Restricted { allowed: Vec<JurisdictionCode> }, ProvenanceNull }
impl RestrictionLevel {
    pub fn serialize(&self) -> Vec<u8> { serialize_level(self) }
    pub fn to_u64(&self) -> u64 {
        match self { RestrictionLevel::GlobalClean => RESTRICTION_GLOBAL_CLEAN, RestrictionLevel::ProvenanceNull => RESTRICTION_PROVENANCE_NULL, RestrictionLevel::Restricted { allowed } => if let Some(f) = allowed.first() { CAT_JURISDICTION | ((f[0] as u64) & 0xFF) } else { CAT_JURISDICTION } }
    }
}
pub type JurisdictionCode = [u8; 4];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofScheme { Halo2 = 0, Stark = 1 }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof { pub scheme: ProofScheme, pub version: u16, pub data: Vec<u8> }
impl ZkProof { pub fn empty() -> Self { ZkProof { scheme: ProofScheme::Halo2, version: 0, data: Vec::new() } } pub fn is_valid(&self) -> bool { !self.data.is_empty() && self.version > 0 } }

#[derive(Debug, thiserror::Error)]
pub enum UtxoError { #[error("Zero amount")] ZeroAmount(u64), #[error("Zero blinding")] ZeroBlinding, #[error("Zero tag")] ZeroTagBlinding, #[error("Zero key")] ZeroKey }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JtUtxo {
    pub(crate) amount_commitment: AmountCommitment, pub(crate) tag_commitment: TagCommitment, pub(crate) serial: u64,
    pub(crate) nullifier: Hash, pub(crate) tx_hash: Hash, pub(crate) output_index: usize, pub(crate) owner: PublicKey,
    pub(crate) zk_proof: ZkProof, pub(crate) amount: u64, pub(crate) restriction_level: u64, pub(crate) created_height: u64,
    pub taint_distance: u16, pub taint_origin: u64, pub taint_timestamp: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalUtxoRecord { pub utxo: JtUtxo, pub amount: u64, pub restriction_level: u64, pub created_height: u64, pub output_index: usize }

impl JtUtxo {
    fn build(owner: PublicKey, amount: u64, ab: &[u8; 32], tb: &[u8; 32], serial: u64, ch: u64, level: RestrictionLevel, tx_hash: Hash) -> Result<Self, UtxoError> {
        if amount == 0 { return Err(UtxoError::ZeroAmount(amount)); } if ab == &[0u8; 32] { return Err(UtxoError::ZeroBlinding); } if tb == &[0u8; 32] { return Err(UtxoError::ZeroTagBlinding); } if owner.to_bytes() == [0u8; 32] { return Err(UtxoError::ZeroKey); }
        let ac = AmountCommitment::commit(amount, ab); let tc = TagCommitment::commit(&level.serialize(), tb);
        let n = Hash::from_utxo_components(&owner, &ac, &tc, serial);
        Ok(Self { amount, restriction_level: level.to_u64(), created_height: ch, amount_commitment: ac, tag_commitment: tc, serial, nullifier: n, tx_hash, output_index: 0, owner, zk_proof: ZkProof::empty(), taint_distance: 0, taint_origin: CAT_GLOBAL, taint_timestamp: 0 })
    }
    pub fn new_global_clean(o: PublicKey, a: u64, ab: &[u8; 32], tb: &[u8; 32], s: u64, ch: u64, th: Hash) -> Result<Self, UtxoError> { Self::build(o, a, ab, tb, s, ch, RestrictionLevel::GlobalClean, th) }
    pub fn new_restricted(o: PublicKey, a: u64, ab: &[u8; 32], tb: &[u8; 32], s: u64, ch: u64, al: Vec<JurisdictionCode>, th: Hash) -> Result<Self, UtxoError> { Self::build(o, a, ab, tb, s, ch, RestrictionLevel::Restricted { allowed: al }, th) }
    pub fn new_provenance_null(o: PublicKey, a: u64, ab: &[u8; 32], tb: &[u8; 32], s: u64, ch: u64, th: Hash) -> Result<Self, UtxoError> { Self::build(o, a, ab, tb, s, ch, RestrictionLevel::ProvenanceNull, th) }
    pub fn from_parts(th: Hash, o: PublicKey, a: u64, ac: AmountCommitment, tc: TagCommitment, s: u64, ch: u64, n: Hash, zp: ZkProof, rl: u64, oi: usize) -> Self {
        JtUtxo { amount: a, restriction_level: rl, created_height: ch, amount_commitment: ac, tag_commitment: tc, serial: s, nullifier: n, tx_hash: th, output_index: oi, owner: o, zk_proof: zp, taint_distance: 0, taint_origin: CAT_GLOBAL, taint_timestamp: 0 }
    }
    pub fn from_tx_output(o: &crate::core::transaction::TxOutput, th: Hash, ch: u64) -> Self {
        JtUtxo::from_parts(th, o.owner.clone(), o.amount, o.amount_commitment, o.tag_commitment.clone(), o.serial, ch, o.nullifier, o.zk_proof.clone(), o.restriction_level, o.output_index as usize)
    }
    pub fn compute_taint(inputs: &[JtUtxo], ch: u64) -> (u16, u64, u64) {
        if inputs.is_empty() { return (0, CAT_GLOBAL, 0); }
        let mut md = u16::MAX; let mut wo = CAT_GLOBAL; let mut ot = u64::MAX;
        for i in inputs { let e = decay_taint(i.taint_distance, i.taint_timestamp, ch); if e < md { md = e; wo = i.taint_origin; ot = i.taint_timestamp; } }
        if md == 0 { (0, CAT_GLOBAL, 0) } else { (md.saturating_add(1), wo, ot) }
    }
    pub fn owner(&self) -> &PublicKey { &self.owner } pub fn amount(&self) -> u64 { self.amount } pub fn restriction_level(&self) -> u64 { self.restriction_level } pub fn created_height(&self) -> u64 { self.created_height }
    pub fn amount_commitment(&self) -> &AmountCommitment { &self.amount_commitment } pub fn tag_commitment(&self) -> &TagCommitment { &self.tag_commitment } pub fn serial(&self) -> u64 { self.serial }
    pub fn nullifier(&self) -> &Hash { &self.nullifier } pub fn tx_hash(&self) -> &Hash { &self.tx_hash } pub fn output_index(&self) -> usize { self.output_index } pub fn zk_proof(&self) -> &ZkProof { &self.zk_proof }
    pub fn is_spendable(&self, ch: u64, m: u64) -> bool { is_spendable(self.restriction_level, ch, self.created_height, m) }
    pub fn jurisdiction_code(&self) -> u8 { get_jurisdiction_code(self.restriction_level) }
    pub fn to_local_record(&self) -> LocalUtxoRecord { LocalUtxoRecord { amount: self.amount, restriction_level: self.restriction_level, created_height: self.created_height, output_index: self.output_index, utxo: self.clone() } }
    pub fn from_local_record(r: LocalUtxoRecord) -> Self { let mut u = r.utxo; u.amount = r.amount; u.restriction_level = r.restriction_level; u.created_height = r.created_height; u.output_index = r.output_index; u }
}

pub fn serialize_level(level: &RestrictionLevel) -> Vec<u8> {
    match level { RestrictionLevel::GlobalClean => vec![0x00], RestrictionLevel::ProvenanceNull => vec![0xFF], RestrictionLevel::Restricted { allowed } => { let mut d = vec![0x01, allowed.len() as u8]; for c in allowed { d.extend_from_slice(c); } d } }
}
