use serde::{Deserialize, Serialize};
use crate::crypto::hash::{AmountCommitment, Hash, TagCommitment};
use crate::crypto::keys::PublicKey;
use crate::core::jt_utxo::{JtUtxo, ZkProof};
use crate::core::dna::TokenDNA;
use std::collections::HashSet;

pub const CHAIN_ID_MAINNET: u32 = 2;
pub const COINBASE_RESTRICTION_LEVEL: u64 = 0x2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TransactionType { Standard = 0, Coinbase = 1, Heartbeat = 2 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub tx_hash: Hash, pub output_index: u32, pub nullifier: Hash,
    pub signature: Vec<u8>, pub public_key: PublicKey, pub signed_hash: Hash, pub nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub amount: u64, pub owner: PublicKey,
    pub amount_commitment: AmountCommitment, pub tag_commitment: TagCommitment,
    pub nullifier: Hash, pub serial: u64, pub zk_proof: ZkProof, pub tx_hash: Hash,
    pub view_key_public: [u8; 32], pub encrypted_amount: [u8; 8], pub auth_tag: [u8; 8],
    pub restriction_level: u64, pub output_index: u32,
    pub taint_distance: u16, pub taint_origin: u64, pub taint_timestamp: u64,
    #[serde(default)]
    pub dna: TokenDNA,
    #[serde(default)]
    pub dna_range_id: Option<Hash>,
}

impl TxOutput {
    pub fn from_jt_utxo(utxo: &JtUtxo, index: u32) -> Self {
        TxOutput {
            amount: utxo.amount(), owner: utxo.owner().clone(),
            amount_commitment: *utxo.amount_commitment(), tag_commitment: utxo.tag_commitment().clone(),
            nullifier: *utxo.nullifier(), serial: utxo.serial(),
            zk_proof: utxo.zk_proof().clone(), tx_hash: *utxo.tx_hash(),
            view_key_public: [0u8; 32], encrypted_amount: [0u8; 8], auth_tag: [0u8; 8],
            restriction_level: utxo.restriction_level(), output_index: index,
            taint_distance: utxo.taint_distance, taint_origin: utxo.taint_origin, taint_timestamp: utxo.taint_timestamp,
            dna: utxo.dna.clone(),
            dna_range_id: None,
        }
    }

    pub fn new_coinbase(owner: PublicKey, amount: u64, serial: u64, output_index: u32) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_COINBASE_NULLIFIER_V1"); h.update(owner.as_bytes()); h.update(&serial.to_le_bytes());
        TxOutput {
            amount, owner,
            amount_commitment: AmountCommitment([0u8; 32]), tag_commitment: TagCommitment([0u8; 32]),
            nullifier: Hash(h.finalize().into()), serial,
            zk_proof: ZkProof::empty(), tx_hash: Hash::zero(),
            view_key_public: [0u8; 32], encrypted_amount: [0u8; 8], auth_tag: [0u8; 8],
            restriction_level: COINBASE_RESTRICTION_LEVEL, output_index,
            taint_distance: 0, taint_origin: 0x2000, taint_timestamp: 0,
            dna: TokenDNA::default(),
            dna_range_id: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32, pub chain_id: u32, pub tx_type: TransactionType,
    pub inputs: Vec<TxInput>, pub outputs: Vec<TxOutput>,
    pub fee: u64, pub tx_hash: Hash, pub poh_tick: u64, pub locktime: u64,
    #[serde(default)] pub heartbeat_witnesses: Vec<Vec<u8>>,
}

impl Transaction {
    pub fn new_raw(v: u32, c: u32, inputs: Vec<TxInput>, outputs: Vec<TxOutput>, fee: u64, poh: u64, lock: u64) -> Self {
        Transaction { version: v, chain_id: c, tx_type: TransactionType::Standard, inputs, outputs, fee, tx_hash: Hash::zero(), poh_tick: poh, locktime: lock, heartbeat_witnesses: Vec::new() }
    }
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>, fee: u64) -> Self { let mut tx = Self::new_raw(1, CHAIN_ID_MAINNET, inputs, outputs, fee, 0, 0); tx.compute_hash(); tx }
    pub fn new_heartbeat(witnesses: Vec<Vec<u8>>, chain_id: u32) -> Self { let mut tx = Transaction { version: 1, chain_id, tx_type: TransactionType::Heartbeat, inputs: Vec::new(), outputs: Vec::new(), fee: 0, tx_hash: Hash::zero(), poh_tick: 0, locktime: 0, heartbeat_witnesses: witnesses }; tx.compute_hash(); tx }
    pub fn new_coinbase(outputs: Vec<TxOutput>, poh: u64, chain_id: u32) -> Self { let mut tx = Transaction { version: 1, chain_id, tx_type: TransactionType::Coinbase, inputs: Vec::new(), outputs, fee: 0, tx_hash: Hash::zero(), poh_tick: poh, locktime: 0, heartbeat_witnesses: Vec::new() }; tx.compute_hash(); tx }

    pub fn compute_hash(&mut self) { self.tx_hash = self.recompute_hash(); }

    pub fn recompute_hash(&self) -> Hash {
        let mut h = blake3::Hasher::new(); h.update(b"AEVUM_TX_V4");
        h.update(&self.chain_id.to_le_bytes()); h.update(&self.version.to_le_bytes()); h.update(&[self.tx_type as u8]);
        h.update(&(self.inputs.len() as u32).to_le_bytes());
        for i in &self.inputs { h.update(i.tx_hash.as_bytes()); h.update(&i.output_index.to_le_bytes()); h.update(i.nullifier.as_bytes()); h.update(i.public_key.as_bytes()); h.update(i.signed_hash.as_bytes()); h.update(&i.nonce.to_le_bytes()); }
        h.update(&(self.outputs.len() as u32).to_le_bytes());
        for o in &self.outputs { h.update(&o.amount.to_le_bytes()); h.update(o.owner.as_bytes()); h.update(o.amount_commitment.as_bytes()); h.update(o.tag_commitment.as_bytes()); h.update(o.nullifier.as_bytes()); h.update(&o.serial.to_le_bytes()); h.update(&o.restriction_level.to_le_bytes()); h.update(&o.output_index.to_le_bytes()); h.update(&o.taint_distance.to_le_bytes()); h.update(&o.taint_origin.to_le_bytes()); h.update(&o.taint_timestamp.to_le_bytes()); }
        h.update(&self.fee.to_le_bytes()); h.update(&self.poh_tick.to_le_bytes()); h.update(&self.locktime.to_le_bytes());
        h.update(&(self.heartbeat_witnesses.len() as u32).to_le_bytes());
        for w in &self.heartbeat_witnesses { h.update(&(w.len() as u32).to_le_bytes()); h.update(w); }
        Hash(h.finalize().into())
    }

    pub fn is_coinbase(&self) -> bool { matches!(self.tx_type, TransactionType::Coinbase) }
    pub fn is_heartbeat(&self) -> bool { self.tx_type == TransactionType::Heartbeat }

    pub fn verify_heartbeat(&self, now: u64) -> Result<(), &'static str> {
        if !self.is_heartbeat() { return Err("not heartbeat"); }
        if self.heartbeat_witnesses.is_empty() { return Err("empty witnesses"); }
        let mut prev: Option<[u8; 32]> = None;
        for w in &self.heartbeat_witnesses {
            if w.len() < 40 { return Err("too short"); }
            let mut id = [0u8; 32]; id.copy_from_slice(&w[..32]);
            let ts = u64::from_le_bytes(w[32..40].try_into().unwrap());
            if now.saturating_sub(ts) > 180 { return Err("stale"); }
            if let Some(p) = prev { if id <= p { return Err("unsorted or duplicate"); } }
            prev = Some(id);
        }
        Ok(())
    }

    pub fn heartbeat_coverage_bps(&self, total: usize) -> u64 {
        if total == 0 { return 0; }
        let unique: HashSet<_> = self.heartbeat_witnesses.iter().collect();
        ((unique.len() as u128 * 10000) / total as u128) as u64
    }
}

impl TxInput {
    pub fn verify_signature(&self) -> bool {
        if self.signature.len() != 64 { return false; }
        let mut sig = [0u8; 64]; sig.copy_from_slice(&self.signature);
        self.public_key.verify(self.signed_hash.as_bytes(), &sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Keypair;

    #[test] fn coinbase_has_taint_zero() { let kp = Keypair::generate(); let out = TxOutput::new_coinbase(kp.public, 100, 1, 0); assert_eq!(out.taint_distance, 0); }
    #[test] fn strict_is_coinbase() { assert!(Transaction::new_coinbase(vec![], 0, CHAIN_ID_MAINNET).is_coinbase()); }
    #[test] fn heartbeat_rejects_stale() { let w = vec![{ let mut v = vec![0u8; 40]; v[32..40].copy_from_slice(&50u64.to_le_bytes()); v }]; let tx = Transaction::new_heartbeat(w, CHAIN_ID_MAINNET); assert!(tx.verify_heartbeat(300).is_err()); }
}
