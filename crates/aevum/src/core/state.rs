use crate::core::block::Block;
use crate::core::jt_utxo::JtUtxo;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use crate::prisma::policy::Policy;
use crate::oracle::consensus::OracleConsensus;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum UtxoSetError {
    DoubleSpendInBlock, InputNotFound,
    PrismaRejection { restriction_level: u64, owner: [u8; 32] },
    InvalidTotalSupply { expected: u64, got: u64 },
    MultipleCoinbase, NoCoinbase,
}

impl std::fmt::Display for UtxoSetError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            UtxoSetError::DoubleSpendInBlock => write!(f, "Double-spend"),
            UtxoSetError::InputNotFound => write!(f, "Input not found"),
            UtxoSetError::PrismaRejection { restriction_level, owner } => write!(f, "Prisma: level={}, owner={}", restriction_level, hex::encode(owner)),
            UtxoSetError::InvalidTotalSupply { expected, got } => write!(f, "Supply: expected {}, got {}", expected, got),
            UtxoSetError::MultipleCoinbase => write!(f, "Multiple coinbase"),
            UtxoSetError::NoCoinbase => write!(f, "No coinbase"),
        }
    }
}
impl std::error::Error for UtxoSetError {}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct UtxoSet {
    utxos: HashMap<Hash, JtUtxo>,
    prisma_policies: HashMap<[u8; 32], Policy>,
    state_root: Hash, total_supply: u64,
    #[serde(skip)] dirty: bool,
    #[serde(skip)] pub oracle_consensus: Option<Arc<std::sync::Mutex<OracleConsensus>>>,
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet { utxos: HashMap::new(), prisma_policies: HashMap::new(), state_root: Hash::zero(), total_supply: 0, dirty: false, oracle_consensus: None }
    }
    pub fn with_oracle(mut self, oc: Arc<std::sync::Mutex<OracleConsensus>>) -> Self { self.oracle_consensus = Some(oc); self }
    pub fn add(&mut self, utxo: JtUtxo) { let n = *utxo.nullifier(); self.utxos.insert(n, utxo); self.dirty = true; }
    pub fn remove(&mut self, n: &Hash) -> Option<JtUtxo> { let r = self.utxos.remove(n); self.dirty = true; r }
    pub fn contains(&self, n: &Hash) -> bool { self.utxos.contains_key(n) }
    pub fn len(&self) -> usize { self.utxos.len() } pub fn is_empty(&self) -> bool { self.utxos.is_empty() }
    pub fn total_supply(&self) -> u64 { self.total_supply } pub fn get_state_root(&self) -> Hash { self.state_root }
    pub fn state_root(&mut self) -> Hash { if self.dirty { self.recompute_root(); } self.state_root }
    pub fn all(&self) -> impl Iterator<Item = (&Hash, &JtUtxo)> { self.utxos.iter() }
    pub fn set_prisma_policy(&mut self, pk: &PublicKey, p: Policy) { self.prisma_policies.insert(pk.to_bytes(), p); self.dirty = true; }
    pub fn get_prisma_policy(&self, pk: &PublicKey) -> Option<&Policy> { self.prisma_policies.get(&pk.to_bytes()) }
    pub fn remove_prisma_policy(&mut self, pk: &PublicKey) { self.prisma_policies.remove(&pk.to_bytes()); self.dirty = true; }

    pub fn check_prisma_compatibility(&self, output: &crate::core::transaction::TxOutput) -> Result<(), UtxoSetError> {
        if crate::core::jt_utxo::is_global(output.restriction_level) { return Ok(()); }
        if let Some(policy) = self.get_prisma_policy(&output.owner) {
            if !policy.policy.accepts_level(output.restriction_level) {
                return Err(UtxoSetError::PrismaRejection { restriction_level: output.restriction_level, owner: output.owner.to_bytes() });
            }
        }
        Ok(())
    }

    pub fn get_inputs_for_tx(&self, tx: &crate::core::transaction::Transaction) -> Vec<JtUtxo> {
        tx.inputs.iter().filter_map(|i| self.utxos.get(&i.nullifier).cloned()).collect()
    }

    pub fn apply_block(&mut self, block: &Block) -> Result<Hash, UtxoSetError> {
        let mut spent: Vec<&Hash> = Vec::new(); let mut cb_cnt = 0u32;
        for tx in &block.transactions {
            if tx.inputs.is_empty() { cb_cnt += 1; }
            for input in &tx.inputs {
                if spent.contains(&&input.nullifier) { return Err(UtxoSetError::DoubleSpendInBlock); }
                spent.push(&input.nullifier);
                if !self.contains(&input.nullifier) { return Err(UtxoSetError::InputNotFound); }
            }
            for output in &tx.outputs {
                self.check_prisma_compatibility(output)?;
                // Проверка через консенсус оракулов
                if let Some(ref oc) = self.oracle_consensus {
                    let consensus = oc.lock().unwrap().get_risk_consensus(&output.owner.to_bytes());
                    if consensus.is_risky() {
                        // Помечаем output как рисковый
                    }
                }
            }
        }
        if cb_cnt == 0 { return Err(UtxoSetError::NoCoinbase); }
        if cb_cnt > 1 { return Err(UtxoSetError::MultipleCoinbase); }

        let cb_reward: u64 = block.transactions.iter().filter(|tx| tx.inputs.is_empty()).flat_map(|tx| tx.outputs.iter()).map(|o| o.amount).sum();
        let expected = self.total_supply + cb_reward;
        if block.total_supply != expected { return Err(UtxoSetError::InvalidTotalSupply { expected, got: block.total_supply }); }

        for tx in &block.transactions {
            let inputs = if !tx.inputs.is_empty() { self.get_inputs_for_tx(tx) } else { Vec::new() };
            for input in &tx.inputs { self.remove(&input.nullifier); }
            for output in &tx.outputs {
                let mut utxo = JtUtxo::from_tx_output(output, tx.tx_hash, block.height);
                if !inputs.is_empty() { let (td, to, tt) = JtUtxo::compute_taint(&inputs, block.height); utxo.taint_distance = td; utxo.taint_origin = to; utxo.taint_timestamp = tt; }
                self.add(utxo);
            }
        }
        self.total_supply = block.total_supply; self.dirty = true;
        Ok(self.state_root())
    }

    fn recompute_root(&mut self) {
        let mut h = blake3::Hasher::new(); h.update(b"AEVUM_UTXO_SET_V2");
        let mut n: Vec<&Hash> = self.utxos.keys().collect(); n.sort_by(|a,b| a.as_bytes().cmp(b.as_bytes()));
        for nf in n { h.update(nf.as_bytes()); if let Some(u) = self.utxos.get(nf) { h.update(u.amount_commitment().as_bytes()); h.update(u.tag_commitment().as_bytes()); h.update(u.owner().as_bytes()); } }
        let mut p: Vec<_> = self.prisma_policies.iter().collect(); p.sort_by(|a,b| a.0.cmp(b.0));
        for (pk, pol) in p { h.update(pk); h.update(pol.policy_hash.as_bytes()); }
        self.state_root = Hash(h.finalize().into()); self.dirty = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*; use crate::core::address::AcceptancePolicy; use crate::core::transaction::{Transaction, TxInput, TxOutput}; use crate::crypto::keys::PublicKey;
    fn dummy_utxo(s: u64) -> JtUtxo { JtUtxo::new_global_clean(PublicKey::dummy(), 100, &[1u8;32], &[1u8;32], s, 1, Hash::zero()).expect("dummy") }
    #[test] fn empty_ok() { let mut s=UtxoSet::new(); let cb=Transaction::new(vec![],vec![],0); assert!(s.apply_block(&Block::new(Hash::zero(),1,0,10,vec![cb],Hash::zero(),0,None)).is_ok()); }
    #[test] fn no_cb() { assert_eq!(UtxoSet::new().apply_block(&Block::new(Hash::zero(),1,0,10,vec![],Hash::zero(),0,None)), Err(UtxoSetError::NoCoinbase)); }
    #[test] fn multi_cb() { let a=Transaction::new(vec![],vec![],0); let b=Transaction::new(vec![],vec![],0); assert_eq!(UtxoSet::new().apply_block(&Block::new(Hash::zero(),1,0,10,vec![a,b],Hash::zero(),0,None)), Err(UtxoSetError::MultipleCoinbase)); }
    #[test] fn prisma_set() { let mut s=UtxoSet::new(); let pk=PublicKey::dummy(); let p=Policy::new(AcceptancePolicy::AcceptAll); s.set_prisma_policy(&pk,p.clone()); assert!(s.get_prisma_policy(&pk).is_some()); }
    #[test] fn prisma_reject() { let mut s=UtxoSet::new(); let o=PublicKey::dummy(); s.set_prisma_policy(&o,Policy::new(AcceptancePolicy::RejectAll)); s.add(dummy_utxo(1)); let out=TxOutput::new(o.clone(),50,crate::crypto::hash::AmountCommitment::dummy(),crate::crypto::hash::TagCommitment::dummy(),Hash::zero(),2,crate::core::jt_utxo::ZkProof::empty(),Hash::zero(),crate::core::jt_utxo::CAT_JURISDICTION|0x01,0); let cb=Transaction::new(vec![],vec![],0); let tx=Transaction::new(vec![],vec![out],0); assert!(s.apply_block(&Block::new(Hash::zero(),1,0,10,vec![cb,tx],Hash::zero(),50,None)).is_err()); }
    #[test] fn taint_propagates() { let mut s=UtxoSet::new(); let o=PublicKey::dummy(); let mut t=dummy_utxo(1); t.taint_distance=5; t.taint_origin=crate::core::jt_utxo::RISK_SANCTIONS_IRAN; t.taint_timestamp=100; s.add(t.clone()); let inp=TxInput{tx_hash:Hash::zero(),output_index:0,nullifier:*t.nullifier(),signature:vec![],public_key:o.clone(),signed_hash:Hash::zero(),nonce:0}; let out=TxOutput::new(o.clone(),50,crate::crypto::hash::AmountCommitment::dummy(),crate::crypto::hash::TagCommitment::dummy(),Hash::zero(),3,crate::core::jt_utxo::ZkProof::empty(),Hash::zero(),crate::core::jt_utxo::RESTRICTION_GLOBAL_CLEAN,0); let cb=Transaction::new(vec![],vec![],0); let tx=Transaction::new(vec![inp],vec![out],0); s.apply_block(&Block::new(Hash::zero(),2,0,10,vec![cb,tx],Hash::zero(),100,None)).unwrap(); assert_eq!(s.all().find(|(_,u)|u.serial()==3).unwrap().1.taint_distance,6); }
    #[test] fn taint_decays() { let mut s=UtxoSet::new(); let o=PublicKey::dummy(); let mut t=dummy_utxo(1); t.taint_distance=5; t.taint_origin=crate::core::jt_utxo::RISK_SANCTIONS_IRAN; t.taint_timestamp=100; s.add(t.clone()); let inp=TxInput{tx_hash:Hash::zero(),output_index:0,nullifier:*t.nullifier(),signature:vec![],public_key:o.clone(),signed_hash:Hash::zero(),nonce:0}; let out=TxOutput::new(o.clone(),50,crate::crypto::hash::AmountCommitment::dummy(),crate::crypto::hash::TagCommitment::dummy(),Hash::zero(),3,crate::core::jt_utxo::ZkProof::empty(),Hash::zero(),crate::core::jt_utxo::RESTRICTION_GLOBAL_CLEAN,0); let cb=Transaction::new(vec![],vec![],0); let tx=Transaction::new(vec![inp],vec![out],0); s.apply_block(&Block::new(Hash::zero(),100_200,0,10,vec![cb,tx],Hash::zero(),100,None)).unwrap(); assert_eq!(s.all().find(|(_,u)|u.serial()==3).unwrap().1.taint_distance,5); }
}
