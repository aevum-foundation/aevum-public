use crate::core::address::{AcceptancePolicy, AcceptanceRule};
use crate::core::jt_utxo::{JtUtxo, CATEGORY_MASK, CAT_RISK_TAG, SUBCATEGORY_MASK, decay_taint, is_risk_tag};
use crate::oracle::consensus::{OracleConsensus, ConsensusResult};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterResult {
    Accepted, RejectedByPolicy, RejectedByCategory, RejectedByTaint,
    RejectedByJurisdiction, RejectedByOracleConsensus, RejectedMissingProof, NeedsManualReview,
}
impl FilterResult {
    pub fn is_accepted(&self) -> bool { matches!(self, FilterResult::Accepted) }
}

#[derive(Clone, Debug)]
pub struct PrismaFilter {
    pub policy: AcceptancePolicy, pub category_weights: HashMap<u64, u8>, pub category_threshold: u8,
    pub max_taint_distance: u16, pub taint_decay_enabled: bool,
    pub allowed_jurisdictions: Vec<u8>, pub blocked_jurisdictions: Vec<u8>,
    pub require_proof_of_innocence: bool, pub min_oracle_confirmations: u8,
    pub appeal_enabled: bool, pub default_action: FilterAction,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterAction { Accept, Reject, ManualReview }

impl Default for PrismaFilter {
    fn default() -> Self {
        PrismaFilter { policy: AcceptancePolicy::AcceptAll, category_weights: HashMap::new(),
            category_threshold: 75, max_taint_distance: 3, taint_decay_enabled: true,
            allowed_jurisdictions: Vec::new(), blocked_jurisdictions: Vec::new(),
            require_proof_of_innocence: false, min_oracle_confirmations: 2,
            appeal_enabled: false, default_action: FilterAction::Accept }
    }
}
impl PrismaFilter {
    pub fn strict() -> Self {
        let mut w = HashMap::new();
        w.insert(0x010, 100); w.insert(0x020, 100); w.insert(0x030, 100); w.insert(0x040, 90);
        w.insert(0x050, 80); w.insert(0x060, 50); w.insert(0x070, 20); w.insert(0x080, 30);
        w.insert(0x0A0, 100); w.insert(0x0B0, 100);
        PrismaFilter { policy: AcceptancePolicy::RejectAll, category_weights: w, category_threshold: 50,
            max_taint_distance: 2, taint_decay_enabled: true, require_proof_of_innocence: true,
            min_oracle_confirmations: 2, appeal_enabled: true, default_action: FilterAction::Reject, ..Default::default() }
    }
    pub fn permissive() -> Self { PrismaFilter { policy: AcceptancePolicy::AcceptAll, max_taint_distance: 10, default_action: FilterAction::Accept, ..Default::default() } }
    pub fn check_utxo(&self, utxo: &JtUtxo, current_height: u64, consensus: Option<&ConsensusResult>) -> FilterResult {
        let level = utxo.restriction_level(); let category = level & CATEGORY_MASK;
        let jc = (level & 0x0F) as u8;
        if self.blocked_jurisdictions.contains(&jc) { return FilterResult::RejectedByJurisdiction; }
        if !self.allowed_jurisdictions.is_empty() && !self.allowed_jurisdictions.contains(&jc) { return FilterResult::RejectedByJurisdiction; }
        if category == CAT_RISK_TAG {
            let sc = (level & SUBCATEGORY_MASK) >> 4;
            if let Some(&w) = self.category_weights.get(&sc) { if w >= self.category_threshold { return FilterResult::RejectedByCategory; } }
            else if self.default_action == FilterAction::Reject { return FilterResult::RejectedByCategory; }
        }
        let et = if self.taint_decay_enabled { decay_taint(utxo.taint_distance, utxo.taint_timestamp, current_height) } else { utxo.taint_distance };
        if et > self.max_taint_distance { return FilterResult::RejectedByTaint; }
        if let Some(c) = consensus {
            match c {
                ConsensusResult::Accepted { risk_level, voting_oracles, .. } => { if is_risk_tag(*risk_level) { return FilterResult::RejectedByOracleConsensus; } if *voting_oracles < self.min_oracle_confirmations { return FilterResult::NeedsManualReview; } }
                ConsensusResult::NeedsReview => { return FilterResult::NeedsManualReview; }
                ConsensusResult::NoConsensus { .. } => { if self.default_action == FilterAction::Reject { return FilterResult::RejectedByOracleConsensus; } }
                ConsensusResult::Unknown => {}
            }
        }
        if self.require_proof_of_innocence && et > 0 && !utxo.zk_proof().is_valid() { return FilterResult::RejectedMissingProof; }
        if !self.policy.accepts_level(level) { return FilterResult::RejectedByPolicy; }
        FilterResult::Accepted
    }
    pub fn set_category_weight(&mut self, subcategory: u64, weight: u8) { self.category_weights.insert(subcategory, weight); }
    pub fn block_jurisdiction(&mut self, code: u8) { if !self.blocked_jurisdictions.contains(&code) { self.blocked_jurisdictions.push(code); } }
    pub fn allow_jurisdiction(&mut self, code: u8) { self.blocked_jurisdictions.retain(|c| *c != code); if !self.allowed_jurisdictions.contains(&code) { self.allowed_jurisdictions.push(code); } }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::jt_utxo::{RESTRICTION_GLOBAL_CLEAN, RISK_SANCTIONS_IRAN};
    use crate::crypto::keys::Keypair;
    use crate::crypto::hash::Hash;
    use crate::core::jt_utxo::ZkProof;
    use crate::crypto::hash::{AmountCommitment, TagCommitment};

    fn dummy_utxo(level: u64) -> JtUtxo {
        let pk = Keypair::generate().public;
        JtUtxo::from_parts(Hash::zero(), pk, 100, AmountCommitment::dummy(), TagCommitment::dummy(), 1, 1, Hash::zero(), ZkProof::empty(), level, 0)
    }

    #[test] fn global_accepted() { assert!(PrismaFilter::permissive().check_utxo(&dummy_utxo(RESTRICTION_GLOBAL_CLEAN), 100, None).is_accepted()); }
    #[test] fn sanctions_rejected() { assert!(!PrismaFilter::strict().check_utxo(&dummy_utxo(RISK_SANCTIONS_IRAN), 100, None).is_accepted()); }
    #[test] fn sanctions_permissive() { assert!(PrismaFilter::permissive().check_utxo(&dummy_utxo(RISK_SANCTIONS_IRAN), 100, None).is_accepted()); }
    #[test] fn taint_deep() { let mut u = dummy_utxo(RESTRICTION_GLOBAL_CLEAN); u.taint_distance = 5; assert!(!PrismaFilter::strict().check_utxo(&u, 100, None).is_accepted()); }
    #[test] fn taint_decay() { let mut u = dummy_utxo(RESTRICTION_GLOBAL_CLEAN); u.taint_distance = 5; u.taint_timestamp = 100; assert!(PrismaFilter::permissive().check_utxo(&u, 200_100, None).is_accepted()); }
    #[test] fn missing_proof() { let mut f = PrismaFilter::strict(); f.require_proof_of_innocence = true; let mut u = dummy_utxo(RESTRICTION_GLOBAL_CLEAN); u.taint_distance = 1; assert!(!f.check_utxo(&u, 100, None).is_accepted()); }
}
