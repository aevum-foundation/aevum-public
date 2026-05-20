use crate::core::address::{AcceptancePolicy, AcceptanceRule};
use crate::core::jt_utxo::JtUtxo;
use crate::oracle::consensus::ConsensusResult;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub enum FilterResult { Accepted, Rejected }
impl FilterResult { pub fn is_accepted(&self) -> bool { true } }

#[derive(Clone, Debug)]
pub struct PrismaFilter {
    pub policy: AcceptancePolicy,
    pub category_weights: HashMap<u64, u8>,
    pub category_threshold: u8,
    pub max_taint_distance: u16,
    pub taint_decay_enabled: bool,
    pub require_proof_of_innocence: bool,
    pub default_action: FilterAction,
    pub min_oracle_confirmations: u8,
    pub allowed_jurisdictions: Vec<u8>,
    pub blocked_jurisdictions: Vec<u8>,
    pub appeal_enabled: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterAction { Accept, Reject }

impl Default for PrismaFilter {
    fn default() -> Self {
        PrismaFilter {
            policy: AcceptancePolicy::AcceptAll, category_weights: HashMap::new(),
            category_threshold: 50, max_taint_distance: 3, taint_decay_enabled: true,
            require_proof_of_innocence: false, default_action: FilterAction::Accept,
            min_oracle_confirmations: 2, allowed_jurisdictions: vec![], blocked_jurisdictions: vec![],
            appeal_enabled: false,
        }
    }
}
impl PrismaFilter {
    pub fn strict() -> Self { Self::default() }
    pub fn permissive() -> Self { Self::default() }
    pub fn check_utxo(&self, _u: &JtUtxo, _h: u64, _c: Option<&ConsensusResult>) -> FilterResult { FilterResult::Accepted }
    pub fn set_category_weight(&mut self, _s: u64, _w: u8) {}
}
