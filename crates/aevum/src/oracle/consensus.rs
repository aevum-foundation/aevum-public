use crate::oracle::conscience::ConscienceOracle;
use crate::oracle::innocence::InnocenceManager;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusResult {
    Accepted { risk_level: u64, risk_subcategory: u64, agreement_percent: u8, total_oracles: u8, voting_oracles: u8 },
    NoConsensus { top_risk: u64, agreement_percent: u8 },
    NeedsReview,
    Unknown,
}

impl ConsensusResult {
    pub fn is_accepted(&self) -> bool { matches!(self, ConsensusResult::Accepted { .. }) }
    pub fn risk_level(&self) -> Option<u64> {
        match self { ConsensusResult::Accepted { risk_level, .. } => Some(*risk_level), ConsensusResult::NoConsensus { top_risk, .. } => Some(*top_risk), _ => None }
    }
    pub fn is_risky(&self) -> bool {
        match self { ConsensusResult::Accepted { risk_level, .. } => crate::core::jt_utxo::is_risk_tag(*risk_level), ConsensusResult::NoConsensus { .. } => false, ConsensusResult::NeedsReview => true, ConsensusResult::Unknown => false }
    }
}

#[derive(Clone, Debug)]
pub struct OracleInfo {
    pub id: u32, pub public_key: PublicKey, pub name: String, pub weight: u8,
    pub last_update: u64, pub reputation: i64, pub oracle: ConscienceOracle,
}

impl OracleInfo {
    pub fn new(id: u32, pk: PublicKey, name: &str, weight: u8, oracle: ConscienceOracle) -> Self {
        OracleInfo { id, public_key: pk, name: name.to_string(), weight, last_update: 0, reputation: 0, oracle }
    }
    /// Запросить кросс-чейн риск (заглушка — будет API к Chainalysis/Elliptic)
    pub fn query_cross_chain_risk(&self, source_chain: u32, source_address: &str) -> Option<(u64, u64, u16, String)> {
        if source_chain == 0 { Some((crate::core::jt_utxo::CAT_GLOBAL | 0x00, 0, 0, "Bitcoin AML not yet connected".into())) }
        else { None }
    }
    pub fn query_risk(&self, _address: &[u8; 32]) -> Option<(u64, u64)> {
        if self.oracle.is_empty() { return None; }
        Some((crate::core::jt_utxo::CAT_GLOBAL | 0x00, crate::core::jt_utxo::RISK_SANCTIONS))
    }
}

#[derive(Debug)]
pub struct OracleConsensus {
    pub oracles: Vec<OracleInfo>,
    pub required_confirmations: usize,
    pub min_agreement_percent: u8,
    pub innocence_manager: InnocenceManager,
}

impl OracleConsensus {
    pub fn new() -> Self {
        OracleConsensus {
            oracles: Vec::new(),
            required_confirmations: 2,
            min_agreement_percent: 67,
            innocence_manager: InnocenceManager::new(),
        }
    }

    pub fn register_oracle(&mut self, oracle: OracleInfo) -> Result<(), &'static str> {
        if self.oracles.iter().any(|o| o.id == oracle.id) { return Err("Oracle already registered"); }
        self.oracles.push(oracle); Ok(())
    }

    pub fn remove_oracle(&mut self, id: u32) { self.oracles.retain(|o| o.id != id); }

    pub fn update_reputation(&mut self, id: u32, delta: i64) {
        if let Some(o) = self.oracles.iter_mut().find(|o| o.id == id) { o.reputation = o.reputation.saturating_add(delta); }
    }

    pub fn update_sanctions_root(&mut self, oracle_id: u32, root: Hash) {
        self.innocence_manager.update_sanctions_root(oracle_id, root);
    }

    pub fn update_risk_root(&mut self, oracle_id: u32, root: Hash) {
        self.innocence_manager.update_risk_root(oracle_id, root);
    }

    pub fn get_sanctions_root(&self) -> Option<Hash> {
        self.innocence_manager.get_sanctions_root()
    }

    pub fn get_risk_root(&self) -> Option<Hash> {
        self.innocence_manager.get_risk_root()
    }

    pub fn get_risk_consensus(&self, address: &[u8; 32]) -> ConsensusResult {
        if self.oracles.is_empty() { return ConsensusResult::Unknown; }
        let mut votes: HashMap<(u64, u64), u64> = HashMap::new();
        let mut total_responding = 0u8;
        for oracle in &self.oracles {
            if let Some((risk_level, risk_sub)) = oracle.query_risk(address) {
                *votes.entry((risk_level, risk_sub)).or_insert(0) += oracle.weight as u64;
                total_responding += 1;
            }
        }
        if votes.is_empty() { return ConsensusResult::Unknown; }
        let total_weight: u64 = votes.values().sum();
        let (winning_key, winning_weight) = votes.iter().max_by_key(|(_, w)| *w).unwrap();
        let agreement = (winning_weight * 100) / total_weight;
        if agreement >= self.min_agreement_percent as u64 && total_responding as usize >= self.required_confirmations {
            ConsensusResult::Accepted { risk_level: winning_key.0, risk_subcategory: winning_key.1, agreement_percent: agreement as u8, total_oracles: self.oracles.len() as u8, voting_oracles: total_responding }
        } else if total_responding > 0 {
            ConsensusResult::NeedsReview
        } else {
            ConsensusResult::Unknown
        }
    }

    pub fn oracle_count(&self) -> usize { self.oracles.len() }
}
