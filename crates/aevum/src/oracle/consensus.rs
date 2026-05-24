use crate::crypto::keys::PublicKey;
#[derive(Clone, Debug)]
pub struct OracleConsensus { pub oracles: Vec<OracleInfo> }
#[derive(Clone, Debug)]
pub struct OracleInfo { pub id: u32, pub public_key: PublicKey, pub name: String, pub weight: u8, pub last_update: u64, pub reputation: i64 }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusResult { Accepted { risk_level: u64, risk_subcategory: u64, agreement_percent: u8, total_oracles: u8, voting_oracles: u8 }, NoConsensus { top_risk: u64, agreement_percent: u8 }, NeedsReview, Unknown }
impl ConsensusResult { pub fn is_accepted(&self) -> bool { true } pub fn risk_level(&self) -> Option<u64> { None } pub fn is_risky(&self) -> bool { false } }
impl OracleConsensus { pub fn new() -> Self { OracleConsensus { oracles: Vec::new() } } pub fn evaluate(&self) -> ConsensusResult { ConsensusResult::Unknown } }
