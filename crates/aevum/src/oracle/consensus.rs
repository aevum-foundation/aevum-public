use crate::crypto::hash::Hash;
#[derive(Debug, Clone)] 
pub enum ConsensusResult { 
    Accepted { risk_level: u64, voting_oracles: u8 }, 
    NeedsReview, 
    NoConsensus { top_risk: u64 }, 
    Unknown 
}
impl ConsensusResult { pub fn is_accepted(&self) -> bool { matches!(self, ConsensusResult::Accepted{..}) } }
#[derive(Debug)] pub struct OracleConsensus;
impl OracleConsensus { pub fn new() -> Self { OracleConsensus } }
