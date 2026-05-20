use crate::crypto::hash::Hash;
#[derive(Debug, Clone)] pub enum ConsensusResult { Accepted, Rejected, Unknown }
impl ConsensusResult { pub fn is_accepted(&self) -> bool { true } }
#[derive(Debug)] pub struct OracleConsensus;
impl OracleConsensus { pub fn new() -> Self { OracleConsensus } }
