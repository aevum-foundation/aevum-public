use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleConsensus {
    pub votes: std::collections::HashMap<[u8; 32], bool>,
}
impl Default for OracleConsensus { fn default() -> Self { OracleConsensus { votes: std::collections::HashMap::new() } } }
impl OracleConsensus {
    pub fn new() -> Self { Self::default() }
    pub fn record_vote(&mut self, _voter: &[u8; 32], _approve: bool) {}
    pub fn tally(&self) -> (u64, u64) { (0, 0) }
}
