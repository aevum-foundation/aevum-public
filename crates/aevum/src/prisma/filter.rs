use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrismaFilter {
    pub policies: Vec<Policy>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub policy: String,
    pub policy_hash: [u8; 32],
    pub restriction_level: u64,
}
impl Default for PrismaFilter { fn default() -> Self { PrismaFilter { policies: vec![] } } }
impl PrismaFilter {
    pub fn new() -> Self { Self::default() }
    pub fn check(&self, _level: u64) -> bool { true }
}
