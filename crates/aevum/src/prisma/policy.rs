use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Policy {
    pub policy: String,
    pub policy_hash: [u8; 32],
    pub restriction_level: u64,
}
impl Policy {
    pub fn new(_s: String) -> Self { Self::default() }
    pub fn accepts_level(&self, _level: u64) -> bool { true }
}
