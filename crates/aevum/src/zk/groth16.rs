use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkProof { pub a: Vec<u8>, pub b: Vec<u8>, pub c: Vec<u8>, pub public_inputs: Vec<u8> }
impl ZkProof { pub fn is_valid(&self) -> bool { !self.a.is_empty() && !self.b.is_empty() && !self.c.is_empty() } }
