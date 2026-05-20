use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkJuris;
impl ZkJuris { pub fn new() -> Self { ZkJuris } }
