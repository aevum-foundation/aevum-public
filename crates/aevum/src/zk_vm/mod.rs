use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkVm;
impl ZkVm { pub fn new() -> Self { ZkVm } }
