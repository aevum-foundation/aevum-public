use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InnocenceOracle;
impl InnocenceOracle { pub fn new() -> Self { InnocenceOracle } }
