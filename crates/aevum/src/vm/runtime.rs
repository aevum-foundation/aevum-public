use crate::crypto::hash::Hash;

#[derive(Clone, Debug)]
pub struct WasmRuntime {
    module_hash: Option<Hash>,
    version: u8,
}

#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub success: bool,
    pub data: Vec<u8>,
    pub gas_used: u64,
    pub state_hash: Hash,
}

impl WasmRuntime {
    pub const CURRENT_VERSION: u8 = 0x01;

    pub fn new() -> Self {
        WasmRuntime {
            module_hash: None,
            version: Self::CURRENT_VERSION,
        }
    }

    pub fn load_module(&mut self, wasm_bytes: &[u8]) -> Result<Hash, &'static str> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(wasm_bytes);
        let hash = Hash(hasher.finalize().into());
        self.module_hash = Some(hash);
        Ok(hash)
    }

    pub fn execute(&self, _method: &str, _args: &[u8]) -> Result<ExecutionResult, &'static str> {
        if !self.is_loaded() {
            return Err("No module loaded");
        }
        Ok(ExecutionResult {
            success: true,
            data: Vec::new(),
            gas_used: 0,
            state_hash: Hash::zero(),
        })
    }

    pub fn is_loaded(&self) -> bool {
        self.module_hash.is_some()
    }
    pub fn module_hash(&self) -> Option<Hash> {
        self.module_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_runtime_is_not_loaded() {
        assert!(!WasmRuntime::new().is_loaded());
    }

    #[test]
    fn load_module_sets_hash() {
        let mut rt = WasmRuntime::new();
        let hash = rt.load_module(b"dummy").unwrap();
        assert!(rt.is_loaded());
        assert_eq!(rt.module_hash(), Some(hash));
    }

    #[test]
    fn load_different_modules_different_hashes() {
        let mut rt = WasmRuntime::new();
        let h1 = rt.load_module(b"module_a").unwrap();
        let h2 = rt.load_module(b"module_b").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn execute_fails_without_module() {
        assert!(WasmRuntime::new().execute("test", b"").is_err());
    }

    #[test]
    fn execute_succeeds_with_module() {
        let mut rt = WasmRuntime::new();
        rt.load_module(b"dummy").unwrap();
        assert!(rt.execute("test", b"").unwrap().success);
    }
}
