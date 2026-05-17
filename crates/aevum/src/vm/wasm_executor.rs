use crate::crypto::hash::Hash;
use std::collections::HashMap;

/// WASM-исполнитель для смарт-контрактов
pub struct WasmExecutor {
    /// Загруженные модули (module_hash → wasm_bytes)
    modules: HashMap<Hash, Vec<u8>>,
    /// Лимит газа по умолчанию
    default_gas_limit: u64,
}

/// Результат выполнения контракта
#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub events: Vec<ContractEvent>,
}

/// Событие контракта (для логов)
#[derive(Clone, Debug)]
pub struct ContractEvent {
    pub contract_hash: Hash,
    pub topic: String,
    pub data: Vec<u8>,
}

impl WasmExecutor {
    pub fn new() -> Self {
        WasmExecutor {
            modules: HashMap::new(),
            default_gas_limit: 1_000_000,
        }
    }

    /// Загрузить WASM-модуль
    pub fn load_module(&mut self, wasm_bytes: &[u8]) -> Result<Hash, &'static str> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_WASM_MODULE");
        hasher.update(wasm_bytes);
        let module_hash = Hash(hasher.finalize().into());
        self.modules.insert(module_hash, wasm_bytes.to_vec());
        Ok(module_hash)
    }

    /// Вызвать метод контракта
    pub fn call(
        &self,
        module_hash: &Hash,
        method: &str,
        args: &[u8],
        gas_limit: Option<u64>,
    ) -> Result<ExecutionResult, &'static str> {
        let _wasm_bytes = self.modules.get(module_hash).ok_or("Module not found")?;
        let gas = gas_limit.unwrap_or(self.default_gas_limit);

        // v0.2: заглушка — эмулируем выполнение
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_CALL");
        hasher.update(module_hash.as_bytes());
        hasher.update(method.as_bytes());
        hasher.update(args);
        let result_hash = Hash(hasher.finalize().into());

        Ok(ExecutionResult {
            success: true,
            return_data: result_hash.as_bytes().to_vec(),
            gas_used: gas / 100, // ~1% лимита
            events: vec![ContractEvent {
                contract_hash: *module_hash,
                topic: method.to_string(),
                data: args.to_vec(),
            }],
        })
    }

    /// Задеплоить контракт (загрузить + вызвать init)
    pub fn deploy(
        &mut self,
        wasm_bytes: &[u8],
        init_args: &[u8],
    ) -> Result<(Hash, ExecutionResult), &'static str> {
        let module_hash = self.load_module(wasm_bytes)?;
        let result = self.call(&module_hash, "init", init_args, None)?;
        Ok((module_hash, result))
    }

    /// Проверить что модуль загружен
    pub fn is_loaded(&self, module_hash: &Hash) -> bool {
        self.modules.contains_key(module_hash)
    }

    /// Количество загруженных модулей
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_and_call() {
        let mut executor = WasmExecutor::new();
        let hash = executor.load_module(b"dummy wasm").unwrap();
        assert!(executor.is_loaded(&hash));

        let result = executor.call(&hash, "test", b"hello", None).unwrap();
        assert!(result.success);
        assert!(result.gas_used > 0);
        assert_eq!(result.events.len(), 1);
    }

    #[test]
    fn deploy_contract() {
        let mut executor = WasmExecutor::new();
        let (hash, result) = executor.deploy(b"contract code", b"init").unwrap();
        assert!(executor.is_loaded(&hash));
        assert!(result.success);
    }

    #[test]
    fn module_not_found() {
        let executor = WasmExecutor::new();
        let result = executor.call(&Hash::zero(), "test", b"", None);
        assert!(result.is_err());
    }
}
