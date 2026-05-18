use crate::core::compute::BlockSolution;
use crate::core::transaction::Transaction;
use crate::crypto::hash::Hash;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub version: u8,
    pub prev_hash: Hash,
    pub block_hash: Hash,
    pub height: u64,
    pub poh_tick_start: u64,
    pub poh_tick_end: u64,
    pub transactions: Vec<Transaction>,
    pub state_root: Hash,
    pub total_supply: u64,
    pub useful_solution: Option<BlockSolution>,
}

impl Block {
    pub const CURRENT_VERSION: u8 = 0x01;
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_BLOCK_V1";

    pub fn new(
        prev_hash: Hash,
        height: u64,
        poh_tick_start: u64,
        poh_tick_end: u64,
        transactions: Vec<Transaction>,
        state_root: Hash,
        total_supply: u64,
        useful_solution: Option<BlockSolution>,
    ) -> Self {
        let mut block = Block {
            version: Self::CURRENT_VERSION,
            prev_hash,
            block_hash: Hash::zero(),
            height,
            poh_tick_start,
            poh_tick_end,
            transactions,
            state_root,
            total_supply,
            useful_solution,
        };
        block.block_hash = block.compute_hash();
        block
    }

    pub fn genesis(transactions: Vec<Transaction>) -> Self {
        Block::new(Hash::zero(), 0, 0, 0, transactions, Hash::zero(), 0, None)
    }

    pub fn is_valid_after(&self, prev: &Block) -> bool {
        self.prev_hash == prev.block_hash
            && self.height == prev.height + 1
            && self.poh_tick_start >= prev.poh_tick_end
    }

    pub fn is_internal_valid(&self) -> bool {
        if self.transactions.is_empty() {
            return false;
        }
        if self.poh_tick_end < self.poh_tick_start {
            return false;
        }
        for tx in &self.transactions {
            // Проверка баланса: сумма выходов ≤ сумме входов (входы проверяются в UTXO)
            if !Self::verify_tx_balance(tx) {
                return false;
            }
            if tx.inputs.is_empty() {
                // Coinbase транзакция: проверяем временные рамки
                if tx.poh_tick < self.poh_tick_start || tx.poh_tick > self.poh_tick_end {
                    return false;
                }
            }
        }
        true
    }

    /// Проверить что сумма выходов не превышает сумму входов + fee
    fn verify_tx_balance(tx: &Transaction) -> bool {
        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        let input_sum: u64 = 0; // Входы проверяются по UTXO-сету, здесь только выходы
        
        // Для coinbase: выходы = награда + fee
        if tx.inputs.is_empty() {
            return true; // Coinbase всегда валидна по балансу (награда проверяется в консенсусе)
        }
        
        // Для обычных транзакций: выходы + fee ≤ входы (проверяется в валидаторе)
        // Здесь базовая проверка: выходы не нулевые
        if output_sum == 0 {
            return false;
        }
        
        true
    }

    pub fn is_genesis(&self) -> bool {
        self.height == 0 && self.prev_hash == Hash::zero()
    }

    pub fn compute_hash(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&[self.version]);
        hasher.update(self.prev_hash.as_bytes());
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.poh_tick_start.to_le_bytes());
        hasher.update(&self.poh_tick_end.to_le_bytes());
        hasher.update(self.state_root.as_bytes());
        hasher.update(&self.total_supply.to_le_bytes());
        for tx in &self.transactions {
            hasher.update(tx.tx_hash.as_bytes());
        }
        if let Some(ref sol) = self.useful_solution {
            hasher.update(sol.solution.as_slice());
        }
        Hash(hasher.finalize().into())
    }
}
