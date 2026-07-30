//! Consensus traits — plug-compatible интерфейсы для правил.
//!
//! Каждый trait определяет контракт для одного домена валидации.
//! Реализации находятся в rules/*.
//!
//! ## Использование
//! - Verifier: вызывает trait-методы для статической проверки
//! - Validator: вызывает trait-методы для оркестрации
//! - WASM/Light client: использует trait-объекты для переиспользования

use crate::core::block::Block;
use crate::core::transaction::Transaction;
use crate::crypto::hash::Hash;
use crate::consensus::errors::SpecResult;

/// Валидация структуры блока.
pub trait BlockRule {
    fn validate_structural(&self, block: &Block) -> SpecResult<()>;
    fn validate_presence(&self, block: &Block) -> SpecResult<()>;
}

/// Валидация транзакции.
pub trait TxRule {
    fn validate_structural(&self, tx: &Transaction) -> SpecResult<()>;
}

/// Валидация heartbeat (liveness).
pub trait HeartbeatRule {
    fn validate_count(&self, block: &Block) -> SpecResult<()>;
    fn validate_content(&self, block: &Block) -> SpecResult<()>;
    fn validate_ordering(&self, block: &Block) -> SpecResult<()>;
}

/// Валидация coinbase (issuance).
pub trait CoinbaseRule {
    fn validate(&self, block: &Block) -> SpecResult<()>;
    fn block_reward(&self, height: u64) -> u64;
    fn max_coinbase_reward(&self, height: u64, total_fees: u64) -> u64;
}

/// Валидация PoH (time).
pub trait PohRule {
    fn validate_range(&self, start: u64, end: u64) -> SpecResult<()>;
    fn validate_continuity(&self, prev_end: u64, next_start: u64) -> SpecResult<()>;
}

/// Валидация supply (economics).
pub trait SupplyRule {
    fn validate_emission(&self, current: u64, additional: u64) -> SpecResult<()>;
}

/// Валидация finality (safety).
pub trait FinalityRule {
    fn is_finalized(&self, height: u64, finalized_height: u64) -> bool;
    fn validate_reorg_depth(&self, current: u64, target: u64) -> SpecResult<()>;
}

/// Выбор форка.
pub trait ForkChoiceRule {
    fn select_canonical(
        &self,
        current_height: u64,
        current_hash: &Hash,
        candidate_height: u64,
        candidate_hash: &Hash,
    ) -> (u64, Hash);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Проверка что все traits object-safe (можно использовать как `dyn Trait`).
    fn _assert_object_safe(
        _b: &dyn BlockRule,
        _t: &dyn TxRule,
        _h: &dyn HeartbeatRule,
        _c: &dyn CoinbaseRule,
        _p: &dyn PohRule,
        _s: &dyn SupplyRule,
        _f: &dyn FinalityRule,
        _fc: &dyn ForkChoiceRule,
    ) {}

    #[test]
    fn all_traits_object_safe() {
        // Компиляция гарантирует object-safety
    }
}
