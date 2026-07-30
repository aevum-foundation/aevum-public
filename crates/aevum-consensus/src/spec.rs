//! Aevum L1 Consensus Specification v2.0
//!
//! spec.rs = ТОЛЬКО константы и re-export. Логика в rules/*.

pub const MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TRANSACTIONS: usize = 100_000;
pub const MAX_REORG_DEPTH: u64 = 64;
pub const CONFIRMATIONS_FOR_FINALITY: u64 = 6;
pub const HEARTBEAT_WITNESS_TTL_TICKS: u64 = 180;
pub const HEARTBEAT_MIN_WITNESSES: usize = 1;

pub use crate::consensus::rules::heartbeat;
pub use crate::consensus::rules::coinbase;
pub use crate::consensus::rules::poh;
pub use crate::consensus::rules::block;
pub use crate::consensus::rules::tx;
pub use crate::consensus::rules::supply;
pub use crate::consensus::rules::finality;
pub use crate::consensus::rules::fork;

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: функция существует и доступна.
    fn assert_fn<T>(_f: T) {}

    #[test]
    fn constants_consistent() {
        assert_eq!(MAX_BLOCK_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_TRANSACTIONS, 100_000);
        assert_eq!(MAX_REORG_DEPTH, 64);
        assert_eq!(CONFIRMATIONS_FOR_FINALITY, 6);
    }

    #[test]
    fn all_rules_compile_and_link() {
        // Heartbeat
        assert_fn(heartbeat::validate_count);
        assert_fn(heartbeat::validate_content);
        assert_fn(heartbeat::validate_ordering);

        // Coinbase
        assert_fn(coinbase::block_reward);
        assert_fn(coinbase::total_emitted);
        assert_fn(coinbase::validate);
        assert_fn(coinbase::validate_supply_cap);
        assert_fn(coinbase::max_coinbase_reward);

        // PoH
        assert_fn(poh::validate_range);
        assert_fn(poh::validate_continuity);

        // Block
        assert_fn(block::validate_presence);
        assert_fn(block::validate_structural);

        // Transaction
        assert_fn(tx::validate_structural);

        // Supply
        assert_fn(supply::validate_emission);

        // Finality
        assert_fn(finality::is_finalized);
        assert_fn(finality::validate_reorg_depth);

        // Fork choice
        assert_fn(fork::select_canonical);
    }
}
