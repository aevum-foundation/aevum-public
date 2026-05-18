use crate::core::transaction::{Transaction, TxOutput};
use crate::core::jt_utxo::JtUtxo;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;

pub struct Economics;

impl Economics {
    pub const SATOSHI_PER_AEV: u64 = 100_000_000;
    pub const INITIAL_REWARD_SATOSHI: u64 = 5_000_000_000;
    pub const HALVING_INTERVAL: u64 = 210_000;
    pub const MAX_SUPPLY_AEV: u64 = 21_000_000;
    pub const MAX_SUPPLY_SATOSHI: u64 = Self::MAX_SUPPLY_AEV * Self::SATOSHI_PER_AEV;
    pub const FEE_BPS: u64 = 1;
    pub const DEVELOPER_SHARE_BPS: u64 = 1000;

    pub fn block_reward_satoshi(height: u64) -> u64 {
        let halvings = height / Self::HALVING_INTERVAL;
        if halvings >= 64 { return 0; }
        Self::INITIAL_REWARD_SATOSHI / (1u64 << halvings)
    }

    pub fn block_reward_aev(height: u64) -> f64 {
        Self::block_reward_satoshi(height) as f64 / Self::SATOSHI_PER_AEV as f64
    }

    pub fn calculate_fee(amount_satoshi: u64) -> (u64, u64) {
        let total_fee = (amount_satoshi * Self::FEE_BPS) / 10_000;
        let developer_cut = (total_fee * Self::DEVELOPER_SHARE_BPS) / 10_000;
        (total_fee.max(1), developer_cut)
    }

    pub fn create_coinbase(
        miner: &PublicKey, height: u64, total_fees: u64,
        developer_address: &PublicKey, serial: u64, poh_tick: u64,
    ) -> Transaction {
        let base_reward = Self::block_reward_satoshi(height);
        let developer_cut = (total_fees * Self::DEVELOPER_SHARE_BPS) / 10_000;
        let miner_fee_share = total_fees.saturating_sub(developer_cut);
        let miner_reward = base_reward.saturating_add(miner_fee_share);

        let mut outputs = Vec::new();
        let amount_blind = blake3::hash(&height.to_le_bytes()).into();
        let tag_blind = blake3::hash(&serial.to_le_bytes()).into();
        let miner_utxo = JtUtxo::new_global_clean(
            miner.clone(), miner_reward, &amount_blind, &tag_blind, serial, height, Hash::zero(),
        ).expect("coinbase UTXO creation failed");
        outputs.push(TxOutput::from_jt_utxo(&miner_utxo, 0));

        if developer_cut > 0 {
            let amount_blind2 = blake3::hash(&(height + 1).to_le_bytes()).into();
            let tag_blind2 = blake3::hash(&(serial + 1).to_le_bytes()).into();
            let dev_utxo = JtUtxo::new_global_clean(
                developer_address.clone(), developer_cut, &amount_blind2, &tag_blind2, serial + 1, height, Hash::zero(),
            ).expect("dev UTXO creation failed");
            outputs.push(TxOutput::from_jt_utxo(&dev_utxo, 1));
        }

        { let mut tx = Transaction::new(vec![], outputs, 0); tx.poh_tick = poh_tick; tx.compute_hash(); tx }
    }

    pub fn check_supply(current_supply: u64, additional: u64) -> bool {
        current_supply.saturating_add(additional) <= Self::MAX_SUPPLY_SATOSHI
    }

    pub fn supply_aev(supply_satoshi: u64) -> f64 {
        supply_satoshi as f64 / Self::SATOSHI_PER_AEV as f64
    }

    pub fn supply_progress(supply_satoshi: u64) -> f64 {
        supply_satoshi as f64 / Self::MAX_SUPPLY_SATOSHI as f64
    }

    pub fn blocks_until_halving(height: u64) -> u64 {
        Self::HALVING_INTERVAL - (height % Self::HALVING_INTERVAL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_reward_is_5_billion_satoshi() {
        assert_eq!(Economics::block_reward_satoshi(0), 5_000_000_000);
    }

    #[test]
    fn halving_reduces_reward() {
        assert_eq!(Economics::block_reward_satoshi(210_000), 2_500_000_000);
        assert_eq!(Economics::block_reward_satoshi(420_000), 1_250_000_000);
        assert_eq!(Economics::block_reward_satoshi(630_000), 625_000_000);
    }

    #[test]
    fn reward_zero_after_64_halvings() {
        assert_eq!(Economics::block_reward_satoshi(64 * 210_000), 0);
    }

    #[test]
    fn fee_is_0_01_percent() {
        let (fee, dev_cut) = Economics::calculate_fee(100_000_000);
        assert_eq!(fee, 10_000);
        assert_eq!(dev_cut, 1_000);
    }

    #[test]
    fn fee_minimum_1_satoshi() {
        let (fee, _) = Economics::calculate_fee(100);
        assert_eq!(fee, 1);
    }

    #[test]
    fn max_supply_is_21_million_aev() {
        assert_eq!(Economics::MAX_SUPPLY_SATOSHI, 2_100_000_000_000_000);
    }

    #[test]
    fn supply_check_respects_max() {
        let max = Economics::MAX_SUPPLY_SATOSHI;
        assert!(Economics::check_supply(max - 1000, 500));
        assert!(!Economics::check_supply(max, 1));
    }

    #[test]
    fn blocks_until_halving_correct() {
        assert_eq!(Economics::blocks_until_halving(0), 210_000);
        assert_eq!(Economics::blocks_until_halving(209_999), 1);
        assert_eq!(Economics::blocks_until_halving(210_000), 210_000);
    }
}
