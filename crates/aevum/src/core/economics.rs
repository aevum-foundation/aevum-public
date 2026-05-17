use crate::core::transaction::{Transaction, TxOutput};
use crate::core::jt_utxo::JtUtxo;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;

pub struct Economics;

impl Economics {
    // 1 AEV = 100_000_000 люмен (минимальных единиц)
    pub const LUMEN_PER_AEV: u64 = 100_000_000;
    
    // Награда за блок в AEV
    pub const INITIAL_REWARD_AEV: u64 = 50;
    pub const HALVING_INTERVAL: u64 = 210_000;
    pub const MAX_SUPPLY_AEV: u64 = 21_000_000;
    
    // Максимальная эмиссия в люмен
    pub const MAX_SUPPLY: u64 = Self::MAX_SUPPLY_AEV * Self::LUMEN_PER_AEV;
    
    // Комиссии
    pub const FEE_BPS: u64 = 1;                    // 0.01%
    pub const DEVELOPER_SHARE_BPS: u64 = 1000;      // 10% от комиссии
    
    /// Награда за блок в люмен
    pub fn block_reward(height: u64) -> u64 {
        let halvings = height / Self::HALVING_INTERVAL;
        if halvings >= 64 { return 0; }
        (Self::INITIAL_REWARD_AEV >> halvings) * Self::LUMEN_PER_AEV
    }
    
    /// Комиссия за перевод
    pub fn calculate_fee(amount_люмен: u64) -> (u64, u64) {
        let total_fee = (amount_люмен * Self::FEE_BPS) / 10_000;
        let developer_cut = (total_fee * Self::DEVELOPER_SHARE_BPS) / 10_000;
        (total_fee, developer_cut)
    }
    
    /// Создать coinbase-транзакцию
    pub fn create_coinbase(
        miner: &PublicKey, height: u64, total_fees: u64,
        developer_address: &PublicKey, serial: u64, poh_tick: u64,
    ) -> Transaction {
        let base_reward = Self::block_reward(height);
        let developer_cut = (total_fees * Self::DEVELOPER_SHARE_BPS) / 10_000;
        let miner_fee_share = total_fees - developer_cut;
        let miner_reward = base_reward + miner_fee_share;
        
        let mut outputs = Vec::new();
        
        let miner_utxo = JtUtxo::new_global_clean(
            miner.clone(), miner_reward, &[0u8; 32], &[0u8; 32], serial, Hash::zero(),
        );
        outputs.push(TxOutput::from_jt_utxo(&miner_utxo));
        
        if developer_cut > 0 {
            let dev_utxo = JtUtxo::new_global_clean(
                developer_address.clone(), developer_cut, &[0u8; 32], &[0u8; 32], serial + 1, Hash::zero(),
            );
            outputs.push(TxOutput::from_jt_utxo(&dev_utxo));
        }
        
        Transaction::new(vec![], outputs, poh_tick)
    }
    
    pub fn check_supply(current_supply: u64, additional: u64) -> bool {
        current_supply.saturating_add(additional) <= Self::MAX_SUPPLY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::PrivateKey;
    
    #[test]
    fn initial_reward_is_5_billion_люмен() {
        assert_eq!(Economics::block_reward(0), 5_000_000_000);
    }
    
    #[test]
    fn halving_reduces_reward() {
        assert_eq!(Economics::block_reward(210_000), 2_500_000_000);
        assert_eq!(Economics::block_reward(420_000), 1_250_000_000);
    }
    
    #[test]
    fn max_supply_is_21_million_aev() {
        assert_eq!(Economics::MAX_SUPPLY, 2_100_000_000_000_000);
    }
}
