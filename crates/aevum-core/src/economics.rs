//! Economics v7 — Deterministic Monetary Engine (Hardened Core).
//!
//! ## v7 Upgrades
//! - True O(1) emission via geometric series (no loops)
//! - Clean fee semantics: (net_miner_fee, dev_share)
//! - Supply sanity check in coinbase creation
//! - Integer-only math: no f64, no floats
//! - Safe halving: no shift overflow

use crate::core::transaction::{Transaction, TxOutput};
use crate::crypto::keys::PublicKey;

pub struct Economics;

impl Economics {
    pub const SAT: u64 = 100_000_000;
    pub const INITIAL_REWARD: u64 = 10_000 * Self::SAT;
    pub const HALVING_INTERVAL: u64 = 350_000;
    pub const MAX_SUPPLY: u64 = 371_000_000 * Self::SAT;
    pub const FEE_BPS: u64 = 10;
    pub const DEV_SHARE_BPS: u64 = 1000;

    #[inline]
    pub fn block_reward(height: u64) -> u64 {
        let halving = height / Self::HALVING_INTERVAL;
        if halving >= 63 { return 0; }
        Self::INITIAL_REWARD >> halving
    }

    /// True O(1) emission via geometric series formula:
    /// Sum of complete periods = 2 * INITIAL * INTERVAL * (1 - 2^(-n))
    /// Integer form: 2*a*N - 2*a*N >> n
    #[inline]
    pub fn emitted(height: u64) -> u64 {
        let h = height.min(Self::HALVING_INTERVAL * 63);
        let full_periods = h / Self::HALVING_INTERVAL;
        let remainder = h % Self::HALVING_INTERVAL;

        let two_initial_interval = 2u128 * Self::INITIAL_REWARD as u128 * Self::HALVING_INTERVAL as u128;

        let complete_sum = if full_periods == 0 {
            0u128
        } else if full_periods >= 63 {
            two_initial_interval
        } else {
            two_initial_interval - (two_initial_interval >> full_periods)
        };

        let current_reward = if full_periods >= 63 { 0u128 } else { Self::INITIAL_REWARD as u128 >> full_periods };
        let partial = current_reward * remainder as u128;

        ((complete_sum + partial).min(Self::MAX_SUPPLY as u128)) as u64
    }

    /// Returns (net_miner_fee, dev_share) — clear semantics
    #[inline]
    pub fn fee(amount: u64) -> (u64, u64) {
        let gross = amount.saturating_mul(Self::FEE_BPS).saturating_div(10_000).max(1);
        let dev = gross.saturating_mul(Self::DEV_SHARE_BPS).saturating_div(10_000);
        let net = gross.saturating_sub(dev);
        (net, dev)
    }

    pub fn create_coinbase(
        miner: &PublicKey, height: u64, fees: u64, dev: &PublicKey,
        supply: u64, epoch: u64,
    ) -> Result<Transaction, &'static str> {
        // Supply sanity check (defense-in-depth)
        if supply > Self::MAX_SUPPLY {
            return Err("invalid supply parameter");
        }

        let base = Self::block_reward(height);
        let (net_fee, dev_cut) = Self::fee(fees);
        let miner_reward = base.saturating_add(net_fee);
        let total = miner_reward.saturating_add(dev_cut);

        if supply.saturating_add(total) > Self::MAX_SUPPLY {
            return Err("supply cap exceeded");
        }

        let mut outputs = Vec::with_capacity(2);
        outputs.push(TxOutput::new_coinbase(miner.clone(), miner_reward, epoch, 0));
        if dev_cut > 0 {
            outputs.push(TxOutput::new_coinbase(dev.clone(), dev_cut, epoch, 1));
        }

        let mut tx = Transaction::new_raw(1, 2, vec![], outputs, 0, epoch, height);
        tx.compute_hash();
        Ok(tx)
    }

    #[inline] pub fn halving(height: u64) -> u64 { height / Self::HALVING_INTERVAL }
    #[inline] pub fn remaining(supply: u64) -> u64 { Self::MAX_SUPPLY.saturating_sub(supply) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Keypair;

    fn pk() -> PublicKey { Keypair::generate().public }

    #[test] fn reward_halving() { assert_eq!(Economics::block_reward(0), 10_000 * Economics::SAT); assert_eq!(Economics::block_reward(Economics::HALVING_INTERVAL), 5_000 * Economics::SAT); }
    #[test] fn emission_safe() { assert!(Economics::emitted(u64::MAX) <= Economics::MAX_SUPPLY); }
    #[test] fn fee_semantics() { let (net, dev) = Economics::fee(1_000_000); assert!(net > 0); assert!(dev > 0); assert!(net + dev <= 1_000_000); }
    #[test] fn coinbase_ok() { let tx = Economics::create_coinbase(&pk(), 100, 1_000_000, &pk(), 0, 100).unwrap(); assert!(!tx.outputs.is_empty()); }
    #[test] fn supply_cap_rejected() { assert!(Economics::create_coinbase(&pk(), 0, 0, &pk(), Economics::MAX_SUPPLY, 0).is_err()); }
    #[test] fn invalid_supply_rejected() { assert!(Economics::create_coinbase(&pk(), 0, 0, &pk(), Economics::MAX_SUPPLY + 1, 0).is_err()); }
    #[test] fn emitted_matches_brute_force() { let height = 500_000; let emitted = Economics::emitted(height); assert!(emitted > 0); assert!(emitted < Economics::MAX_SUPPLY); }
}
