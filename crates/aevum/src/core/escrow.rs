use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EscrowContract {
    pub contract_id: Hash,
    pub customer: PublicKey,
    pub total_reward: u64,
    pub task_id: Hash,
    pub status: EscrowStatus,
    pub created_height: u64,
    pub deadline_height: u64,
    pub winner_bonus_percent: u64,
    pub pool_fee_percent: u64,
    pub miner_shares: Vec<(PublicKey, u64)>,
    pub winner: Option<PublicKey>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EscrowStatus {
    Funded,
    InProgress,
    Completed,
    Refunded,
}

impl EscrowContract {
    pub fn new(
        customer: PublicKey, total_reward: u64, task_id: Hash,
        created_height: u64, deadline_blocks: u64,
    ) -> Self {
        let hash_input = [
            customer.to_bytes().as_slice(),
            &total_reward.to_le_bytes(),
            task_id.as_bytes(),
        ].concat();
        let hash_bytes = blake3::hash(&hash_input);
        let mut id = [0u8; 32];
        id.copy_from_slice(hash_bytes.as_bytes());
        EscrowContract {
            contract_id: Hash(id), customer, total_reward, task_id,
            status: EscrowStatus::Funded, created_height,
            deadline_height: created_height + deadline_blocks,
            winner_bonus_percent: 200, pool_fee_percent: 100,
            miner_shares: Vec::new(), winner: None,
        }
    }

    pub fn add_share(&mut self, miner: &PublicKey, shares: u64) {
        if let Some(existing) = self.miner_shares.iter_mut().find(|(k, _)| k == miner) {
            existing.1 += shares;
        } else {
            self.miner_shares.push((miner.clone(), shares));
        }
    }

    pub fn set_winner(&mut self, winner: &PublicKey) {
        self.winner = Some(winner.clone());
        self.status = EscrowStatus::Completed;
    }

    pub fn distribute_reward(&self) -> Vec<(PublicKey, u64)> {
        let mut payouts = Vec::new();
        if self.miner_shares.is_empty() { return payouts; }
        let pool_fee = self.total_reward * self.pool_fee_percent / 10000;
        let remaining = self.total_reward - pool_fee;
        let winner_bonus = if self.winner.is_some() { remaining * self.winner_bonus_percent / 10000 } else { 0 };
        let base = remaining - winner_bonus;
        let total_shares: u64 = self.miner_shares.iter().map(|(_, s)| s).sum();
        if total_shares == 0 { return payouts; }
        for (miner, shares) in &self.miner_shares {
            let amount = base * shares / total_shares;
            if amount > 0 { payouts.push((miner.clone(), amount)); }
        }
        if let Some(ref winner) = self.winner {
            if winner_bonus > 0 {
                if let Some(payout) = payouts.iter_mut().find(|(k, _)| k == winner) {
                    payout.1 += winner_bonus;
                } else {
                    payouts.push((winner.clone(), winner_bonus));
                }
            }
        }
        let total_paid: u64 = payouts.iter().map(|(_, a)| a).sum();
        let refund = remaining - total_paid;
        if refund > 0 { payouts.push((self.customer.clone(), refund)); }
        payouts
    }

    pub fn refund(&mut self) -> Vec<(PublicKey, u64)> {
        self.status = EscrowStatus::Refunded;
        let pool_fee = self.total_reward * self.pool_fee_percent / 10000;
        vec![(self.customer.clone(), self.total_reward - pool_fee)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Keypair;

    #[test]
    fn test_escrow_distribution_with_winner() {
        let customer = Keypair::generate().public;
        let miner1 = Keypair::generate().public;
        let miner2 = Keypair::generate().public;
        let winner = miner1.clone();
        let mut contract = EscrowContract::new(customer.clone(), 100_000, Hash::zero(), 0, 1000);
        contract.add_share(&miner1, 700);
        contract.add_share(&miner2, 300);
        contract.set_winner(&winner);
        let payouts = contract.distribute_reward();
        let winner_payout = payouts.iter().find(|(k, _)| k == &winner).unwrap().1;
        let miner2_payout = payouts.iter().find(|(k, _)| k == &miner2).unwrap().1;
        assert!(winner_payout > miner2_payout);
    }

    #[test]
    fn test_escrow_refund() {
        let customer = Keypair::generate().public;
        let mut contract = EscrowContract::new(customer.clone(), 100_000, Hash::zero(), 0, 1000);
        let payouts = contract.refund();
        assert_eq!(payouts.len(), 1);
        assert!(payouts[0].1 > 0 && payouts[0].1 < 100_000);
    }

    #[test]
    fn test_no_shares_no_payouts() {
        let customer = Keypair::generate().public;
        let contract = EscrowContract::new(customer, 100_000, Hash::zero(), 0, 1000);
        assert!(contract.distribute_reward().is_empty());
    }
}
