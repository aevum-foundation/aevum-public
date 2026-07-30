//! L2 State v5 — Deterministic execution engine (hardened + audit-grade)
//!
//! ## v5 Key upgrades
//! - ExecutionContext OWNS data (from/to copied, not borrowed)
//! - No borrow conflict: immutable check → mutable apply
//! - Atomic validation pipeline (no partial state rollback risks)
//! - Pre-validation before mutation
//! - Explicit execution context
//! - Reduced mutation surface
//! - Stronger invariants on nonce + balance handling
//! - Comprehensive test suite (3 tests)

use std::collections::{BTreeMap, HashSet};
use aevum::crypto::hash::Hash;
use aevum::crypto::keys::PublicKey;
use crate::l2_transaction::{L2Transaction, L2Utxo};

#[derive(Debug, PartialEq)]
pub enum L2StateError {
    InvalidSignature,
    ReplayDetected,
    InvalidNonce { expected: u64, got: u64 },
    InsufficientBalance { required: u64, available: u64 },
    AmountZero,
}

/// Execution context — OWNS all data, no borrows into L2State.
/// This avoids borrow conflicts between immutable validation
/// and mutable state application.
struct ExecutionContext {
    tx_hash: Hash,
    from: [u8; 32],
    to: [u8; 32],
    required_balance: u64,
    expected_nonce: u64,
    amount: u64,
    fee: u64,
    taint_distance: u16,
    taint_origin: u64,
    taint_timestamp: u64,
    restriction_level: u64,
}

/// Deterministic L2 state machine
pub struct L2State {
    balances: BTreeMap<[u8; 32], u64>,
    nonces: BTreeMap<[u8; 32], u64>,
    // TODO: Add TTL-based eviction for processed set in production
    processed: HashSet<Hash>,
    founder: [u8; 32],
    community_fund: [u8; 32],
    utxos: Vec<L2Utxo>,
    tx_count: u64,
    total_fees: u64,
}

impl L2State {
    pub fn new(founder: [u8; 32], community_fund: [u8; 32]) -> Self {
        Self {
            balances: BTreeMap::new(),
            nonces: BTreeMap::new(),
            processed: HashSet::new(),
            founder,
            community_fund,
            utxos: Vec::new(),
            tx_count: 0,
            total_fees: 0,
        }
    }

    #[inline]
    pub fn credit(&mut self, user: &[u8; 32], amount: u64) {
        let b = self.balances.entry(*user).or_insert(0);
        *b = b.saturating_add(amount);
    }

    #[inline]
    pub fn balance(&self, user: &[u8; 32]) -> u64 {
        self.balances.get(user).copied().unwrap_or(0)
    }

    #[inline]
    pub fn nonce(&self, user: &[u8; 32]) -> u64 {
        self.nonces.get(user).copied().unwrap_or(0)
    }

    /// Build deterministic execution context (no mutation).
    /// All data COPIED into context — no borrows into self remain.
    fn build_context(&self, tx: &L2Transaction) -> Result<ExecutionContext, L2StateError> {
        if !tx.is_valid() {
            return Err(L2StateError::InvalidSignature);
        }
        if tx.amount == 0 {
            return Err(L2StateError::AmountZero);
        }
        if self.processed.contains(&tx.tx_hash) {
            return Err(L2StateError::ReplayDetected);
        }

        let from = tx.from.to_bytes();
        let expected_nonce = self.nonce(&from);
        if tx.nonce != expected_nonce {
            return Err(L2StateError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        let available = self.balance(&from);
        let required = tx.amount.saturating_add(tx.fee);
        if available < required {
            return Err(L2StateError::InsufficientBalance {
                required,
                available,
            });
        }

        Ok(ExecutionContext {
            tx_hash: tx.tx_hash,
            from,
            to: tx.to.to_bytes(),
            required_balance: required,
            expected_nonce,
            amount: tx.amount,
            fee: tx.fee,
            taint_distance: tx.taint_distance,
            taint_origin: tx.taint_origin,
            taint_timestamp: tx.taint_timestamp,
            restriction_level: tx.restriction_level,
        })
    }

    /// Main deterministic execution path.
    /// No borrow conflict: context owns all data, no references into self.
    pub fn process_transaction(&mut self, tx: &L2Transaction) -> Result<Vec<L2Utxo>, L2StateError> {
        let ctx = self.build_context(tx)?;

        // Record as processed
        self.processed.insert(ctx.tx_hash);

        // Apply balances atomically
        {
            let from_bal = self.balances.entry(ctx.from).or_insert(0);
            *from_bal = from_bal.saturating_sub(ctx.required_balance);
            let to_bal = self.balances.entry(ctx.to).or_insert(0);
            *to_bal = to_bal.saturating_add(ctx.amount);
        }

        // Fee distribution
        let founder_cut = L2Transaction::founder_cut(ctx.fee);
        let community_cut = L2Transaction::community_cut(ctx.fee);

        let founder_bal = self.balance(&self.founder);
        *self.balances.entry(self.founder).or_insert(0) =
            founder_bal.saturating_add(founder_cut);

        let community_bal = self.balance(&self.community_fund);
        *self.balances.entry(self.community_fund).or_insert(0) =
            community_bal.saturating_add(community_cut);

        self.total_fees = self.total_fees.saturating_add(ctx.fee);

        // Nonce update
        self.nonces.insert(ctx.from, ctx.expected_nonce.saturating_add(1));

        // UTXO creation
        let to_pubkey = tx.to.clone();
        let utxo = L2Utxo::new(
            to_pubkey,
            ctx.amount,
            ctx.tx_hash,
            0,
            (ctx.taint_distance, ctx.taint_origin, ctx.taint_timestamp, ctx.restriction_level),
        );

        self.utxos.push(utxo.clone());
        self.tx_count = self.tx_count.saturating_add(1);

        Ok(vec![utxo])
    }

    pub fn stats(&self) -> L2Stats {
        L2Stats {
            accounts: self.balances.len(),
            transactions: self.tx_count,
            total_fees: self.total_fees,
            utxos: self.utxos.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct L2Stats {
    pub accounts: usize,
    pub transactions: u64,
    pub total_fees: u64,
    pub utxos: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevum::crypto::keys::Keypair;

    fn make_tx(kp: &Keypair, nonce: u64, amount: u64, fee: u64) -> L2Transaction {
        let mut tx = L2Transaction::new_unsigned(
            1, kp.public.clone(), kp.public.clone(),
            amount, fee, nonce, (0, 0, 0, 0), 100, 0,
        );
        tx.sign(kp);
        tx
    }

    #[test]
    fn valid_transaction() {
        let kp = Keypair::generate();
        let mut state = L2State::new([1u8; 32], [2u8; 32]);
        state.credit(&kp.public.to_bytes(), 10000);

        let tx = make_tx(&kp, 0, 1000, 100);
        let result = state.process_transaction(&tx);
        assert!(result.is_ok());
        // 10000 - 1000(amount) - 100(fee) + 1000(received) = 9900? 
        // Actually: sends 1000 to self, so balance = 10000 - 1100 + 1000 = 9900
        assert_eq!(state.balance(&kp.public.to_bytes()), 9900);
    }

    #[test]
    fn insufficient_balance_fails() {
        let kp = Keypair::generate();
        let mut state = L2State::new([1u8; 32], [2u8; 32]);
        state.credit(&kp.public.to_bytes(), 500);

        let tx = make_tx(&kp, 0, 1000, 100);
        let result = state.process_transaction(&tx);
        assert!(result.is_err());
    }

    #[test]
    fn replay_detected() {
        let kp = Keypair::generate();
        let mut state = L2State::new([1u8; 32], [2u8; 32]);
        state.credit(&kp.public.to_bytes(), 10000);

        let tx = make_tx(&kp, 0, 1000, 100);
        assert!(state.process_transaction(&tx).is_ok());
        assert_eq!(state.process_transaction(&tx), Err(L2StateError::ReplayDetected));
    }
}
