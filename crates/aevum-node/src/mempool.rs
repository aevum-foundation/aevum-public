use aevum::core::transaction::Transaction;
use aevum::crypto::hash::Hash;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct Mempool {
    transactions: HashMap<Hash, Transaction>,
    spent_nullifiers: HashSet<Hash>,
    max_size: usize,
    min_poh_tick: u64,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Mempool {
            transactions: HashMap::new(),
            spent_nullifiers: HashSet::new(),
            max_size,
            min_poh_tick: 0,
        }
    }

    pub fn insert(&mut self, tx: Transaction) -> Result<(), &'static str> {
        if self.transactions.len() >= self.max_size {
            return Err("Mempool full");
        }
        if tx.poh_tick < self.min_poh_tick {
            return Err("Transaction too old");
        }
        for input in &tx.inputs {
            if self.spent_nullifiers.contains(&input.nullifier) {
                return Err("Double-spend detected in mempool");
            }
        }
        for input in &tx.inputs {
            self.spent_nullifiers.insert(input.nullifier);
        }
        let hash = tx.tx_hash;
        self.transactions.insert(hash, tx);
        Ok(())
    }

    pub fn remove(&mut self, tx_hash: &Hash) -> Option<Transaction> {
        let tx = self.transactions.remove(tx_hash)?;
        for input in &tx.inputs {
            self.spent_nullifiers.remove(&input.nullifier);
        }
        Some(tx)
    }

    pub fn remove_batch(&mut self, tx_hashes: &[Hash]) {
        for hash in tx_hashes {
            self.remove(hash);
        }
    }

    pub fn get(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.transactions.get(tx_hash)
    }

    pub fn take_batch(&mut self, max_count: usize) -> Vec<Transaction> {
        let mut txs: Vec<Transaction> = self.transactions.values().cloned().collect();
        txs.sort_by_key(|tx| tx.poh_tick);
        txs.truncate(max_count);
        for tx in &txs {
            self.remove(&tx.tx_hash);
        }
        txs
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
    pub fn contains(&self, tx_hash: &Hash) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    pub fn update_min_poh_tick(&mut self, poh_tick: u64) {
        self.min_poh_tick = poh_tick;
        let to_remove: Vec<Hash> = self
            .transactions
            .values()
            .filter(|tx| tx.poh_tick < self.min_poh_tick)
            .map(|tx| tx.tx_hash)
            .collect();
        self.remove_batch(&to_remove);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aevum::core::jt_utxo::ZkProof;
    use aevum::core::transaction::{TxInput, TxOutput};
    use aevum::crypto::hash::{AmountCommitment, TagCommitment};
    use aevum::crypto::keys::PublicKey;

    fn dummy_tx(poh_tick: u64, input_nullifier: Hash, output_nullifier: Hash) -> Transaction {
        let owner = PublicKey::dummy();
        let amount = AmountCommitment::commit(100, &[0u8; 32]);
        let tag = TagCommitment::commit(b"test", &[0u8; 32]);
        let input = TxInput {
            nonce: 0,
            tx_hash: Hash::zero(),
            output_index: 0,
            nullifier: input_nullifier,
            signature: vec![],
            public_key: owner.clone(),
            signed_hash: Hash::zero(),
        };
        let output = TxOutput {
            amount: 0,
            owner,
            amount_commitment: amount,
            tag_commitment: tag,
            nullifier: output_nullifier,
            serial: poh_tick,
            zk_proof: ZkProof::empty(),
            tx_hash: Hash::zero(),
            view_key_public: [0u8; 32],
            encrypted_amount: [0u8; 8],
            auth_tag: [0u8; 8],
        };
        Transaction::new(vec![input], vec![output], poh_tick)
    }

    #[test]
    fn insert_and_retrieve() {
        let mut pool = Mempool::new(100);
        let tx = dummy_tx(10, Hash([1u8; 32]), Hash([10u8; 32]));
        let hash = tx.tx_hash;
        pool.insert(tx.clone()).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&hash));
    }

    #[test]
    fn take_batch_sorts_by_poh_tick() {
        let mut pool = Mempool::new(100);
        pool.insert(dummy_tx(30, Hash([1u8; 32]), Hash([11u8; 32])))
            .unwrap();
        pool.insert(dummy_tx(10, Hash([2u8; 32]), Hash([12u8; 32])))
            .unwrap();
        pool.insert(dummy_tx(20, Hash([3u8; 32]), Hash([13u8; 32])))
            .unwrap();

        let batch = pool.take_batch(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].poh_tick, 10);
        assert_eq!(batch[1].poh_tick, 20);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_old_transactions() {
        let mut pool = Mempool::new(100);
        pool.update_min_poh_tick(50);
        let tx = dummy_tx(10, Hash([1u8; 32]), Hash([10u8; 32]));
        assert!(pool.insert(tx).is_err());
    }

    #[test]
    fn removes_old_on_update() {
        let mut pool = Mempool::new(100);
        pool.insert(dummy_tx(10, Hash([1u8; 32]), Hash([10u8; 32])))
            .unwrap();
        pool.insert(dummy_tx(60, Hash([2u8; 32]), Hash([12u8; 32])))
            .unwrap();
        pool.update_min_poh_tick(50);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn rejects_double_spend() {
        let mut pool = Mempool::new(100);
        pool.insert(dummy_tx(1, Hash([1u8; 32]), Hash([10u8; 32])))
            .unwrap();
        assert!(pool
            .insert(dummy_tx(2, Hash([1u8; 32]), Hash([11u8; 32])))
            .is_err());
    }

    #[test]
    fn remove_frees_nullifier() {
        let mut pool = Mempool::new(100);
        let tx = dummy_tx(1, Hash([5u8; 32]), Hash([15u8; 32]));
        let hash = tx.tx_hash;
        pool.insert(tx).unwrap();
        pool.remove(&hash);
        assert!(pool
            .insert(dummy_tx(2, Hash([5u8; 32]), Hash([16u8; 32])))
            .is_ok());
    }
}
