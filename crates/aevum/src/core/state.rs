use crate::core::block::Block;
use crate::core::jt_utxo::JtUtxo;
use crate::crypto::hash::Hash;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct UtxoSet {
    utxos: HashMap<Hash, JtUtxo>,
    state_root: Hash,
    total_supply: u64,
}

impl UtxoSet {
    pub fn new() -> Self {
        UtxoSet {
            utxos: HashMap::new(),
            state_root: Hash::zero(),
            total_supply: 0,
        }
    }

    pub fn add(&mut self, utxo: JtUtxo) {
        let nullifier = *utxo.nullifier();
        self.utxos.insert(nullifier, utxo);
        self.recompute_root();
    }

    pub fn remove(&mut self, nullifier: &Hash) -> Option<JtUtxo> {
        let result = self.utxos.remove(nullifier);
        self.recompute_root();
        result
    }

    pub fn contains(&self, nullifier: &Hash) -> bool {
        self.utxos.contains_key(nullifier)
    }
    pub fn len(&self) -> usize {
        self.utxos.len()
    }
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }
    pub fn state_root(&self) -> Hash {
        self.state_root
    }
    pub fn total_supply(&self) -> u64 {
        self.total_supply
    }
    pub fn all(&self) -> impl Iterator<Item = (&Hash, &JtUtxo)> {
        self.utxos.iter()
    }

    pub fn apply_block(&mut self, block: &Block) -> Result<Hash, &'static str> {
        let mut spent_in_block: Vec<&Hash> = Vec::new();
        for tx in &block.transactions {
            // TX processing logged
            for input in &tx.inputs {
                if spent_in_block.contains(&&input.nullifier) {
                    return Err("Double-spend within block");
                }
                spent_in_block.push(&input.nullifier);
                if self.remove(&input.nullifier).is_none() {
                    return Err("Input UTXO not found");
                }
            }
        }
        for tx in &block.transactions {
            // TX processing logged
            for output in &tx.outputs {
                let utxo = JtUtxo::from_tx_output(output, tx.tx_hash);
                self.add(utxo);
            }
        }
        self.total_supply = block.total_supply;
        Ok(self.state_root)
    }

    fn recompute_root(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_UTXO_SET_V1");
        let mut nullifiers: Vec<&Hash> = self.utxos.keys().collect();
        nullifiers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for nullifier in nullifiers {
            hasher.update(nullifier.as_bytes());
            if let Some(utxo) = self.utxos.get(nullifier) {
                hasher.update(utxo.amount_commitment().as_bytes());
                hasher.update(utxo.tag_commitment().as_bytes());
                hasher.update(utxo.owner().as_bytes());
            }
        }
        self.state_root = Hash(hasher.finalize().into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::jt_utxo::ZkProof;
    use crate::core::transaction::{Transaction, TxInput, TxOutput};
    use crate::crypto::keys::PublicKey;

    fn dummy_utxo(serial: u64) -> JtUtxo {
        let owner = PublicKey::dummy();
        JtUtxo::new_global_clean(
            owner.clone(),
            100,
            &[0u8; 32],
            &[1u8; 32],
            serial,
            Hash::zero(),
        )
    }

    #[test]
    fn apply_block_updates_total_supply() {
        let mut set = UtxoSet::new();
        let utxo = dummy_utxo(1);
        set.add(utxo.clone());
        let block = Block::new(Hash::zero(), 1, 0, 10, vec![], Hash::zero(), 21000000, None);
        set.apply_block(&block).unwrap();
        assert_eq!(set.total_supply(), 21000000);
    }
}
