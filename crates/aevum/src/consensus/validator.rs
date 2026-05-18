use crate::consensus::poh::PohGenerator;
use crate::core::block::Block;
use crate::core::state::UtxoSet;
use crate::crypto::hash::Hash;

#[derive(Clone, Debug)]
pub struct Validator {
    pub serial_counter: u64,
    utxo_set: UtxoSet,
    poh: PohGenerator,
    last_block_hash: Hash,
    last_block_height: u64,
    last_poh_tick_end: u64,
    genesis_applied: bool,
}

impl Validator {
    pub fn new(seed: &[u8]) -> Self {
        Validator {
            utxo_set: UtxoSet::new(),
            poh: PohGenerator::new(seed),
            last_block_hash: Hash::zero(),
            last_block_height: 0,
            last_poh_tick_end: 0,
            serial_counter: 0,
            genesis_applied: false,
        }
    }

    pub fn tick_poh(&mut self) {
        self.poh.tick();
    }

    pub fn validate_and_apply(&mut self, block: &mut Block) -> Result<(), Box<dyn std::error::Error>> {
        if !block.is_internal_valid() {
            return Err("Block internal validation failed".into());
        }

        // Проверка полезного решения
        if let Some(ref solution) = block.useful_solution {
            if !solution.verify() {
                return Err("Invalid useful solution".into());
            }
        }

        if block.is_genesis() {
            if self.genesis_applied {
                return Err("Genesis already applied".into());
            }
            let new_root = self.utxo_set.apply_block(block)?;
            block.state_root = new_root;
            block.block_hash = block.compute_hash();
            while self.poh.current_tick_number() < block.poh_tick_end {
                self.poh.tick();
            }
            self.last_block_hash = block.block_hash;
            self.last_block_height = block.height;
            self.last_poh_tick_end = block.poh_tick_end;
            self.genesis_applied = true;
            return Ok(());
        }

        if !self.genesis_applied {
            return Err("Genesis not applied yet".into());
        }
        if block.prev_hash != self.last_block_hash {
            return Err("Block prev_hash mismatch".into());
        }
        if block.height != self.last_block_height + 1 {
            return Err("Block height mismatch".into());
        }
        if block.poh_tick_start < self.last_poh_tick_end {
            return Err("PoH tick overlap".into());
        }

        while self.poh.current_tick_number() < block.poh_tick_start {
            self.poh.tick();
        }
        let new_root = self.utxo_set.apply_block(block)?;
        block.state_root = new_root;
        block.block_hash = block.compute_hash();
        while self.poh.current_tick_number() < block.poh_tick_end {
            self.poh.tick();
        }

        self.last_block_hash = block.block_hash;
        self.last_block_height = block.height;
        self.last_poh_tick_end = block.poh_tick_end;
        Ok(())
    }

    pub fn pre_validate(&self, block: &Block) -> Result<(), &'static str> {
        if !block.is_internal_valid() {
            return Err("Block internal validation failed".into());
        }
        if let Some(ref solution) = block.useful_solution {
            if !solution.verify() {
                return Err("Invalid useful solution".into());
            }
        }
        if block.is_genesis() {
            return if self.genesis_applied {
                Err("Genesis already applied".into())
            } else {
                Ok(())
            };
        }
        if !self.genesis_applied {
            return Err("Genesis not applied yet".into());
        }
        if block.prev_hash != self.last_block_hash {
            return Err("Block prev_hash mismatch".into());
        }
        if block.height != self.last_block_height + 1 {
            return Err("Block height mismatch".into());
        }
        if block.poh_tick_start < self.last_poh_tick_end {
            return Err("PoH tick overlap".into());
        }
        Ok(())
    }

    pub fn restore_poh_from_snapshot(&mut self, snap: &super::poh::PohSnapshot) {
        while self.poh.current_tick_number() < snap.tick_count {
            self.poh.tick();
        }
        self.last_poh_tick_end = snap.tick_count;
    }

    pub fn poh_snapshot(&self) -> super::poh::PohSnapshot {
        self.poh.snapshot()
    }

    pub fn snapshot(&self) -> ValidatorSnapshot {
        ValidatorSnapshot {
            last_block_hash: self.last_block_hash,
            last_block_height: self.last_block_height,
            last_poh_tick_end: self.last_poh_tick_end,
            genesis_applied: self.genesis_applied,
            poh_snapshot: self.poh.snapshot(),
        }
    }

    pub fn from_snapshot(snapshot: &ValidatorSnapshot, utxo_set: UtxoSet) -> Self {
        Validator {
            utxo_set,
            poh: PohGenerator::from_snapshot(&snapshot.poh_snapshot),
            last_block_hash: snapshot.last_block_hash,
            last_block_height: snapshot.last_block_height,
            last_poh_tick_end: snapshot.last_poh_tick_end,
            genesis_applied: snapshot.genesis_applied,
            serial_counter: 0,
        }
    }

    pub fn load_utxo_set(&mut self, utxo_set: UtxoSet) {
        self.utxo_set = utxo_set;
    }

    pub fn set_last_block(&mut self, hash: Hash, height: u64, poh_tick_end: u64) {
        self.last_block_hash = hash;
        self.last_block_height = height;
        self.last_poh_tick_end = poh_tick_end;
        self.genesis_applied = true;
    }

    pub fn utxo_set(&self) -> &UtxoSet {
        &self.utxo_set
    }
    pub fn last_block_hash(&self) -> Hash {
        self.last_block_hash
    }
    pub fn last_block_height(&self) -> u64 {
        self.last_block_height
    }
    pub fn last_poh_tick_end(&self) -> u64 {
        self.last_poh_tick_end
    }
    pub fn poh(&self) -> &PohGenerator {
        &self.poh
    }
}

#[derive(Clone, Debug)]
pub struct ValidatorSnapshot {
    pub last_block_hash: Hash,
    pub last_block_height: u64,
    pub last_poh_tick_end: u64,
    pub genesis_applied: bool,
    pub poh_snapshot: super::poh::PohSnapshot,
}
