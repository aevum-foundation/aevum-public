use crate::crypto::hash::Hash;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct PohGenerator {
    current_hash: Hash,
    tick_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PohTick {
    pub tick_number: u64,
    pub hash: Hash,
}

impl PohGenerator {
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_POH_TICK_V1";

    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(b"GENESIS");
        hasher.update(seed);
        PohGenerator {
            current_hash: Hash(hasher.finalize().into()),
            tick_count: 0,
        }
    }

    pub fn tick(&mut self) -> PohTick {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(self.current_hash.as_bytes());
        hasher.update(&self.tick_count.to_le_bytes());
        let tick_hash = Hash(hasher.finalize().into());
        self.current_hash = tick_hash;
        self.tick_count += 1;
        PohTick {
            tick_number: self.tick_count,
            hash: tick_hash,
        }
    }

    pub fn verify_tick_chain(tick1: &PohTick, tick2: &PohTick) -> bool {
        if tick2.tick_number != tick1.tick_number + 1 {
            return false;
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(tick1.hash.as_bytes());
        hasher.update(&tick1.tick_number.to_le_bytes());
        Hash(hasher.finalize().into()) == tick2.hash
    }

    pub fn verify_tick_chain_multi(ticks: &[PohTick]) -> bool {
        if ticks.len() < 2 {
            return true;
        }
        for i in 0..(ticks.len() - 1) {
            if !Self::verify_tick_chain(&ticks[i], &ticks[i + 1]) {
                return false;
            }
        }
        true
    }

    pub fn current_tick_number(&self) -> u64 {
        self.tick_count
    }
    pub fn current_hash(&self) -> Hash {
        self.current_hash
    }
    pub fn snapshot(&self) -> PohSnapshot {
        PohSnapshot {
            hash: self.current_hash,
            tick_count: self.tick_count,
        }
    }
    pub fn from_snapshot(snapshot: &PohSnapshot) -> Self {
        PohGenerator {
            current_hash: snapshot.hash,
            tick_count: snapshot.tick_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PohSnapshot {
    pub hash: Hash,
    pub tick_count: u64,
}
