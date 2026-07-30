//! LedgerEntry v1 — Универсальная запись леджера Aevum

use serde::{Deserialize, Serialize};
use crate::crypto::hash::Hash;
use crate::core::genesis::GenesisBlock;
use crate::core::presence::PresenceRecord;
use crate::core::settlement::SettlementBlock;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LedgerEntry {
    #[allow(dead_code)]
    Genesis(GenesisBlock),
    Presence(PresenceRecord),
    Settlement(SettlementBlock),
}

impl LedgerEntry {
    pub fn hash(&self) -> Hash {
        match self {
            LedgerEntry::Genesis(g) => g.block_hash,
            LedgerEntry::Presence(p) => p.record_hash,
            LedgerEntry::Settlement(s) => s.block_hash,
        }
    }

    pub fn is_settlement(&self) -> bool { matches!(self, LedgerEntry::Settlement(_)) }
    pub fn is_genesis(&self) -> bool { matches!(self, LedgerEntry::Genesis(_)) }
    pub fn is_presence(&self) -> bool { matches!(self, LedgerEntry::Presence(_)) }
}
