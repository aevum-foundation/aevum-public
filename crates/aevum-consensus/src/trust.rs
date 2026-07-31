//! Trust Model v6 — Deterministic Delegate Consensus (Production)
//!
//! ## v6 Upgrades
//! - trust_root: cryptographic commitment of delegates
//! - current_epoch + advance_epoch
//! - max_delegates + revoke
//! - quorum = 2/3 network_size
//! - verify_root for audit
//! - BTreeSet for determinism
//! - saturating_* everywhere

use serde::{Serialize, Deserialize};
use std::collections::BTreeSet;
use blake3;

pub const MAINNET_GENESIS_BOOTSTRAP: [u8; 32] = [
    0x9e, 0x3a, 0xe8, 0x84, 0x6e, 0x53, 0xf5, 0x1b,
    0x66, 0xed, 0xf3, 0xd9, 0xc6, 0x14, 0xfc, 0x76,
    0x65, 0x0f, 0xa9, 0x3b, 0xb9, 0x16, 0x20, 0xb4,
    0x7c, 0x44, 0xf9, 0x96, 0x79, 0x70, 0x0e, 0x30,
];

const DOMAIN_TRUST_ROOT: &[u8] = b"AEVUM_TRUST_ROOT_V6";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustModel {
    pub trust_version: u16,
    pub current_epoch: u64,
    pub genesis_bootstrap: [u8; 32],
    pub delegates: BTreeSet<[u8; 32]>,
    pub min_quorum: usize,
    pub max_quorum: usize,
    pub max_delegates: usize,
    pub trust_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError {
    NotAuthorized,
    AlreadyDelegate,
    DelegateLimitReached,
    VoterNotDelegate,
    NoQuorum { have: usize, need: usize },
}

impl Default for TrustModel {
    fn default() -> Self {
        let mut model = Self {
            trust_version: 1, current_epoch: 0,
            genesis_bootstrap: MAINNET_GENESIS_BOOTSTRAP,
            delegates: BTreeSet::new(),
            min_quorum: 3, max_quorum: 9, max_delegates: 10_000,
            trust_root: [0u8; 32],
        };
        model.recompute_trust_root();
        model
    }
}

impl TrustModel {
    pub fn new_genesis() -> Self {
        let mut model = Self::default();
        model.delegates.insert(MAINNET_GENESIS_BOOTSTRAP);
        model.recompute_trust_root();
        model
    }

    pub fn network_size(&self) -> usize { self.delegates.len().max(1) }

    pub fn quorum(&self) -> usize {
        let n = self.network_size();
        let q = ((n.saturating_mul(2)) / 3).max(self.min_quorum);
        q.min(self.max_quorum)
    }

    pub fn recompute_trust_root(&mut self) {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_TRUST_ROOT);
        h.update(&self.trust_version.to_le_bytes());
        h.update(&self.current_epoch.to_le_bytes());
        for d in &self.delegates { h.update(d); }
        self.trust_root = h.finalize().into();
    }

    pub fn trust_root(&self) -> [u8; 32] { self.trust_root }
    pub fn is_genesis(&self, pk: &[u8; 32]) -> bool { *pk == self.genesis_bootstrap }
    pub fn is_delegate(&self, pk: &[u8; 32]) -> bool { self.delegates.contains(pk) }
    pub fn can_endorse(&self, pk: &[u8; 32]) -> bool { self.is_genesis(pk) || self.is_delegate(pk) }

    pub fn delegate(
        &mut self, from: &[u8; 32], to: &[u8; 32], endorsements: &[[u8; 32]],
    ) -> Result<(), TrustError> {
        if self.is_delegate(to) { return Err(TrustError::AlreadyDelegate); }
        if self.delegates.len() >= self.max_delegates { return Err(TrustError::DelegateLimitReached); }
        if !self.can_endorse(from) { return Err(TrustError::NotAuthorized); }

        if self.is_genesis(from) {
            self.delegates.insert(*to);
            self.recompute_trust_root();
            return Ok(());
        }

        let quorum = self.quorum();
        let mut voters: BTreeSet<&[u8; 32]> = endorsements.iter().collect();
        voters.insert(from);

        for v in &voters { if !self.is_delegate(v) { return Err(TrustError::VoterNotDelegate); } }
        if voters.len() < quorum { return Err(TrustError::NoQuorum { have: voters.len(), need: quorum }); }

        self.delegates.insert(*to);
        self.recompute_trust_root();
        Ok(())
    }

    pub fn revoke(&mut self, delegate: &[u8; 32]) -> bool {
        let removed = self.delegates.remove(delegate);
        if removed { self.recompute_trust_root(); }
        removed
    }

    pub fn can_join(
        &self, candidate: &[u8; 32], endorsements: &[[u8; 32]],
    ) -> Result<(), TrustError> {
        if self.is_genesis(candidate) { return Ok(()); }
        if self.is_delegate(candidate) { return Err(TrustError::AlreadyDelegate); }
        let quorum = self.quorum();
        let voters: BTreeSet<&[u8; 32]> = endorsements.iter().collect();
        for v in &voters { if !self.can_endorse(v) { return Err(TrustError::VoterNotDelegate); } }
        if voters.len() < quorum { return Err(TrustError::NoQuorum { have: voters.len(), need: quorum }); }
        Ok(())
    }

    pub fn advance_epoch(&mut self) {
        self.current_epoch = self.current_epoch.saturating_add(1);
        self.recompute_trust_root();
    }

    pub fn verify_root(&self) -> bool {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN_TRUST_ROOT);
        h.update(&self.trust_version.to_le_bytes());
        h.update(&self.current_epoch.to_le_bytes());
        for d in &self.delegates { h.update(d); }
        let computed: [u8; 32] = h.finalize().into();
        computed == self.trust_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rpk(seed: u8) -> [u8; 32] { let mut pk = [0u8; 32]; pk[0] = seed; pk }

    #[test] fn test_genesis() { let m = TrustModel::new_genesis(); assert!(m.can_endorse(&MAINNET_GENESIS_BOOTSTRAP)); }
    #[test] fn test_delegate() { let mut m = TrustModel::new_genesis(); m.delegate(&MAINNET_GENESIS_BOOTSTRAP, &rpk(1), &[]).unwrap(); assert!(m.is_delegate(&rpk(1))); }
    #[test] fn test_quorum() {
        let mut m = TrustModel::new_genesis();
        let d1 = rpk(1); let d2 = rpk(2);
        m.delegate(&MAINNET_GENESIS_BOOTSTRAP, &d1, &[]).unwrap();
        m.delegate(&MAINNET_GENESIS_BOOTSTRAP, &d2, &[]).unwrap();
        assert_eq!(m.delegate(&d1, &rpk(3), &[d2]), Err(TrustError::NoQuorum { have: 2, need: 3 }));
    }
    #[test] fn test_verify_root() { let m = TrustModel::new_genesis(); assert!(m.verify_root()); }
}
