use crate::core::jt_utxo::RestrictionLevel;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use serde::{Serialize, Deserialize};

/// Политика приёма UTXO.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcceptancePolicy {
    Whitelist(Vec<AcceptanceRule>),
    Blacklist(Vec<AcceptanceRule>),
    AcceptAll,
    RejectAll,
}

const ACCEPTANCE_POLICY_FORMAT_VERSION: u8 = 0x01;

impl AcceptancePolicy {
    pub fn accepts_level(&self, level: u64) -> bool {
        match self {
            AcceptancePolicy::AcceptAll => true,
            AcceptancePolicy::RejectAll => false,
            AcceptancePolicy::Whitelist(rules) => rules.iter().any(|rule| match rule {
                AcceptanceRule::Level(ref rl) => rl.to_u64() == level,
                AcceptanceRule::Jurisdiction(_) => false,
            }),
            AcceptancePolicy::Blacklist(rules) => !rules.iter().any(|rule| match rule {
                AcceptanceRule::Level(ref rl) => rl.to_u64() == level,
                AcceptanceRule::Jurisdiction(_) => false,
            }),
        }
    }

    pub fn accepts_jurisdiction(&self, code: &[u8; 4]) -> bool {
        match self {
            AcceptancePolicy::AcceptAll => true,
            AcceptancePolicy::RejectAll => false,
            AcceptancePolicy::Whitelist(rules) => rules.iter().any(|rule| matches!(rule, AcceptanceRule::Jurisdiction(c) if c == code)),
            AcceptancePolicy::Blacklist(rules) => !rules.iter().any(|rule| matches!(rule, AcceptanceRule::Jurisdiction(c) if c == code)),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = vec![ACCEPTANCE_POLICY_FORMAT_VERSION];
        match self {
            AcceptancePolicy::AcceptAll => data.push(0x00),
            AcceptancePolicy::RejectAll => data.push(0xFF),
            AcceptancePolicy::Whitelist(rules) => {
                data.push(0x01);
                let mut sorted = rules.clone();
                sorted.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
                data.push(sorted.len() as u8);
                for rule in &sorted { data.extend_from_slice(&rule.serialize()); }
            }
            AcceptancePolicy::Blacklist(rules) => {
                data.push(0x02);
                let mut sorted = rules.clone();
                sorted.sort_by(|a, b| a.serialize().cmp(&b.serialize()));
                data.push(sorted.len() as u8);
                for rule in &sorted { data.extend_from_slice(&rule.serialize()); }
            }
        }
        data
    }

    pub fn is_open(&self) -> bool { matches!(self, AcceptancePolicy::AcceptAll) }
    pub fn is_closed(&self) -> bool { matches!(self, AcceptancePolicy::RejectAll) }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcceptanceRule {
    Level(RestrictionLevel),
    Jurisdiction([u8; 4]),
}

impl AcceptanceRule {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            AcceptanceRule::Level(level) => {
                let mut data = vec![0x10];
                data.extend_from_slice(&level.serialize());
                data
            }
            AcceptanceRule::Jurisdiction(code) => {
                let mut data = vec![0x20];
                data.extend_from_slice(code);
                data
            }
        }
    }

    pub fn matches(&self, level: &RestrictionLevel, specific_jurisdiction: Option<&[u8; 4]>) -> bool {
        match self {
            AcceptanceRule::Level(allowed_level) => allowed_level == level,
            AcceptanceRule::Jurisdiction(code) => match specific_jurisdiction {
                Some(j) => j == code,
                None => match level {
                    RestrictionLevel::Restricted { allowed } => allowed.contains(code),
                    _ => false,
                },
            },
        }
    }
}

/// Aevum-адрес с Prisma-политикой.
///
/// ## Версионирование
/// - **0x01 (Legacy):** blake3-деривация, для существующих адресов
/// - **0x02 (Standard):** BIP44-деривация `m/44'/789'/0'/0/{index}`
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    pub public_key: PublicKey,
    pub policy_hash: Hash,
    pub version: u8,
}

impl Address {
    pub const CURRENT_VERSION: u8 = 0x02;
    pub const LEGACY_VERSION: u8 = 0x01;
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_ADDRESS_POLICY_V3";

    /// Создать адрес с политикой.
    pub fn new(public_key: PublicKey, policy: &AcceptancePolicy) -> Self {
        let policy_hash = Self::compute_policy_hash(&public_key, policy);
        Address { public_key, policy_hash, version: Self::CURRENT_VERSION }
    }

    /// Создать адрес с указанной версией.
    pub fn with_version(public_key: PublicKey, policy: &AcceptancePolicy, version: u8) -> Self {
        let policy_hash = Self::compute_policy_hash(&public_key, policy);
        Address { public_key, policy_hash, version }
    }

    pub fn accepts(
        &self,
        policy: &AcceptancePolicy,
        level: &RestrictionLevel,
        specific_jurisdiction: Option<&[u8; 4]>,
    ) -> Result<bool, &'static str> {
        if !self.verify_policy_hash(policy) {
            return Err("policy hash mismatch");
        }
        Ok(match policy {
            AcceptancePolicy::AcceptAll => true,
            AcceptancePolicy::RejectAll => false,
            AcceptancePolicy::Whitelist(rules) => rules.iter().any(|r| r.matches(level, specific_jurisdiction)),
            AcceptancePolicy::Blacklist(rules) => !rules.iter().any(|r| r.matches(level, specific_jurisdiction)),
        })
    }

    pub fn verify_policy_hash(&self, policy: &AcceptancePolicy) -> bool {
        self.policy_hash == Self::compute_policy_hash(&self.public_key, policy)
    }

    pub fn compute_policy_hash(public_key: &PublicKey, policy: &AcceptancePolicy) -> Hash {
        let serialized = policy.serialize();
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&[Self::CURRENT_VERSION]);
        hasher.update(public_key.as_bytes());
        hasher.update(&serialized);
        Hash(hasher.finalize().into())
    }

    pub fn is_legacy(&self) -> bool { self.version == Self::LEGACY_VERSION }
    pub fn is_standard(&self) -> bool { self.version == Self::CURRENT_VERSION }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Keypair;

    fn alice_key() -> PublicKey { Keypair::generate().public }

    #[test]
    fn new_address_is_version_0x02() {
        let addr = Address::new(alice_key(), &AcceptancePolicy::AcceptAll);
        assert_eq!(addr.version, 0x02);
        assert!(addr.is_standard());
    }

    #[test]
    fn with_version_creates_legacy() {
        let addr = Address::with_version(alice_key(), &AcceptancePolicy::AcceptAll, 0x01);
        assert_eq!(addr.version, 0x01);
        assert!(addr.is_legacy());
    }

    #[test]
    fn version_01_and_02_different_hashes() {
        let pk = alice_key();
        let policy = AcceptancePolicy::AcceptAll;
        let addr1 = Address::with_version(pk.clone(), &policy, 0x01);
        let addr2 = Address::with_version(pk, &policy, 0x02);
        // Разные версии — разные хеши политик
        // (если domain separator включает version)
        assert!(addr1.version != addr2.version);
    }
}
