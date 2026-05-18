use crate::core::jt_utxo::RestrictionLevel;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[derive(serde::Serialize, serde::Deserialize)]
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
            AcceptancePolicy::Whitelist(rules) => {
                rules.iter().any(|rule| match rule {
                    AcceptanceRule::Level(ref rl) => rl.to_u64() == level,
                    AcceptanceRule::Jurisdiction(_) => false,
                })
            }
            AcceptancePolicy::Blacklist(rules) => {
                !rules.iter().any(|rule| match rule {
                    AcceptanceRule::Level(ref rl) => rl.to_u64() == level,
                    AcceptanceRule::Jurisdiction(_) => false,
                })
            }
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data = vec![ACCEPTANCE_POLICY_FORMAT_VERSION];
        match self {
            AcceptancePolicy::AcceptAll => data.push(0x00),
            AcceptancePolicy::RejectAll => data.push(0xFF),
            AcceptancePolicy::Whitelist(rules) => {
                data.push(0x01);
                data.push(rules.len() as u8);
                for rule in rules { data.extend_from_slice(&rule.serialize()); }
            }
            AcceptancePolicy::Blacklist(rules) => {
                data.push(0x02);
                data.push(rules.len() as u8);
                for rule in rules { data.extend_from_slice(&rule.serialize()); }
            }
        }
        data
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[derive(serde::Serialize, serde::Deserialize)]
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

    pub fn matches(
        &self,
        level: &RestrictionLevel,
        specific_jurisdiction: Option<&[u8; 4]>,
    ) -> bool {
        match self {
            AcceptanceRule::Level(allowed_level) => allowed_level == level,
            AcceptanceRule::Jurisdiction(code) => match specific_jurisdiction {
                Some(j) => j == code,
                None => {
                    if let RestrictionLevel::Restricted { allowed } = level {
                        allowed.contains(code)
                    } else { false }
                }
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    pub public_key: PublicKey,
    pub policy_hash: Hash,
    pub version: u8,
}

impl Address {
    pub const CURRENT_VERSION: u8 = 0x01;
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_ADDRESS_POLICY_V1";

    pub fn new(public_key: PublicKey, policy: &AcceptancePolicy) -> Self {
        let serialized = policy.serialize();
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&[Self::CURRENT_VERSION]);
        hasher.update(public_key.as_bytes());
        hasher.update(&serialized);
        let policy_hash = Hash(hasher.finalize().into());
        Address { public_key, policy_hash, version: Self::CURRENT_VERSION }
    }

    pub fn accepts(
        &self,
        policy: &AcceptancePolicy,
        level: &RestrictionLevel,
        specific_jurisdiction: Option<&[u8; 4]>,
    ) -> bool {
        match policy {
            AcceptancePolicy::AcceptAll => true,
            AcceptancePolicy::RejectAll => false,
            AcceptancePolicy::Whitelist(rules) => rules.iter().any(|rule| rule.matches(level, specific_jurisdiction)),
            AcceptancePolicy::Blacklist(rules) => !rules.iter().any(|rule| rule.matches(level, specific_jurisdiction)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice_key() -> PublicKey { crate::crypto::keys::PrivateKey::generate().public_key() }
    
    fn check_accepts(policy: &AcceptancePolicy, level: &RestrictionLevel, specific_jurisdiction: Option<&[u8; 4]>) -> bool {
        let addr = Address::new(PublicKey::dummy(), policy);
        addr.accepts(policy, level, specific_jurisdiction)
    }

    #[test]
    fn address_creation_consistent_hash() {
        let pk = alice_key();
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Level(RestrictionLevel::GlobalClean)]);
        assert_eq!(Address::new(pk.clone(), &p).policy_hash, Address::new(pk, &p).policy_hash);
    }

    #[test]
    fn different_policy_different_hash() {
        let pk = alice_key();
        assert_ne!(Address::new(pk.clone(), &AcceptancePolicy::AcceptAll).policy_hash, Address::new(pk, &AcceptancePolicy::RejectAll).policy_hash);
    }

    #[test]
    fn whitelist_accepts_matching_level() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Level(RestrictionLevel::GlobalClean)]);
        assert!(check_accepts(&p, &RestrictionLevel::GlobalClean, None));
    }

    #[test]
    fn whitelist_rejects_non_matching_level() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Level(RestrictionLevel::GlobalClean)]);
        assert!(!check_accepts(&p, &RestrictionLevel::ProvenanceNull, None));
    }

    #[test]
    fn blacklist_rejects_listed_level() {
        let p = AcceptancePolicy::Blacklist(vec![AcceptanceRule::Level(RestrictionLevel::ProvenanceNull)]);
        assert!(!check_accepts(&p, &RestrictionLevel::ProvenanceNull, None));
    }

    #[test]
    fn blacklist_accepts_unlisted_level() {
        let p = AcceptancePolicy::Blacklist(vec![AcceptanceRule::Level(RestrictionLevel::ProvenanceNull)]);
        assert!(check_accepts(&p, &RestrictionLevel::GlobalClean, None));
    }

    #[test]
    fn accept_all_always_accepts() {
        assert!(check_accepts(&AcceptancePolicy::AcceptAll, &RestrictionLevel::ProvenanceNull, None));
    }

    #[test]
    fn reject_all_always_rejects() {
        assert!(!check_accepts(&AcceptancePolicy::RejectAll, &RestrictionLevel::GlobalClean, None));
    }

    #[test]
    fn jurisdiction_rule_matches_restricted_utxo() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Jurisdiction(*b"NLOK")]);
        let l = RestrictionLevel::Restricted { allowed: vec![*b"NLOK", *b"DEOK"] };
        assert!(check_accepts(&p, &l, None));
    }

    #[test]
    fn jurisdiction_rule_rejects_non_matching() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Jurisdiction(*b"USOK")]);
        let l = RestrictionLevel::Restricted { allowed: vec![*b"NLOK"] };
        assert!(!check_accepts(&p, &l, None));
    }
}
