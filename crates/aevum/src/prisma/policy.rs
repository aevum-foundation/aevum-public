use crate::core::address::AcceptancePolicy;
use crate::crypto::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub policy: AcceptancePolicy,
    pub policy_hash: Hash,
    pub version: u8,
}

impl Policy {
    const CURRENT_VERSION: u8 = 0x01;
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_POLICY_V1";

    pub fn new(policy: AcceptancePolicy) -> Self {
        let serialized = policy.serialize();
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&[Self::CURRENT_VERSION]);
        hasher.update(&serialized);
        let policy_hash = Hash(hasher.finalize().into());
        Policy {
            policy,
            policy_hash,
            version: Self::CURRENT_VERSION,
        }
    }

    pub fn verify_hash(&self) -> bool {
        let serialized = self.policy.serialize();
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&[self.version]);
        hasher.update(&serialized);
        Hash(hasher.finalize().into()) == self.policy_hash
    }

    pub fn from_bytes(_bytes: &[u8]) -> Result<Self, &'static str> {
        Err("Bytes deserialization not implemented in v0.1")
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::AcceptanceRule;
    use crate::core::jt_utxo::RestrictionLevel;

    #[test]
    fn policy_creation_and_verification() {
        let p = Policy::new(AcceptancePolicy::Whitelist(vec![AcceptanceRule::Level(
            RestrictionLevel::GlobalClean,
        )]));
        assert!(p.verify_hash());
    }

    #[test]
    fn policy_hash_deterministic() {
        let p1 = Policy::new(AcceptancePolicy::AcceptAll);
        let p2 = Policy::new(AcceptancePolicy::AcceptAll);
        assert_eq!(p1.policy_hash, p2.policy_hash);
    }

    #[test]
    fn policy_hash_changes_with_content() {
        let p1 = Policy::new(AcceptancePolicy::AcceptAll);
        let p2 = Policy::new(AcceptancePolicy::RejectAll);
        assert_ne!(p1.policy_hash, p2.policy_hash);
    }

    #[test]
    fn verify_hash_detects_tampering() {
        let mut p = Policy::new(AcceptancePolicy::AcceptAll);
        p.policy = AcceptancePolicy::RejectAll;
        assert!(!p.verify_hash());
    }

    #[test]
    fn json_stubs() {
        let p = Policy::new(AcceptancePolicy::AcceptAll);
        assert!(p.to_bytes().is_empty());
        assert!(Policy::from_bytes(&[]).is_err());
    }
}
