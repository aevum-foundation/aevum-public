use crate::crypto::hash::Hash;
use crate::oracle::zk_juris::ZkJurisdictionProof;

#[derive(Clone, Debug)]
pub struct ZkAcceptProof {
    pub policy_hash: Hash,
    pub tag_hash: Hash,
    pub accepted: bool,
    pub jurisdiction_hash: Option<Hash>,
    pub proof_data: Vec<u8>,
}

impl ZkAcceptProof {
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_ZK_ACCEPT_V1";

    pub fn create(
        policy_hash: &Hash,
        tag_bytes: &[u8],
        accepted: bool,
        jurisdiction_proof: Option<&ZkJurisdictionProof>,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(tag_bytes);
        let tag_hash = Hash(hasher.finalize().into());

        let jurisdiction_hash = jurisdiction_proof.map(|jp| jp.jurisdiction_hash);

        ZkAcceptProof {
            policy_hash: *policy_hash,
            tag_hash,
            accepted,
            jurisdiction_hash,
            proof_data: Vec::new(),
        }
    }

    pub fn verify(&self, expected_policy_hash: &Hash, expected_tag_hash: &Hash) -> bool {
        self.policy_hash == *expected_policy_hash
            && self.tag_hash == *expected_tag_hash
            && self.accepted
    }

    pub fn verify_with_jurisdiction(
        &self,
        expected_policy_hash: &Hash,
        expected_tag_hash: &Hash,
        expected_jurisdiction_hash: &Hash,
    ) -> bool {
        self.verify(expected_policy_hash, expected_tag_hash)
            && self.jurisdiction_hash == Some(*expected_jurisdiction_hash)
    }

    pub fn is_accepted(&self) -> bool {
        self.accepted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_verify_accepted() {
        let ph = Hash([1u8; 32]);
        let proof = ZkAcceptProof::create(&ph, b"test_tag", true, None);
        assert!(proof.is_accepted());
        assert!(proof.verify(&ph, &proof.tag_hash));
    }

    #[test]
    fn create_and_verify_rejected() {
        let ph = Hash([2u8; 32]);
        let proof = ZkAcceptProof::create(&ph, b"test_tag", false, None);
        assert!(!proof.is_accepted());
        assert!(!proof.verify(&ph, &proof.tag_hash));
    }

    #[test]
    fn verify_rejects_wrong_hash() {
        let ph = Hash([1u8; 32]);
        let proof = ZkAcceptProof::create(&ph, b"test_tag", true, None);
        let wrong = Hash([0xFF; 32]);
        assert!(!proof.verify(&wrong, &proof.tag_hash));
        assert!(!proof.verify(&ph, &wrong));
    }

    #[test]
    fn verify_with_jurisdiction() {
        let jp = ZkJurisdictionProof::create(b"NL", b"NLOK", true);
        let ph = Hash([3u8; 32]);
        let proof = ZkAcceptProof::create(&ph, b"tag", true, Some(&jp));
        assert!(proof.verify_with_jurisdiction(&ph, &proof.tag_hash, &jp.jurisdiction_hash));
    }

    #[test]
    fn verify_with_jurisdiction_rejects_wrong_jurisdiction() {
        let jp = ZkJurisdictionProof::create(b"NL", b"NLOK", true);
        let ph = Hash([3u8; 32]);
        let proof = ZkAcceptProof::create(&ph, b"tag", true, Some(&jp));
        let wrong = Hash([0xAA; 32]);
        assert!(!proof.verify_with_jurisdiction(&ph, &proof.tag_hash, &wrong));
    }

    #[test]
    fn different_tags_different_hashes() {
        let ph = Hash([1u8; 32]);
        let p1 = ZkAcceptProof::create(&ph, b"tag1", true, None);
        let p2 = ZkAcceptProof::create(&ph, b"tag2", true, None);
        assert_ne!(p1.tag_hash, p2.tag_hash);
    }
}
