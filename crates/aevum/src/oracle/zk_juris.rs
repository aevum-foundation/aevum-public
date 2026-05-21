use crate::crypto::hash::Hash;

#[derive(Clone, Debug)]
pub struct ZkJurisdictionProof {
    pub jurisdiction_hash: Hash,
    pub country_code: [u8; 2],
    pub tag: [u8; 4],
    pub is_allowed: bool,
    pub proof_data: Vec<u8>,
}

impl ZkJurisdictionProof {
    pub fn create(country_code: &[u8; 2], tag: &[u8; 4], is_allowed: bool) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(country_code);
        hasher.update(tag);
        let jurisdiction_hash = Hash(hasher.finalize().into());
        ZkJurisdictionProof {
            jurisdiction_hash,
            country_code: *country_code,
            tag: *tag,
            is_allowed,
            proof_data: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_proof() {
        let proof = ZkJurisdictionProof::create(b"NL", b"NLOK", true);
        assert!(proof.is_allowed);
        assert_eq!(proof.country_code, *b"NL");
    }

    #[test]
    fn different_inputs_different_hashes() {
        let p1 = ZkJurisdictionProof::create(b"NL", b"NLOK", true);
        let p2 = ZkJurisdictionProof::create(b"US", b"NLOK", true);
        assert_ne!(p1.jurisdiction_hash, p2.jurisdiction_hash);
    }
}
