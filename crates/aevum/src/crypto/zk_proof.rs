use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;
use rand::RngCore;
use crate::crypto::hash::Hash;

#[derive(Clone, Debug)]
pub struct ZkProof {
    pub commitment: [u8; 32],
    pub challenge: [u8; 32],
    pub response: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ZkParams {
    pub g: RistrettoPoint,
    pub h_bytes: [u8; 32],
    pub task_hash: Hash,
    pub result_hash: Hash,
}

impl ZkParams {
    pub fn new(result: &[u8], task_hash: &Hash) -> Self {
        let g = RISTRETTO_BASEPOINT_POINT;
        let result_hash_full = Sha512::digest(result);
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&result_hash_full[..32]);
        let secret = Scalar::from_bytes_mod_order(secret_bytes);
        let h = g * secret;
        let h_bytes = h.compress().to_bytes();
        let mut result_hash_arr = [0u8; 32];
        result_hash_arr.copy_from_slice(&result_hash_full[32..64]);
        let result_hash = Hash(result_hash_arr);
        Self { g, h_bytes, task_hash: task_hash.clone(), result_hash }
    }

    pub fn h_point(&self) -> Option<RistrettoPoint> {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.h_bytes);
        let compressed = curve25519_dalek::ristretto::CompressedRistretto(arr);
        let opt: Option<RistrettoPoint> = compressed.decompress().into();
        opt
    }
}

pub fn prove(result: &[u8], task_hash: &Hash) -> ZkProof {
    let mut rng = OsRng;
    let g = RISTRETTO_BASEPOINT_POINT;
    let result_hash_full = Sha512::digest(result);
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&result_hash_full[..32]);
    let secret = Scalar::from_bytes_mod_order(secret_bytes);
    let h = g * secret;
    
    let mut r_bytes = [0u8; 32];
    rng.fill_bytes(&mut r_bytes);
    let r = Scalar::from_bytes_mod_order(r_bytes);
    
    let a = g * r;
    let a_bytes = a.compress().to_bytes();
    
    let challenge = {
        let mut hasher = Sha512::new();
        hasher.update(b"AEVUM_ZK_V4");
        hasher.update(g.compress().as_bytes());
        hasher.update(h.compress().as_bytes());
        hasher.update(&a_bytes);
        hasher.update(&task_hash.0);
        hasher.update(&result_hash_full[32..64]);
        let hash = hasher.finalize();
        let mut challenge_bytes = [0u8; 32];
        challenge_bytes.copy_from_slice(&hash[..32]);
        Scalar::from_bytes_mod_order(challenge_bytes)
    };
    
    let response = r + challenge * secret;
    ZkProof { commitment: a_bytes, challenge: challenge.to_bytes(), response: response.to_bytes() }
}

pub fn verify(params: &ZkParams, proof: &ZkProof) -> Result<bool, String> {
    let g = params.g;
    let h = params.h_point().ok_or("Invalid H")?;
    
    let a = {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&proof.commitment);
        let compressed = curve25519_dalek::ristretto::CompressedRistretto(arr);
        let opt: Option<RistrettoPoint> = compressed.decompress().into();
        opt.ok_or("Not on curve")?
    };
    
    let c = {
        let bytes = proof.challenge;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or("Invalid challenge")?
    };
    let s = {
        let bytes = proof.response;
        Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes)).ok_or("Invalid response")?
    };
    
    let expected_c = {
        let mut hasher = Sha512::new();
        hasher.update(b"AEVUM_ZK_V4");
        hasher.update(g.compress().as_bytes());
        hasher.update(h.compress().as_bytes());
        hasher.update(&proof.commitment);
        hasher.update(&params.task_hash.0);
        hasher.update(&params.result_hash.0);
        let hash = hasher.finalize();
        let mut cb = [0u8; 32];
        cb.copy_from_slice(&hash[..32]);
        Scalar::from_bytes_mod_order(cb)
    };
    
    if c != expected_c { return Ok(false); }
    
    let left = g * s;
    let right = a + h * c;
    Ok(left.compress().to_bytes() == right.compress().to_bytes())
}

pub fn verify_proof(h_bytes: &[u8; 32], result_hash: &Hash, task_hash: &Hash, proof_bytes: &[u8]) -> Result<bool, String> {
    if proof_bytes.len() != 96 { return Err("Proof must be 96 bytes".into()); }
    let mut commitment = [0u8; 32]; commitment.copy_from_slice(&proof_bytes[..32]);
    let mut challenge = [0u8; 32]; challenge.copy_from_slice(&proof_bytes[32..64]);
    let mut response = [0u8; 32]; response.copy_from_slice(&proof_bytes[64..96]);
    let proof = ZkProof { commitment, challenge, response };
    let params = ZkParams { g: RISTRETTO_BASEPOINT_POINT, h_bytes: *h_bytes, task_hash: task_hash.clone(), result_hash: result_hash.clone() };
    verify(&params, &proof)
}

pub fn proof_to_bytes(proof: &ZkProof) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(&proof.commitment);
    bytes.extend_from_slice(&proof.challenge);
    bytes.extend_from_slice(&proof.response);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_valid() {
        let r = b"test_result";
        let th = Hash([0xAA; 32]);
        let p = ZkParams::new(r, &th);
        let pr = prove(r, &th);
        assert!(verify(&p, &pr).unwrap());
    }

    #[test]
    fn test_zk_wrong_result() {
        let th = Hash([0xAA; 32]);
        let p = ZkParams::new(b"correct", &th);
        let pr = prove(b"wrong", &th);
        assert!(!verify(&p, &pr).unwrap());
    }

    #[test]
    fn test_zk_malleability() {
        let th = Hash([0xBB; 32]);
        let p = ZkParams::new(b"test", &th);
        let mut pr = prove(b"test", &th);
        pr.challenge[0] ^= 1;
        assert!(!verify(&p, &pr).unwrap());
    }

    #[test]
    fn test_zk_serialization() {
        let th = Hash([0xCC; 32]);
        let p = ZkParams::new(b"test", &th);
        let pr = prove(b"test", &th);
        let bytes = proof_to_bytes(&pr);
        assert_eq!(bytes.len(), 96);
        assert!(verify_proof(&p.h_bytes, &p.result_hash, &th, &bytes).unwrap());
    }
}
