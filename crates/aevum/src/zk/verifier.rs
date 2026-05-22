use crate::crypto::hash::Hash;
use super::pairing::bls12_381::{G1Point, G2Point};
use super::pairing::verifier::verify_groth16;
use super::pairing::miller::miller_loop;
pub fn verify_proof(proof: &[u8], verification_key: &Hash) -> bool {
    if proof.len() < 384 { return false; }
    let a = match G1Point::from_bytes(&proof[..96]) { Some(p) => p, None => return false };
    let b = match G2Point::from_bytes(&proof[96..288]) { Some(p) => p, None => return false };
    let c = match G1Point::from_bytes(&proof[288..384]) { Some(p) => p, None => return false };
    let vk = verification_key.as_bytes();
    let alpha_beta = miller_loop(&a, &b).data;
    let gamma = G2Point { x: [2u8; 96], y: [2u8; 96] };
    let delta = G2Point { x: [3u8; 96], y: [3u8; 96] };
    verify_groth16(&a, &b, &c, &alpha_beta, &gamma, &delta, &[])
}
