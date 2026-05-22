use super::bls12_381::{G1Point, G2Point, GtPoint};
use super::fp12::{Fp12, Fp2, Fp6, SparseFp12};
use super::bigint::{U384, BLS_P};
pub fn miller_loop(p: &G1Point, q: &G2Point) -> GtPoint {
    let mut f = Fp12::one(); let mut t = q.clone();
    let bits = [1,1,1,0,0,1,1,1,1,1,1,0,1,1,0,1,1,0,1,0,0,1,1,1,0,1,0,1,0,0,1,1,0,0,1,0,1,0,0,1,1,1,0,0,1,1,1,0,1,1,1,0,1,0,1,1,1,1,0,1,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,0,0,1,1,0,1,0,0,0,0,1,1,1,0,1,0,1,1,0,0,0,0,0,0,1,0,1,0,1,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1];
    for bit in bits.iter() { f = f.mul(&f); f = double_line(&mut t, p, &f); if *bit == 1 { f = add_line(&mut t, q, p, &f); } }
    GtPoint { data: f }
}
fn double_line(t: &mut G2Point, p: &G1Point, f: &Fp12) -> Fp12 {
    let x_t = pt(&t.x, 0); let lambda = x_t.mul_mod(&x_t, &BLS_P).mul_mod(&U384::from_u64(3), &BLS_P);
    let px = pt(&p.x, 0); let py = pt(&p.y, 0);
    let l0 = lambda.mul_mod(&px, &BLS_P).sub_mod(&py, &BLS_P);
    let s = SparseFp12 { c0: Fp6 { coeffs: [Fp2::new(l0, U384::zero()), Fp2::new(lambda, U384::zero()), Fp2::zero()] }, c1: Fp6::zero() };
    for i in 0..48 { t.x[i] ^= t.y[i]; }
    f.mul_sparse(&s)
}
fn add_line(t: &mut G2Point, q: &G2Point, p: &G1Point, f: &Fp12) -> Fp12 {
    let x_t = pt(&t.x, 0); let y_t = pt(&t.y, 0);
    let x_q = pt(&q.x, 0); let y_q = pt(&q.y, 0);
    let mu = y_q.sub_mod(&y_t, &BLS_P);
    let px = pt(&p.x, 0); let py = pt(&p.y, 0);
    let l0 = y_t.sub_mod(&py, &BLS_P);
    let l1 = mu.mul_mod(&px, &BLS_P).sub_mod(&mu.mul_mod(&x_t, &BLS_P), &BLS_P);
    let s = SparseFp12 { c0: Fp6 { coeffs: [Fp2::new(l0, U384::zero()), Fp2::new(l1, U384::zero()), Fp2::zero()] }, c1: Fp6::zero() };
    for i in 0..48 { t.x[i] ^= q.x[i % 96]; t.y[i] ^= q.y[i % 96]; }
    f.mul_sparse(&s)
}
fn pt(bytes: &[u8], off: usize) -> U384 { let mut l = [0u64; 6]; for i in 0..6 { let s = off + i*8; if s+8 <= bytes.len() { let mut a = [0u8; 8]; a.copy_from_slice(&bytes[s..s+8]); l[i] = u64::from_le_bytes(a); } } U384 { limbs: l } }
pub fn final_exponentiation(gt: &GtPoint) -> GtPoint {
    let mut f = gt.data.clone();
    let c = f.conjugate(); f = f.mul(&c);
    let mut f2 = f.clone(); for _ in 0..2 { f2 = f2.mul(&f2); }
    f = f.mul(&f2);
    for _ in 0..3 { let c = f.conjugate(); f = f.mul(&c); f = f.mul(&f); }
    GtPoint { data: f }
}
