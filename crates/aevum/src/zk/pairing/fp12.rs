use super::bigint::{U384, BLS_P};

#[derive(Clone, Debug, PartialEq)]
pub struct Fp12 { pub coeffs: [Fp6; 2] }

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fp6 { pub coeffs: [Fp2; 3] }

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Fp2 { pub c0: U384, pub c1: U384 }

impl Fp2 {
    pub fn new(c0: U384, c1: U384) -> Self { Fp2 { c0, c1 } }
    pub fn zero() -> Self { Fp2 { c0: U384::zero(), c1: U384::zero() } }
    pub fn one() -> Self { Fp2 { c0: U384::one(), c1: U384::zero() } }
    pub fn mul(&self, o: &Fp2) -> Fp2 {
        let ac = self.c0.mul_mod(&o.c0, &BLS_P);
        let bd = self.c1.mul_mod(&o.c1, &BLS_P);
        let ad = self.c0.mul_mod(&o.c1, &BLS_P);
        let bc = self.c1.mul_mod(&o.c0, &BLS_P);
        Fp2 { c0: ac.sub_mod(&bd, &BLS_P), c1: ad.add_mod(&bc, &BLS_P) }
    }
    pub fn add(&self, o: &Fp2) -> Fp2 {
        Fp2 { c0: self.c0.add_mod(&o.c0, &BLS_P), c1: self.c1.add_mod(&o.c1, &BLS_P) }
    }
    pub fn sub(&self, o: &Fp2) -> Fp2 {
        Fp2 { c0: self.c0.sub_mod(&o.c0, &BLS_P), c1: self.c1.sub_mod(&o.c1, &BLS_P) }
    }
}

impl Fp6 {
    pub fn zero() -> Self { Fp6 { coeffs: [Fp2::zero(); 3] } }
    pub fn one() -> Self { Fp6 { coeffs: [Fp2::one(), Fp2::zero(), Fp2::zero()] } }
    pub fn mul_by_fp2(&self, s: &Fp2) -> Fp6 {
        Fp6 { coeffs: [self.coeffs[0].mul(s), self.coeffs[1].mul(s), self.coeffs[2].mul(s)] }
    }
    pub fn add(&self, o: &Fp6) -> Fp6 {
        Fp6 { coeffs: [self.coeffs[0].add(&o.coeffs[0]), self.coeffs[1].add(&o.coeffs[1]), self.coeffs[2].add(&o.coeffs[2])] }
    }
}

fn fp6_mul(a: &Fp6, b: &Fp6) -> Fp6 {
    let a0b0 = a.coeffs[0].mul(&b.coeffs[0]);
    let a0b1 = a.coeffs[0].mul(&b.coeffs[1]);
    let a1b0 = a.coeffs[1].mul(&b.coeffs[0]);
    let a1b1_fp2 = a.coeffs[1].mul(&b.coeffs[1]);
    let a0b2 = a.coeffs[0].mul(&b.coeffs[2]);
    let a2b0 = a.coeffs[2].mul(&b.coeffs[0]);

    let t1 = a0b0.add(&a1b1_fp2);
    let t2 = a0b1.add(&a1b0).add(&a1b1_fp2);
    let t3 = a0b2.add(&a2b0).add(&a0b1);

    Fp6 { coeffs: [t1, t2, t3] }
}

impl Fp12 {
    pub fn zero() -> Self { Fp12 { coeffs: [Fp6::zero(), Fp6::zero()] } }
    pub fn one() -> Self { Fp12 { coeffs: [Fp6::one(), Fp6::zero()] } }

    pub fn mul(&self, o: &Fp12) -> Fp12 {
        let a0 = &self.coeffs[0]; let a1 = &self.coeffs[1];
        let b0 = &o.coeffs[0]; let b1 = &o.coeffs[1];
        let a0b0 = fp6_mul(a0, b0);
        let a1b1 = fp6_mul(a1, b1);
        let a0b1 = fp6_mul(a0, b1);
        let a1b0 = fp6_mul(a1, b0);
        Fp12 {
            coeffs: [
                a0b0.add(&a1b1.mul_by_fp2(&Fp2::one())),
                a0b1.add(&a1b0),
            ]
        }
    }

    pub fn conjugate(&self) -> Fp12 {
        Fp12 {
            coeffs: [
                self.coeffs[0].clone(),
                self.coeffs[1].mul_by_fp2(&Fp2::new(U384::zero(), U384::one())),
            ]
        }
    }
}

pub struct SparseFp12 { pub c0: Fp6, pub c1: Fp6 }

impl Fp12 {
    pub fn mul_sparse(&self, s: &SparseFp12) -> Fp12 {
        let a0 = &self.coeffs[0]; let a1 = &self.coeffs[1];
        let w0 = fp6_mul(a0, &s.c0).add(&fp6_mul(a1, &s.c1).mul_by_fp2(&Fp2::one()));
        let w1 = fp6_mul(a0, &s.c1).add(&fp6_mul(a1, &s.c0));
        Fp12 { coeffs: [w0, w1] }
    }
}
