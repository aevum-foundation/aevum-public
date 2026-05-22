#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U384 { pub limbs: [u64; 6] }
pub const BLS_P: U384 = U384 { limbs: [0xb9feffffffffaaab, 0x1eabfffeb153ffff, 0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a] };
impl U384 {
    pub const fn zero() -> Self { U384 { limbs: [0; 6] } }
    pub const fn one() -> Self { U384 { limbs: [1, 0, 0, 0, 0, 0] } }
    pub fn add_mod(&self, o: &U384, p: &U384) -> U384 { let mut r = U384::zero(); let mut c: u64 = 0; for i in 0..6 { let (s1, c1) = self.limbs[i].overflowing_add(o.limbs[i]); let (s2, c2) = s1.overflowing_add(c); r.limbs[i] = s2; c = (c1 as u64)+(c2 as u64); } if c>0 || r.cmp(p)>=0 { r = r.sub(p); } r }
    pub fn sub_mod(&self, o: &U384, p: &U384) -> U384 { let mut r = U384::zero(); let mut b: u64 = 0; for i in 0..6 { let (d1, b1) = self.limbs[i].overflowing_sub(o.limbs[i]); let (d2, b2) = d1.overflowing_sub(b); r.limbs[i] = d2; b = (b1 as u64)+(b2 as u64); } if b>0 { r = r.add(p); } r }
    pub fn mul_mod(&self, o: &U384, p: &U384) -> U384 { let mut r = U384::zero(); for i in 0..6 { if o.limbs[i]==0 { continue; } let mut t = U384::zero(); let mut c: u64 = 0; for j in 0..6 { if i+j>=6 { break; } let prod = self.limbs[j] as u128 * o.limbs[i] as u128 + c as u128 + t.limbs[i+j] as u128; t.limbs[i+j] = prod as u64; c = (prod>>64) as u64; } r = r.add_mod(&t, p); } r }
    pub fn sub(&self, o: &U384) -> U384 { let mut r = U384::zero(); let mut b: u64 = 0; for i in 0..6 { let (d, bb) = self.limbs[i].overflowing_sub(o.limbs[i]+b); r.limbs[i] = d; b = bb as u64; } r }
    pub fn add(&self, o: &U384) -> U384 { let mut r = U384::zero(); let mut c: u64 = 0; for i in 0..6 { let s = self.limbs[i] as u128 + o.limbs[i] as u128 + c as u128; r.limbs[i] = s as u64; c = (s>>64) as u64; } r }
    pub fn cmp(&self, o: &U384) -> i32 { for i in (0..6).rev() { if self.limbs[i]>o.limbs[i] { return 1; } if self.limbs[i]<o.limbs[i] { return -1; } } 0 }
    pub fn is_zero(&self) -> bool { self.limbs.iter().all(|&x| x==0) }
    pub fn from_u64(v: u64) -> Self { let mut l = [0u64; 6]; l[0] = v; U384 { limbs: l } }
}
