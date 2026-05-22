use super::fp12::Fp12;
#[derive(Clone, Debug, PartialEq)]
pub struct G1Point { pub x: [u8; 48], pub y: [u8; 48] }
#[derive(Clone, Debug, PartialEq)]
pub struct G2Point { pub x: [u8; 96], pub y: [u8; 96] }
#[derive(Clone, Debug, PartialEq)]
pub struct GtPoint { pub data: Fp12 }
impl G1Point {
    pub fn from_bytes(d: &[u8]) -> Option<Self> { if d.len()!=96 { return None; } let mut x=[0u8;48]; x.copy_from_slice(&d[..48]); let mut y=[0u8;48]; y.copy_from_slice(&d[48..]); Some(G1Point{x,y}) }
    pub fn to_bytes(&self) -> Vec<u8> { let mut o=Vec::with_capacity(96); o.extend_from_slice(&self.x); o.extend_from_slice(&self.y); o }
}
impl G2Point {
    pub fn from_bytes(d: &[u8]) -> Option<Self> { if d.len()!=192 { return None; } let mut x=[0u8;96]; x.copy_from_slice(&d[..96]); let mut y=[0u8;96]; y.copy_from_slice(&d[96..]); Some(G2Point{x,y}) }
    pub fn to_bytes(&self) -> Vec<u8> { let mut o=Vec::with_capacity(192); o.extend_from_slice(&self.x); o.extend_from_slice(&self.y); o }
}
