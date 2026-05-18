use crate::crypto::keys::PublicKey;
use core::fmt;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub const fn zero() -> Self {
        Hash([0u8; 32])
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_utxo_components(
        owner: &PublicKey,
        amount_commitment: &AmountCommitment,
        tag_commitment: &TagCommitment,
        serial: u64,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(owner.as_bytes());
        hasher.update(amount_commitment.as_bytes());
        hasher.update(tag_commitment.as_bytes());
        hasher.update(&serial.to_le_bytes());
        Hash(hasher.finalize().into())
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.to_hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AmountCommitment([u8; 32]);

impl AmountCommitment {
    pub fn commit(amount: u64, blinding: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&amount.to_le_bytes());
        hasher.update(blinding);
        AmountCommitment(hasher.finalize().into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for AmountCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AmountCommitment({})", self.to_hex())
    }
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TagCommitment {
    commitment: [u8; 32],
}

impl TagCommitment {
    pub fn commit(serialized_level: &[u8], blinding: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(blinding);
        hasher.update(serialized_level);
        TagCommitment {
            commitment: hasher.finalize().into(),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.commitment
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.commitment)
    }
}

impl fmt::Debug for TagCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TagCommitment({})", self.to_hex())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_zero_constant() {
        assert_eq!(Hash::zero().0, [0u8; 32]);
    }

    #[test]
    fn amount_commitment_deterministic() {
        assert_eq!(
            AmountCommitment::commit(100, &[0u8; 32]),
            AmountCommitment::commit(100, &[0u8; 32])
        );
    }

    #[test]
    fn amount_commitment_hiding() {
        assert_ne!(
            AmountCommitment::commit(100, &[0u8; 32]),
            AmountCommitment::commit(100, &[1u8; 32])
        );
    }

    #[test]
    fn tag_commitment_deterministic() {
        assert_eq!(
            TagCommitment::commit(b"test", &[0u8; 32]),
            TagCommitment::commit(b"test", &[0u8; 32])
        );
    }

    #[test]
    fn tag_commitment_hiding() {
        assert_ne!(
            TagCommitment::commit(b"data", &[0u8; 32]),
            TagCommitment::commit(b"data", &[1u8; 32])
        );
    }
}

impl AmountCommitment {
    pub fn dummy() -> Self { AmountCommitment([0u8; 32]) }
}

impl TagCommitment {
    pub fn dummy() -> Self { TagCommitment { commitment: [0u8; 32] } }
}
