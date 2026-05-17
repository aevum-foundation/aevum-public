pub use super::ed25519::{Keypair, PrivateKey, PublicKey};

impl PrivateKey {
    /// Diffie-Hellman общий секрет с публичным ключом пира
    pub fn diffie_hellman(&self, peer: &PublicKey) -> [u8; 32] {
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Sha512, Digest};
        
        // Конвертируем Ed25519 приватный ключ в scalar
        let hash = Sha512::digest(&self.to_bytes()[..32]);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[..32]);
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;
        let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        
        // Конвертируем публичный ключ в точку Curve25519
        let peer_bytes = peer.to_bytes();
        let mut peer_point_bytes = [0u8; 32];
        peer_point_bytes.copy_from_slice(&peer_bytes);
        let peer_point = CompressedEdwardsY(peer_point_bytes)
            .decompress()
            .unwrap_or_else(|| curve25519_dalek::edwards::EdwardsPoint::default());
        
        // DH: shared = scalar * peer_point
        let shared = (scalar * peer_point).compress();
        shared.0
    }
}
