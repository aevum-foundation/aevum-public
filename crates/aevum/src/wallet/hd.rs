use crate::core::address::AcceptancePolicy;
use crate::crypto::keys::{Keypair, PrivateKey, PublicKey};
use hmac::{Hmac, Mac};
use sha2::Sha512;

pub struct HdWallet {
    master_private: PrivateKey,
    chain_code: [u8; 32],
}

impl HdWallet {
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let mut hmac =
            Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").expect("HMAC can take key of any size");
        hmac.update(seed);
        let result = hmac.finalize().into_bytes();

        let mut master_private_bytes = [0u8; 32];
        let mut chain_code = [0u8; 32];
        master_private_bytes.copy_from_slice(&result[..32]);
        chain_code.copy_from_slice(&result[32..]);

        let master_private =
            PrivateKey::from_bytes(master_private_bytes).expect("Valid Ed25519 key from seed");

        HdWallet {
            master_private,
            chain_code,
        }
    }

    pub fn master_public(&self) -> PublicKey {
        self.master_private.public_key()
    }

    pub fn derive_child(&self, index: u32) -> (PrivateKey, [u8; 32]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.chain_code);
        hasher.update(&index.to_le_bytes());
        let hash = hasher.finalize();

        let mut child_private_bytes = [0u8; 32];
        child_private_bytes.copy_from_slice(&hash.as_bytes()[..32]);

        let mut hasher2 = blake3::Hasher::new();
        hasher2.update(b"chain_code_derivation");
        hasher2.update(&self.chain_code);
        hasher2.update(&index.to_le_bytes());
        let chain_hash = hasher2.finalize();

        let mut child_chain_code = [0u8; 32];
        child_chain_code.copy_from_slice(&chain_hash.as_bytes()[..32]);

        let child_private = PrivateKey::from_bytes(child_private_bytes).expect("Valid derived key");

        (child_private, child_chain_code)
    }

    pub fn derive_path(&self, path: &str) -> Result<(PrivateKey, [u8; 32]), &'static str> {
        let parts: Vec<&str> = path.split('/').filter(|p| *p != "m").collect();
        let mut current_private = self.master_private.clone();
        let mut current_chain = self.chain_code;

        for part in parts {
            let index: u32 = part.parse().map_err(|_| "Invalid derivation path")?;
            let wallet = HdWallet {
                master_private: current_private.clone(),
                chain_code: current_chain,
            };
            (current_private, current_chain) = wallet.derive_child(index);
        }

        Ok((current_private, current_chain))
    }

    pub fn derive_keypair(&self, index: u32) -> Keypair {
        let (private, _) = self.derive_child(index);
        Keypair::from_private(&private)
    }

    pub fn derive_address(
        &self,
        index: u32,
        policy: &AcceptancePolicy,
    ) -> crate::core::address::Address {
        let kp = self.derive_keypair(index);
        crate::core::address::Address::new(kp.public, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_seed_creates_master_keys() {
        let wallet = HdWallet::from_seed(&[42u8; 64]);
        assert!(!wallet.master_public().as_bytes().is_empty());
    }

    #[test]
    fn deterministic_derivation() {
        let wallet = HdWallet::from_seed(&[1u8; 64]);
        let (pk1, _) = wallet.derive_child(0);
        let (pk2, _) = wallet.derive_child(0);
        assert_eq!(pk1.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn different_indices_different_keys() {
        let wallet = HdWallet::from_seed(&[2u8; 64]);
        assert_ne!(
            wallet.derive_child(0).0.to_bytes(),
            wallet.derive_child(1).0.to_bytes()
        );
    }

    #[test]
    fn derive_path_works() {
        let wallet = HdWallet::from_seed(&[3u8; 64]);
        assert!(wallet.derive_path("m/0/1/2").is_ok());
    }

    #[test]
    fn derive_address_works() {
        let wallet = HdWallet::from_seed(&[4u8; 64]);
        let addr = wallet.derive_address(0, &AcceptancePolicy::AcceptAll);
        assert_eq!(addr.version, 0x01);
    }
}
