mod hd;
pub use hd::HdWallet;

use crate::core::address::{AcceptancePolicy, Address};
use crate::crypto::keys::{Keypair, PrivateKey, PublicKey};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};

pub struct Mnemonic {
    pub words: Vec<String>,
}

impl Mnemonic {
    pub fn generate() -> Self {
        let mut entropy = [0u8; 16];
        rand::thread_rng().fill(&mut entropy);
        Self::from_entropy(&entropy)
    }

    fn from_entropy(entropy: &[u8]) -> Self {
        let wordlist = include_str!("../../assets/bip39_english.txt");
        let words_list: Vec<&str> = wordlist.lines().collect();
        let hash = Sha256::digest(entropy);
        let checksum_bits = entropy.len() / 4;
        let checksum = (hash[0] >> (8 - checksum_bits)) as u16;
        let mut bits = vec![];
        for byte in entropy {
            for i in (0..8).rev() {
                bits.push((byte >> i) & 1);
            }
        }
        for i in (0..checksum_bits).rev() {
            bits.push(((checksum >> i) & 1) as u8);
        }
        let mut mnemonic = Vec::new();
        for chunk in bits.chunks(11) {
            let mut index = 0u16;
            for bit in chunk {
                index = (index << 1) | (*bit as u16);
            }
            mnemonic.push(words_list[index as usize].to_string());
        }
        Mnemonic { words: mnemonic }
    }

    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mnemonic_str = self.words.join(" ");
        let salt = format!("mnemonic{}", passphrase);
        let mut seed = [0u8; 64];
        pbkdf2::<Hmac<Sha512>>(mnemonic_str.as_bytes(), salt.as_bytes(), 2048, &mut seed)
            .expect("PBKDF2 failed");
        seed
    }
}

pub struct Wallet {
    hd: HdWallet,
}

impl Wallet {
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        Wallet {
            hd: HdWallet::from_seed(seed),
        }
    }

    pub fn new() -> (Self, Mnemonic) {
        let mnemonic = Mnemonic::generate();
        let seed = mnemonic.to_seed("");
        (Self::from_seed(&seed), mnemonic)
    }

    pub fn create_address(&self, policy: &AcceptancePolicy) -> Address {
        self.hd.derive_address(0, policy)
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let kp = self.hd.derive_keypair(0);
        kp.sign(message).to_vec()
    }

    pub fn public_key(&self) -> PublicKey {
        self.hd.master_public()
    }

    pub fn derive_keypair(&self, index: u32) -> Keypair {
        self.hd.derive_keypair(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_mnemonic_and_seed() {
        let mnemonic = Mnemonic::generate();
        assert_eq!(mnemonic.words.len(), 12);
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn wallet_from_seed_creates_address() {
        let wallet = Wallet::from_seed(&[42u8; 64]);
        let addr = wallet.create_address(&AcceptancePolicy::AcceptAll);
        assert_eq!(addr.version, 0x01);
    }

    #[test]
    fn sign_is_deterministic() {
        let wallet = Wallet::from_seed(&[7u8; 64]);
        let sig1 = wallet.sign(b"hello");
        let sig2 = wallet.sign(b"hello");
        assert_eq!(sig1, sig2);
    }
}
