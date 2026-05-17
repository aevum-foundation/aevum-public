use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey {
    #[serde(with = "hex_bytes")]
    bytes: [u8; 32],
    #[serde(skip)]
    inner: Option<VerifyingKey>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let hex_str: String = Deserialize::deserialize(d)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(arr)
    }
}

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, &'static str> {
        match VerifyingKey::from_bytes(&bytes) {
            Ok(inner) => Ok(PublicKey {
                bytes,
                inner: Some(inner),
            }),
            Err(_) => Err("Invalid Ed25519 public key"),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    fn get_vk(&self) -> Option<VerifyingKey> {
        self.inner
            .clone()
            .or_else(|| VerifyingKey::from_bytes(&self.bytes).ok())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        if let Some(vk) = self.get_vk() {
            Signature::from_slice(signature)
                .map(|sig| vk.verify(message, &sig).is_ok())
                .unwrap_or(false)
        } else {
            false
        }
    }

    pub fn dummy() -> Self {
        PublicKey {
            bytes: [0u8; 32],
            inner: None,
        }
    }

    #[cfg(test)]
    pub fn random() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let bytes = signing_key.verifying_key().to_bytes();
        PublicKey {
            bytes,
            inner: Some(signing_key.verifying_key()),
        }
    }
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl core::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

#[derive(Serialize, Deserialize)]
pub struct PrivateKey {
    #[serde(with = "hex_bytes")]
    bytes: [u8; 32],
    #[serde(skip)]
    inner: Option<SigningKey>,
}

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, &'static str> {
        let inner = SigningKey::from_bytes(&bytes);
        Ok(PrivateKey {
            bytes,
            inner: Some(inner),
        })
    }

    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        PrivateKey {
            bytes: signing_key.to_bytes(),
            inner: Some(signing_key),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        match &self.inner {
            Some(sk) => sk.sign(message).to_bytes(),
            None => [0u8; 64],
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match &self.inner {
            Some(sk) => {
                let vk = sk.verifying_key();
                PublicKey {
                    bytes: vk.to_bytes(),
                    inner: Some(vk),
                }
            }
            None => PublicKey {
                bytes: [0u8; 32],
                inner: None,
            },
        }
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey {
            bytes: self.bytes,
            inner: Some(SigningKey::from_bytes(&self.bytes)),
        }
    }
}

impl core::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PrivateKey(***)")
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    pub public: PublicKey,
    pub private: PrivateKey,
}

impl Keypair {
    pub fn from_private(private: &PrivateKey) -> Self {
        Keypair {
            private: private.clone(),
            public: private.public_key(),
        }
    }

    pub fn generate() -> Self {
        let private = PrivateKey::generate();
        Self::from_private(&private)
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.private.sign(message)
    }
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        self.public.verify(message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_and_sign() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hello aevum");
        assert!(kp.verify(b"hello aevum", &sig));
    }

    #[test]
    fn wrong_message_fails() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hello");
        assert!(!kp.verify(b"wrong", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let sig = kp1.sign(b"hello");
        assert!(!kp2.verify(b"hello", &sig));
    }

    #[test]
    fn public_key_roundtrip() {
        let kp = Keypair::generate();
        let bytes = kp.public.to_bytes();
        let pk = PublicKey::from_bytes(bytes).unwrap();
        assert_eq!(pk.to_bytes(), bytes);
    }

    #[test]
    #[test]
    fn private_key_roundtrip() {
        let pk = PrivateKey::generate();
        let bytes = pk.to_bytes();
        let pk2 = PrivateKey::from_bytes(bytes).unwrap();
        assert_eq!(pk2.to_bytes(), bytes);
    }

    #[test]
    fn private_key_derives_public() {
        let pk = PrivateKey::generate();
        let pub1 = pk.public_key();
        let pub2 = Keypair::from_private(&pk).public;
        assert_eq!(pub1.to_bytes(), pub2.to_bytes());
    }

    #[test]
    fn signing_is_deterministic() {
        let pk = PrivateKey::from_bytes([1u8; 32]).unwrap();
        let sig1 = pk.sign(b"test");
        let sig2 = pk.sign(b"test");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn dummy_and_random() {
        let dummy = PublicKey::dummy();
        assert_eq!(dummy.as_bytes(), &[0u8; 32]);
        let random = PublicKey::random();
        assert_ne!(random.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn serialize_public_key() {
        let kp = Keypair::generate();
        let json = serde_json::to_string(&kp.public).unwrap();
        let restored: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.to_bytes(), kp.public.to_bytes());
    }

    #[test]
    fn serialize_private_key() {
        let pk = PrivateKey::generate();
        let json = serde_json::to_string(&pk).unwrap();
        let restored: PrivateKey = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.to_bytes(), pk.to_bytes());
    }

    #[test]
    fn deserialized_key_verifies_signature() {
        let kp = Keypair::generate();
        let json = serde_json::to_string(&kp.public).unwrap();
        let restored: PublicKey = serde_json::from_str(&json).unwrap();
        let msg = b"test message";
        let sig = kp.sign(msg);
        assert!(restored.verify(msg, &sig));
    }
}
