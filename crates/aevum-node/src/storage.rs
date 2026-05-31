use aevum::core::block::Block;
use aevum::core::state::UtxoSet;
use aevum::crypto::hash::Hash;
use aevum::crypto::keys::PublicKey;
use sha2::{Sha256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::path::Path;

const ENCRYPTION_ROUNDS: u32 = 100_000;
const PRUNE_KEEP_LAST: u64 = 100;

pub struct Storage {
    db: sled::Db,
    encrypt_key: Option<[u8; 32]>,
    last_prune_height: u64,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(path)?;
        let db = sled::open(path)?;
        Ok(Storage { db, encrypt_key: None, last_prune_height: 0 })
    }

    pub fn with_encryption(mut self, private_key: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"AEVUM_MY_BLOCKS_V2");
        hasher.update(private_key);
        let mut derived = hasher.finalize().to_vec();
        for _ in 0..ENCRYPTION_ROUNDS {
            let d = Sha256::digest(&derived);
            for i in 0..32 { if i < derived.len() { derived[i] ^= d[i]; } }
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived[..32]);
        self.encrypt_key = Some(key);
        self
    }

    fn encrypt_my_block(&self, data: &[u8], block_hash: &[u8]) -> Vec<u8> {
        match self.encrypt_key {
            Some(key) => {
                let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new(chacha20poly1305::Key::from_slice(&key));
                let nonce_hash = Sha256::digest(block_hash);
                let nonce = Nonce::from_slice(&nonce_hash[..12]);
                let encrypted = cipher.encrypt(nonce, data).unwrap_or_else(|_| data.to_vec());
                let mut package = Vec::with_capacity(12 + encrypted.len());
                package.extend_from_slice(&nonce_hash[..12]);
                package.extend_from_slice(&encrypted);
                package
            }
            None => {
                let mut package = Vec::with_capacity(12 + data.len());
                package.extend_from_slice(&[0u8; 12]);
                package.extend_from_slice(data);
                package
            }
        }
    }

    fn decrypt_my_block(&self, package: &[u8]) -> Option<Vec<u8>> {
        if package.len() < 12 { return None; }
        let nonce = Nonce::from_slice(&package[..12]);
        let encrypted = &package[12..];
        match self.encrypt_key {
            Some(key) => {
                let cipher = <ChaCha20Poly1305 as AeadKeyInit>::new(chacha20poly1305::Key::from_slice(&key));
                cipher.decrypt(nonce, encrypted).ok()
            }
            None => Some(encrypted.to_vec()),
        }
    }

    fn genesis_key(height: u64) -> Vec<u8> { format!("g_{:020}", height).into_bytes() }
    fn my_key(height: u64) -> Vec<u8> { format!("m_{:020}", height).into_bytes() }
    fn meta_key(key: &str) -> Vec<u8> { format!("meta_{}", key).into_bytes() }

    // ============================================================
    // GENESIS CHAIN + PRUNING
    // ============================================================

    pub fn save_genesis_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::genesis_key(block.height);
        let data = bincode::serialize(block)?;
        self.db.insert(key, data)?;
        self.db.flush()?;
        if block.height > PRUNE_KEEP_LAST {
            self.prune_old_blocks(block.height)?;
        }
        Ok(())
    }

    fn prune_old_blocks(&self, current_height: u64) -> Result<(), Box<dyn std::error::Error>> {
        if current_height <= PRUNE_KEEP_LAST * 2 { return Ok(()); }
        if current_height - self.last_prune_height < PRUNE_KEEP_LAST { return Ok(()); }
        let prune_below = current_height - PRUNE_KEEP_LAST;
        let mut deleted = 0u64;
        for h in self.last_prune_height..prune_below {
            if h == 0 { continue; }
            let key = Self::genesis_key(h);
            if self.db.remove(key)?.is_some() { deleted += 1; }
        }
        if deleted > 0 {
            self.db.flush()?;
            tracing::info!("[STORAGE] Pruned {} blocks below height {}", deleted, prune_below);
        }
        Ok(())
    }

    pub fn load_genesis_block(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let key = Self::genesis_key(height);
        match self.db.get(key)? {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    pub fn max_genesis_height(&self) -> Result<Option<u64>, Box<dyn std::error::Error>> {
        let mut max = None;
        for result in self.db.scan_prefix("g_") {
            if let Ok((key, _)) = result {
                let key_str = String::from_utf8_lossy(&key);
                if let Ok(h) = key_str[2..].parse::<u64>() {
                    max = Some(max.map_or(h, |m: u64| m.max(h)));
                }
            }
        }
        Ok(max)
    }

    pub fn delete_genesis_block(&self, height: u64) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::genesis_key(height);
        self.db.remove(key)?;
        self.db.flush()?;
        Ok(())
    }

    // ============================================================
    // MY BLOCKS (личные, зашифрованные)
    // ============================================================

    pub fn save_my_block(&self, height: u64, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let key = Self::my_key(height);
        let raw = bincode::serialize(block)?;
        let encrypted = self.encrypt_my_block(&raw, &block.block_hash.0);
        self.db.insert(key, encrypted)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn load_my_block(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let key = Self::my_key(height);
        match self.db.get(key)? {
            Some(data) => {
                if let Some(decrypted) = self.decrypt_my_block(&data) {
                    Ok(Some(bincode::deserialize(&decrypted)?))
                } else { Ok(None) }
            }
            None => Ok(None),
        }
    }

    pub fn get_all_my_blocks(&self) -> Result<Vec<Block>, Box<dyn std::error::Error>> {
        let mut blocks = Vec::new();
        for result in self.db.scan_prefix("m_") {
            if let Ok((_, data)) = result {
                if let Some(decrypted) = self.decrypt_my_block(&data) {
                    if let Ok(block) = bincode::deserialize::<Block>(&decrypted) { blocks.push(block); }
                }
            }
        }
        Ok(blocks)
    }

    // ============================================================
    // KNOWN ADDRESSES (персистентность пиров)
    // ============================================================

    pub fn save_known_addresses(&self, addrs: &DashMap<SocketAddr, u64>) -> Result<(), Box<dyn std::error::Error>> {
        let list: Vec<(String, u64)> = addrs.iter().map(|e| (e.key().to_string(), *e.value())).collect();
        let data = bincode::serialize(&list)?;
        self.save_metadata("known_addresses", &data)
    }

    pub fn load_known_addresses(&self) -> Result<DashMap<SocketAddr, u64>, Box<dyn std::error::Error>> {
        let data = match self.load_metadata("known_addresses")? {
            Some(d) => d,
            None => return Ok(DashMap::new()),
        };
        let list: Vec<(String, u64)> = bincode::deserialize(&data)?;
        let map = DashMap::new();
        for (addr_str, ts) in list {
            if let Ok(addr) = addr_str.parse() {
                map.insert(addr, ts);
            }
        }
        Ok(map)
    }

    // ============================================================
    // METADATA
    // ============================================================

    pub fn save_metadata(&self, key: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.db.insert(Self::meta_key(key), data)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn load_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        match self.db.get(Self::meta_key(key))? {
            Some(data) => Ok(Some(data.to_vec())),
            None => Ok(None),
        }
    }

    pub fn delete_metadata(&self, key: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.db.remove(Self::meta_key(key))?;
        self.db.flush()?;
        Ok(())
    }

    pub fn save_utxo_set(&self, utxo_set: &UtxoSet) -> Result<(), Box<dyn std::error::Error>> {
        let data = bincode::serialize(utxo_set)?;
        self.save_metadata("utxo_set", &data)
    }

    pub fn load_utxo_set(&self) -> Result<UtxoSet, Box<dyn std::error::Error>> {
        match self.load_metadata("utxo_set")? {
            Some(data) => Ok(bincode::deserialize(&data)?),
            None => Ok(UtxoSet::new()),
        }
    }

    // Совместимость
    pub fn load_block(&self, h: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> { self.load_genesis_block(h) }
    pub fn save_block(&self, b: &Block) -> Result<(), Box<dyn std::error::Error>> { self.save_genesis_block(b) }
    pub fn delete_block(&self, h: u64) -> Result<(), Box<dyn std::error::Error>> { self.delete_genesis_block(h) }
    pub fn max_height(&self) -> Result<Option<u64>, Box<dyn std::error::Error>> { self.max_genesis_height() }
    pub fn check_and_update_nonce(&self, _k: &str, _n: u64) -> Result<NonceStatus, Box<dyn std::error::Error>> { Ok(NonceStatus::Accepted) }
}

pub enum NonceStatus { Accepted, Rejected { last_nonce: u64 } }
