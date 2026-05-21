use aevum::core::block::Block;
use aevum::core::jt_utxo::JtUtxo;
use aevum::core::state::UtxoSet;
use aevum::crypto::hash::Hash;
use sha2::{Sha256, Digest};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit as AeadKeyInit};
use std::path::{Path, PathBuf};

const ENCRYPTION_ROUNDS: u32 = 100_000;

pub struct Storage {
    db: sled::Db,
    encrypt_key: Option<[u8; 32]>,
}

impl Storage {
    /// Открыть БД с авто-миграцией из старого SQLite формата
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Self::open_with_mode(path, false)
    }
    
    pub fn open_readonly(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Self::open_with_mode(path, true)
    }
    
    fn open_with_mode(path: &Path, read_only: bool) -> Result<Self, Box<dyn std::error::Error>> {
        std::fs::create_dir_all(path)?;
        let config = sled::Config::new().path(path).mode(if read_only { sled::Mode::HighThroughput } else { sled::Mode::HighThroughput }); let db = config.open()?;
        let has_data = db.scan_prefix("g_").next().is_some();

        if !has_data {
            // Ищем старую SQLite БД: пробуем path.old, потом path (если это SQLite файл)
            let old_path = path.with_extension("db.old");
            let sqlite_path = if old_path.exists() {
                old_path
            } else if path.is_file() {
                // Если path — это файл (SQLite), мигрируем из него
                path.to_path_buf()
            } else {
                // Ищем aevum_mainnet.db в той же директории
                path.parent().map(|p| p.join("aevum_mainnet.db")).unwrap_or_default()
            };

            if sqlite_path.exists() && sqlite_path.is_file() {
                tracing::info!("[STORAGE] Migrating from {}", sqlite_path.display());
                let mut count = 0u64;
                if let Ok(conn) = rusqlite::Connection::open(&sqlite_path) {
                    if let Ok(mut stmt) = conn.prepare("SELECT height, data FROM blocks ORDER BY height") {
                        if let Ok(rows) = stmt.query_map([], |row| {
                            Ok((row.get::<_, u64>(0)?, row.get::<_, Vec<u8>>(1)?))
                        }) {
                            for row in rows {
                                if let Ok((h, d)) = row {
                                    db.insert(Self::genesis_key(h), d)?;
                                    count += 1;
                                }
                            }
                        }
                    }
                    // Мигрируем UTXO
                    if let Ok(mut stmt) = conn.prepare("SELECT value FROM metadata WHERE key = 'utxo_set'") {
                        if let Ok(data) = stmt.query_row([], |row| row.get::<_, Vec<u8>>(0)) {
                            db.insert(Self::meta_key("utxo_set"), data)?;
                        }
                    }
                    // Мигрируем nonce
                    // Мигрируем UTXO из таблицы utxos (если metadata пустая)
                    let utxo_meta = db.get(Self::meta_key("utxo_set")).ok().flatten();
                    if utxo_meta.is_none() {
                        if let Ok(mut stmt) = conn.prepare("SELECT data FROM utxos") {
                            let mut utxo_set = UtxoSet::new();
                            if let Ok(rows) = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0)) {
                                for row in rows {
                                    if let Ok(data) = row {
                                        if let Ok(utxo) = bincode::deserialize::<JtUtxo>(&data) {
                                            utxo_set.add(utxo);
                                        }
                                    }
                                }
                            }
                            if !utxo_set.is_empty() {
                                db.insert(Self::meta_key("utxo_set"), bincode::serialize(&utxo_set).unwrap_or_default())?;
                                tracing::info!("[STORAGE] Migrated {} UTXOs from SQLite", utxo_set.len());
                            }
                        }
                    }
                    if let Ok(mut stmt) = conn.prepare("SELECT key, value FROM nonces") {
                        if let Ok(rows) = stmt.query_map([], |row| {
                            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                        }) {
                            for row in rows {
                                if let Ok((k, v)) = row {
                                    db.insert(Self::meta_key(&format!("nonce_{}", k)), v.to_le_bytes().to_vec())?;
                                }
                            }
                        }
                    }
                    tracing::info!("[STORAGE] Migrated {} blocks from SQLite", count);
                }
                db.flush()?;
            }
        }

        Ok(Storage { db, encrypt_key: None })
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

    pub fn save_genesis_block(&self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let data = bincode::serialize(block)?;
        self.db.insert(Self::genesis_key(block.height), data)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn load_genesis_block(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        match self.db.get(Self::genesis_key(height))? {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    pub fn max_genesis_height(&self) -> Result<Option<u64>, Box<dyn std::error::Error>> {
        let mut max = None;
        for result in self.db.scan_prefix("g_") {
            if let Ok((key, _)) = result {
                if let Ok(h) = std::str::from_utf8(&key).unwrap_or("").trim_start_matches("g_").parse::<u64>() {
                    max = Some(max.map_or(h, |m: u64| m.max(h)));
                }
            }
        }
        Ok(max)
    }

    pub fn delete_genesis_block(&self, height: u64) -> Result<(), Box<dyn std::error::Error>> {
        self.db.remove(Self::genesis_key(height))?;
        self.db.flush()?;
        Ok(())
    }

    pub fn save_my_block(&self, height: u64, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let raw = bincode::serialize(block)?;
        let encrypted = self.encrypt_my_block(&raw, &block.block_hash.0);
        self.db.insert(Self::my_key(height), encrypted)?;
        self.db.flush()?;
        Ok(())
    }

    pub fn load_my_block(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        match self.db.get(Self::my_key(height))? {
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
        self.save_metadata("utxo_set", &bincode::serialize(utxo_set)?)
    }

    pub fn load_utxo_set(&self) -> Result<UtxoSet, Box<dyn std::error::Error>> {
        match self.load_metadata("utxo_set")? {
            Some(data) => Ok(bincode::deserialize(&data)?),
            None => Ok(UtxoSet::new()),
        }
    }

    // Совместимость со старым API
    pub fn load_block(&self, h: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> { self.load_genesis_block(h) }
    pub fn save_block(&self, b: &Block) -> Result<(), Box<dyn std::error::Error>> { self.save_genesis_block(b) }
    pub fn delete_block(&self, h: u64) -> Result<(), Box<dyn std::error::Error>> { self.delete_genesis_block(h) }
    pub fn max_height(&self) -> Result<Option<u64>, Box<dyn std::error::Error>> { self.max_genesis_height() }

    pub fn check_and_update_nonce(&self, key: &str, new_nonce: u64) -> Result<NonceStatus, Box<dyn std::error::Error>> {
        let meta_key = Self::meta_key(&format!("nonce_{}", key));
        let last = self.db.get(&meta_key)?.map(|d| {
            let mut arr = [0u8; 8]; arr.copy_from_slice(&d[..8]); u64::from_le_bytes(arr)
        }).unwrap_or(0);
        if new_nonce > last {
            self.db.insert(meta_key, new_nonce.to_le_bytes().to_vec())?;
            Ok(NonceStatus::Accepted)
        } else {
            Ok(NonceStatus::Rejected { last_nonce: last })
        }
    }
}

pub enum NonceStatus { Accepted, Rejected { last_nonce: u64 } }
