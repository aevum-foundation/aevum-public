//! AevumDB Configuration — Public Architecture Demo
//!
//! This module demonstrates the configuration system for AevumDB.
//! It shows how we structure database settings, validate inputs,
//! and handle encryption keys (implementation details are omitted
//! to protect our unique innovations).
//!
//! ## Validation Layers
//! - Preflight: static checks (bounds, consistency)
//! - Runtime: filesystem checks

use std::path::PathBuf;
use crate::error::{DbError, DbResult};

// ─── Encryption Key (Public Interface) ──────────────────

/// Encryption key placeholder.
/// The actual implementation uses XChaCha20-Poly1305 with HKDF key derivation.
/// This is omitted from the public version.
#[derive(Clone)]
pub struct EncryptionKey(pub [u8; 32]);

impl EncryptionKey {
    /// Basic validity check (placeholder).
    /// In the full version, this includes cryptographically secure validation.
    pub fn is_valid(&self) -> bool {
        // Real implementation: checks against weak keys, all-zeros, etc.
        // For public demo, we only check for non-zero.
        self.0.iter().any(|&b| b != 0)
    }
}

// ─── Sync Mode ────────────────────────────────────────────

/// Write-ahead log synchronization strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMode {
    /// Sync every write (maximum durability)
    Always,
    /// Sync in batches of N milliseconds
    Batch(u64),
    /// Never sync (fastest, least durable)
    Never,
}

impl Default for SyncMode {
    fn default() -> Self { SyncMode::Always }
}

// ─── Compaction Strategy ──────────────────────────────────

/// LSM-tree compaction strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionStrategy {
    /// Leveled compaction: each level has max N files
    Leveled { level0_max_files: usize },
    /// Tiered compaction: each tier is N times larger
    Tiered { tier_size_multiplier: usize },
    /// Adaptive: chooses strategy based on workload
    Adaptive,
}

impl Default for CompactionStrategy {
    fn default() -> Self { CompactionStrategy::Adaptive }
}

// ─── DbConfig ─────────────────────────────────────────────

/// Main database configuration.
/// All fields have safe defaults and are validated at runtime.
#[derive(Debug, Clone)]
pub struct DbConfig {
    /// Path to the database directory
    pub path: PathBuf,
    /// WAL sync mode
    pub sync_mode: SyncMode,
    /// Compaction strategy
    pub compaction: CompactionStrategy,
    /// Maximum size of in-memory buffer before flush
    pub memtable_max_bytes: usize,
    /// Maximum number of open file handles
    pub max_open_files: usize,
    /// Block size for SSTable files
    pub block_size: usize,
    /// Optional encryption key (placeholder)
    pub encryption_key: Option<EncryptionKey>,
    /// Maximum size of WAL segment before rotation
    pub wal_segment_bytes: usize,
    /// How many blocks to keep for L2 (None = unlimited)
    pub l2_retention_blocks: Option<u64>,
}

impl Default for DbConfig {
    fn default() -> Self {
        DbConfig {
            path: PathBuf::from("./aevum_data"),
            sync_mode: SyncMode::default(),
            compaction: CompactionStrategy::default(),
            memtable_max_bytes: 64 * 1024 * 1024,
            max_open_files: 1000,
            block_size: 4096,
            encryption_key: None,
            wal_segment_bytes: 64 * 1024 * 1024,
            l2_retention_blocks: None,
        }
    }
}

impl DbConfig {
    /// Set database path (builder pattern)
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        DbConfig { path: path.into(), ..Default::default() }
    }

    /// Enable encryption with a key (placeholder)
    pub fn with_encryption(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(EncryptionKey(key));
        self
    }

    /// Set sync mode
    pub fn with_sync_mode(mut self, mode: SyncMode) -> Self {
        self.sync_mode = mode;
        self
    }

    /// Set memtable size
    pub fn with_memtable_size(mut self, bytes: usize) -> Self {
        self.memtable_max_bytes = bytes;
        self
    }

    /// Set block size
    pub fn with_block_size(mut self, bytes: usize) -> Self {
        self.block_size = bytes;
        self
    }

    /// Set WAL segment size
    pub fn with_wal_segment_size(mut self, bytes: usize) -> Self {
        self.wal_segment_bytes = bytes;
        self
    }

    /// Set max open files
    pub fn with_max_open_files(mut self, n: usize) -> Self {
        self.max_open_files = n;
        self
    }

    // ── Validation ─────────────────────────────────────────

    /// Preflight validation: checks logical constraints
    pub fn validate(&self) -> DbResult<()> {
        // Encryption key validation (simplified for public demo)
        if let Some(ref key) = self.encryption_key {
            if !key.is_valid() {
                return Err(DbError::Config("encryption key is weak"));
            }
        }

        // Path validation
        if self.path.as_os_str().is_empty() {
            return Err(DbError::Config("database path cannot be empty"));
        }
        if self.path.as_os_str().len() > 4096 {
            return Err(DbError::Config("database path too long (max 4096 bytes)"));
        }

        // Bounds checking
        if self.memtable_max_bytes < 4096 {
            return Err(DbError::Config("memtable_max_bytes must be at least 4096"));
        }
        if self.memtable_max_bytes > 1024 * 1024 * 1024 {
            return Err(DbError::Config("memtable_max_bytes must be at most 1 GiB"));
        }

        if self.block_size < 512 {
            return Err(DbError::Config("block_size must be at least 512 bytes"));
        }
        if self.block_size > 65536 {
            return Err(DbError::Config("block_size must be at most 65536 bytes"));
        }

        if self.max_open_files == 0 {
            return Err(DbError::Config("max_open_files must be at least 1"));
        }
        if self.max_open_files > 100_000 {
            return Err(DbError::Config("max_open_files must be at most 100000"));
        }

        if self.wal_segment_bytes < 4096 {
            return Err(DbError::Config("wal_segment_bytes must be at least 4096"));
        }
        if self.wal_segment_bytes > 1024 * 1024 * 1024 {
            return Err(DbError::Config("wal_segment_bytes must be at most 1 GiB"));
        }

        // Sync mode validation
        if let SyncMode::Batch(ms) = self.sync_mode {
            if ms == 0 {
                return Err(DbError::Config("SyncMode::Batch interval must be > 0 ms"));
            }
            if ms > 60_000 {
                return Err(DbError::Config("SyncMode::Batch interval must be <= 60000 ms"));
            }
        }

        // Cross-field consistency
        if self.memtable_max_bytes < self.block_size * 2 {
            return Err(DbError::Config("memtable_max_bytes must be at least 2x block_size"));
        }
        if self.wal_segment_bytes < self.memtable_max_bytes / 4 {
            return Err(DbError::Config("wal_segment_bytes must be at least memtable_max_bytes/4"));
        }

        Ok(())
    }

    /// Runtime validation: checks filesystem
    pub fn validate_path(&self) -> DbResult<()> {
        let path = &self.path;

        if path.exists() {
            if !path.is_dir() {
                tracing::error!("path exists but is not a directory: {}", path.display());
                return Err(DbError::Config("path is not a directory"));
            }

            let meta = path.metadata()
                .map_err(|e| DbError::io(e, path.clone(), "metadata check"))?;

            if meta.permissions().readonly() {
                return Err(DbError::PermissionDenied {
                    path: path.clone(),
                    context: "database directory is read-only",
                });
            }
        }

        Ok(())
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        DbConfig::default().validate().unwrap();
    }

    #[test]
    fn encryption_key_rejects_weak() {
        assert!(!EncryptionKey([0u8; 32]).is_valid());
        assert!(!EncryptionKey([0xAAu8; 32]).is_valid());
    }

    #[test]
    fn encryption_key_accepts_strong() {
        let mut key = [0u8; 32];
        key[0] = 0x42; key[1] = 0x99; key[2] = 0xDE;
        assert!(EncryptionKey(key).is_valid());
    }

    #[test]
    fn validate_rejects_weak_encryption_key() {
        assert!(DbConfig::default().with_encryption([0u8; 32]).validate().is_err());
    }

    #[test]
    fn validate_rejects_small_memtable() {
        let mut c = DbConfig::default();
        c.memtable_max_bytes = 1024;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_small_block() {
        let mut c = DbConfig::default();
        c.block_size = 256;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_max_open_files() {
        let mut c = DbConfig::default();
        c.max_open_files = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_batch_zero() {
        assert!(DbConfig::default().with_sync_mode(SyncMode::Batch(0)).validate().is_err());
    }

    #[test]
    fn validate_rejects_batch_too_large() {
        assert!(DbConfig::default().with_sync_mode(SyncMode::Batch(70000)).validate().is_err());
    }

    #[test]
    fn validate_rejects_inconsistent_sizes() {
        assert!(DbConfig::default()
            .with_memtable_size(8192)
            .with_block_size(8192)
            .validate()
            .is_err());
    }

    #[test]
    fn validate_rejects_wal_too_small() {
        assert!(DbConfig::default()
            .with_memtable_size(10 * 1024 * 1024)
            .with_wal_segment_size(1024 * 1024)
            .validate()
            .is_err());
    }

    #[test]
    fn validate_accepts_consistent_config() {
        assert!(DbConfig::default()
            .with_memtable_size(64 * 1024 * 1024)
            .with_wal_segment_size(32 * 1024 * 1024)
            .validate()
            .is_ok());
    }

    #[test]
    fn validate_path_accepts_writable_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let cfg = DbConfig::with_path(tmp.path());
        assert!(cfg.validate_path().is_ok());
    }

    #[test]
    fn with_builders() {
        let cfg = DbConfig::default()
            .with_encryption([0x55; 32])
            .with_sync_mode(SyncMode::Batch(200))
            .with_memtable_size(128 * 1024 * 1024)
            .with_block_size(8192)
            .with_wal_segment_size(32 * 1024 * 1024)
            .with_max_open_files(5000);

        assert!(cfg.encryption_key.is_some());
        assert_eq!(cfg.sync_mode, SyncMode::Batch(200));
        assert_eq!(cfg.memtable_max_bytes, 128 * 1024 * 1024);
        assert_eq!(cfg.block_size, 8192);
        assert_eq!(cfg.wal_segment_bytes, 32 * 1024 * 1024);
        assert_eq!(cfg.max_open_files, 5000);
    }
}
