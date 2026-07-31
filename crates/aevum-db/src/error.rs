//! AevumDB error types — production-grade.
//!
//! ## Severity
//! - **Fatal** — corruption, WAL loss (immediate shutdown)
//! - **Recoverable** — I/O, locks, backpressure, partial recovery
//! - **User** — invalid request or configuration
//!
//! ## Error codes
//! - 1xxx: I/O + backpressure
//! - 2xxx: Integrity
//! - 3xxx: User
//! - 4xxx: Configuration
//! - 5xxx: Internal

use aevum::reexport::{hex, bincode, blake3};
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

pub type DbResult<T> = Result<T, DbError>;

// ─── Error Code ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    IoGeneric = 1000,
    IoDiskFull = 1001,
    IoPermissionDenied = 1002,
    IoLocked = 1003,
    IoDirectoryNotFound = 1004,
    SequenceOverflow = 1006,
    CompactionBackpressure = 1005,

    CorruptionWal = 2000,
    CorruptionSstable = 2001,
    CorruptionMemtable = 2002,
    CorruptionManifest = 2003,
    ManifestVersionMismatch = 2004,
    IntegrityViolation = 2005,
    ChecksumMismatch = 2006,
    WalSegmentMissing = 2007,
    SstableTruncated = 2008,
    CompactionCorrupted = 2009,
    RecoveryFailed = 2010,
    RecoveryPartial = 2011,

    NotFound = 3000,
    AlreadyOpen = 3001,
    Closed = 3002,
    InvalidKey = 3003,
    InvalidValue = 3004,
    BatchTooLarge = 3005,
    SnapshotExpired = 3006,
    UtxoSpent = 3007,
    UtxoInvalid = 3008,

    ConfigInvalid = 4000,
    CacheFull = 4006,

    Serialization = 5000,
    Crypto = 5001,
    Internal = 5002,
}

// ─── Severity ────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity { Fatal, Recoverable, User }

// ─── DbError ─────────────────────────────────────────────

#[derive(Debug)]
pub enum DbError {
    // I/O
    Io { code: ErrorCode, source: io::Error, path: Option<PathBuf>, context: &'static str },
    DiskFull { path: PathBuf, available: u64, needed: u64 },
    PermissionDenied { path: PathBuf, context: &'static str },
    Locked { path: PathBuf, holder_pid: Option<u32> },
    DirectoryNotFound(PathBuf),
    CompactionBackpressure { queued_files: usize, max_files: usize },

    // Integrity
    WalCorrupted { segment: u64, offset: u64, expected: [u8; 32], actual: [u8; 32] },
    SstableCorrupted { path: PathBuf, offset: u64, expected: [u8; 32], actual: [u8; 32] },
    MemtableCorrupted { context: &'static str },
    ManifestCorrupted { path: PathBuf, reason: &'static str },
    ManifestVersionMismatch { path: PathBuf, expected: u32, found: u32 },
    Integrity(&'static str),
    ChecksumMismatch { path: PathBuf, offset: u64, stored: [u8; 32], computed: [u8; 32] },
    WalSegmentMissing { segment: u64 },
    SstableTruncated { path: PathBuf, expected: u64, actual: u64 },
    CompactionCorrupted { output_path: PathBuf, reason: &'static str },
    RecoveryFailed { reason: &'static str },
    RecoveryPartial { recovered: usize, total: usize },

    // User
    NotFound { key_hash: [u8; 32], key_len: usize },
    AlreadyOpen { path: PathBuf, holder_pid: Option<u32> },
    Closed,
    SequenceOverflow,
    InvalidKey { context: &'static str, key_len: usize },
    InvalidValue { context: &'static str, value_len: usize },
    BatchTooLarge { size: usize, max: usize },
    SnapshotExpired { snapshot_seq: u64, current_seq: u64 },
    UtxoSpent { tx_hash: [u8; 32], output_index: u32 },
    UtxoInvalid { context: &'static str },

    // Configuration
    Config(&'static str),
    // Cache management
    CacheFull { current: usize, max: usize },

    // Internal
    Serialization { context: &'static str },
    Crypto(&'static str),
    Internal { code: u32, context: &'static str },
}

impl DbError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            DbError::Io { code, .. } => *code,
            DbError::DiskFull { .. } => ErrorCode::IoDiskFull,
            DbError::PermissionDenied { .. } => ErrorCode::IoPermissionDenied,
            DbError::Locked { .. } => ErrorCode::IoLocked,
            DbError::DirectoryNotFound(_) => ErrorCode::IoDirectoryNotFound,
            DbError::CompactionBackpressure { .. } => ErrorCode::CompactionBackpressure,
            DbError::WalCorrupted { .. } => ErrorCode::CorruptionWal,
            DbError::SstableCorrupted { .. } => ErrorCode::CorruptionSstable,
            DbError::MemtableCorrupted { .. } => ErrorCode::CorruptionMemtable,
            DbError::ManifestCorrupted { .. } => ErrorCode::CorruptionManifest,
            DbError::ManifestVersionMismatch { .. } => ErrorCode::ManifestVersionMismatch,
            DbError::Integrity(_) => ErrorCode::IntegrityViolation,
            DbError::ChecksumMismatch { .. } => ErrorCode::ChecksumMismatch,
            DbError::WalSegmentMissing { .. } => ErrorCode::WalSegmentMissing,
            DbError::SstableTruncated { .. } => ErrorCode::SstableTruncated,
            DbError::CompactionCorrupted { .. } => ErrorCode::CompactionCorrupted,
            DbError::RecoveryFailed { .. } => ErrorCode::RecoveryFailed,
            DbError::RecoveryPartial { .. } => ErrorCode::RecoveryPartial,
            DbError::NotFound { .. } => ErrorCode::NotFound,
            DbError::AlreadyOpen { .. } => ErrorCode::AlreadyOpen,
            DbError::Closed => ErrorCode::Closed,
            DbError::SequenceOverflow => ErrorCode::SequenceOverflow,
            DbError::InvalidKey { .. } => ErrorCode::InvalidKey,
            DbError::InvalidValue { .. } => ErrorCode::InvalidValue,
            DbError::BatchTooLarge { .. } => ErrorCode::BatchTooLarge,
            DbError::SnapshotExpired { .. } => ErrorCode::SnapshotExpired,
            DbError::UtxoSpent { .. } => ErrorCode::UtxoSpent,
            DbError::UtxoInvalid { .. } => ErrorCode::UtxoInvalid,
            DbError::Config(_) => ErrorCode::ConfigInvalid,
            DbError::CacheFull { .. } => ErrorCode::CacheFull,
            DbError::Serialization { .. } => ErrorCode::Serialization,
            DbError::Crypto(_) => ErrorCode::Crypto,
            DbError::Internal { .. } => ErrorCode::Internal,
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            DbError::WalCorrupted { .. }
            | DbError::SstableCorrupted { .. }
            | DbError::MemtableCorrupted { .. }
            | DbError::ManifestCorrupted { .. }
            | DbError::ManifestVersionMismatch { .. }
            | DbError::Integrity(_)
            | DbError::ChecksumMismatch { .. }
            | DbError::SstableTruncated { .. }
            | DbError::WalSegmentMissing { .. }
            | DbError::CompactionCorrupted { .. }
            | DbError::RecoveryFailed { .. }
            | DbError::Serialization { .. }
            | DbError::Crypto(_)
            | DbError::Internal { .. } => Severity::Fatal,

            DbError::Io { .. }
            | DbError::DiskFull { .. }
            | DbError::PermissionDenied { .. }
            | DbError::Locked { .. }
            | DbError::DirectoryNotFound(_)
            | DbError::CompactionBackpressure { .. }
            | DbError::RecoveryPartial { .. } => Severity::Recoverable,

            DbError::NotFound { .. }
            | DbError::AlreadyOpen { .. }
            | DbError::SequenceOverflow
            | DbError::Closed
            | DbError::InvalidKey { .. }
            | DbError::InvalidValue { .. }
            | DbError::BatchTooLarge { .. }
            | DbError::SnapshotExpired { .. }
            | DbError::UtxoSpent { .. }
            | DbError::UtxoInvalid { .. }
            | DbError::CacheFull { .. } => Severity::Recoverable,
            DbError::Config(_) => Severity::User,
        }
    }

    pub fn is_fatal(&self) -> bool { self.severity() == Severity::Fatal }
    pub fn is_recoverable(&self) -> bool { self.severity() == Severity::Recoverable }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            DbError::Io { .. } => Some(Duration::from_millis(100)),
            DbError::DiskFull { .. } => Some(Duration::from_secs(5)),
            DbError::Locked { .. } => Some(Duration::from_secs(1)),
            DbError::PermissionDenied { .. } => Some(Duration::from_secs(1)),
            DbError::CompactionBackpressure { .. } => Some(Duration::from_secs(2)),
            DbError::RecoveryPartial { .. } => Some(Duration::from_secs(3)),
            _ => None,
        }
    }

    pub fn should_throttle(&self) -> bool { self.retry_after().is_some() }

    // ── Constructors ──────────────────────────────────

    pub fn io(source: io::Error, path: impl Into<PathBuf>, context: &'static str) -> Self {
        let code = match source.kind() {
            io::ErrorKind::NotFound => ErrorCode::IoDirectoryNotFound,
            io::ErrorKind::PermissionDenied => ErrorCode::IoPermissionDenied,
            _ => ErrorCode::IoGeneric,
        };
        DbError::Io { code, source, path: Some(path.into()), context }
    }

    pub fn directory_not_found(path: impl Into<PathBuf>) -> Self {
        DbError::DirectoryNotFound(path.into())
    }

    pub fn sstable_corruption(path: impl Into<PathBuf>, offset: u64, expected: [u8; 32], actual: [u8; 32]) -> Self {
        DbError::SstableCorrupted { path: path.into(), offset, expected, actual }
    }

    pub fn wal_corruption(segment: u64, offset: u64, expected: [u8; 32], actual: [u8; 32]) -> Self {
        DbError::WalCorrupted { segment, offset, expected, actual }
    }

    pub fn manifest_corruption(path: impl Into<PathBuf>, reason: &'static str) -> Self {
        DbError::ManifestCorrupted { path: path.into(), reason }
    }

    pub fn manifest_version_mismatch(path: impl Into<PathBuf>, expected: u32, found: u32) -> Self {
        DbError::ManifestVersionMismatch { path: path.into(), expected, found }
    }

    pub fn checksum_mismatch(path: impl Into<PathBuf>, offset: u64, stored: [u8; 32], computed: [u8; 32]) -> Self {
        DbError::ChecksumMismatch { path: path.into(), offset, stored, computed }
    }

    pub fn wal_segment_missing(segment: u64) -> Self {
        DbError::WalSegmentMissing { segment }
    }

    pub fn sstable_truncated(path: impl Into<PathBuf>, expected: u64, actual: u64) -> Self {
        DbError::SstableTruncated { path: path.into(), expected, actual }
    }

    pub fn compaction_corrupted(output_path: impl Into<PathBuf>, reason: &'static str) -> Self {
        DbError::CompactionCorrupted { output_path: output_path.into(), reason }
    }

    pub fn recovery_failed(reason: &'static str) -> Self {
        DbError::RecoveryFailed { reason }
    }

    pub fn recovery_partial(recovered: usize, total: usize) -> Self {
        DbError::RecoveryPartial { recovered, total }
    }

    pub fn not_found(key: &[u8]) -> Self {
        let key_hash = blake3::hash(key).into();
        DbError::NotFound { key_hash, key_len: key.len() }
    }

    pub fn invalid_key(context: &'static str, key_len: usize) -> Self {
        DbError::InvalidKey { context, key_len }
    }

    pub fn invalid_value(context: &'static str, value_len: usize) -> Self {
        DbError::InvalidValue { context, value_len }
    }

    pub fn snapshot_expired(snapshot_seq: u64, current_seq: u64) -> Self {
        DbError::SnapshotExpired { snapshot_seq, current_seq }
    }

    pub fn utxo_spent(tx_hash: [u8; 32], output_index: u32) -> Self {
        DbError::UtxoSpent { tx_hash, output_index }
    }

    pub fn utxo_invalid(context: &'static str) -> Self {
        DbError::UtxoInvalid { context }
    }

    pub fn backpressure(queued_files: usize, max_files: usize) -> Self {
        DbError::CompactionBackpressure { queued_files, max_files }
    }

    pub fn cache_full(current: usize, max: usize) -> Self {
        DbError::CacheFull { current, max }
    }
}

// ─── Display (unified format) ────────────────────────────────────

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.error_code() as u32;
        match self {
            DbError::Io { path, context, source, .. } => {
                write!(f, "[E{}] {}: {}", code, context, source)?;
                if let Some(p) = path { write!(f, " at '{}'", p.display())?; }
                Ok(())
            }
            DbError::DiskFull { path, available, needed } => {
                write!(f, "[E{}] disk full at '{}': {} available, {} needed", code, path.display(), available, needed)
            }
            DbError::PermissionDenied { path, context } => {
                write!(f, "[E{}] {} at '{}'", code, context, path.display())
            }
            DbError::Locked { path, holder_pid } => {
                write!(f, "[E{}] database locked: '{}'", code, path.display())?;
                if let Some(pid) = holder_pid { write!(f, " (PID {})", pid)?; }
                Ok(())
            }
            DbError::DirectoryNotFound(path) => {
                write!(f, "[E{}] directory not found: '{}'", code, path.display())
            }
            DbError::CompactionBackpressure { queued_files, max_files } => {
                write!(f, "[E{}] compaction backpressure: {} files queued (max {})", code, queued_files, max_files)
            }
            DbError::WalCorrupted { segment, offset, expected, actual } => {
                write!(f, "[E{}] WAL segment {} corrupted at offset {}: expected {}, actual {}",
                    code, segment, offset, hex::encode(expected), hex::encode(actual))
            }
            DbError::SstableCorrupted { path, offset, expected, actual } => {
                write!(f, "[E{}] SSTable corrupted at '{}' offset {}: expected {}, actual {}",
                    code, path.display(), offset, hex::encode(expected), hex::encode(actual))
            }
            DbError::MemtableCorrupted { context } => {
                write!(f, "[E{}] memtable corrupted: {}", code, context)
            }
            DbError::ManifestCorrupted { path, reason } => {
                write!(f, "[E{}] MANIFEST corrupted at '{}': {}", code, path.display(), reason)
            }
            DbError::ManifestVersionMismatch { path, expected, found } => {
                write!(f, "[E{}] MANIFEST version mismatch at '{}': expected v{}, found v{}",
                    code, path.display(), expected, found)
            }
            DbError::Integrity(msg) => write!(f, "[E{}] integrity violation: {}", code, msg),
            DbError::ChecksumMismatch { path, offset, stored, computed } => {
                write!(f, "[E{}] checksum mismatch at '{}' offset {}: stored {}, computed {}",
                    code, path.display(), offset, hex::encode(stored), hex::encode(computed))
            }
            DbError::WalSegmentMissing { segment } => {
                write!(f, "[E{}] WAL segment {} missing — recovery impossible", code, segment)
            }
            DbError::SstableTruncated { path, expected, actual } => {
                write!(f, "[E{}] SSTable truncated '{}': expected {} bytes, got {}",
                    code, path.display(), expected, actual)
            }
            DbError::CompactionCorrupted { output_path, reason } => {
                write!(f, "[E{}] compaction corrupted output '{}': {}", code, output_path.display(), reason)
            }
            DbError::RecoveryFailed { reason } => {
                write!(f, "[E{}] recovery failed: {}", code, reason)
            }
            DbError::RecoveryPartial { recovered, total } => {
                write!(f, "[E{}] partial recovery: {}/{} entries recovered", code, recovered, total)
            }
            DbError::NotFound { key_hash, key_len } => {
                write!(f, "[E{}] key not found: {} ({} bytes)", code, hex::encode(key_hash), key_len)
            }
            DbError::AlreadyOpen { path, holder_pid } => {
                write!(f, "[E{}] database already open: '{}'", code, path.display())?;
                if let Some(pid) = holder_pid { write!(f, " (PID {})", pid)?; }
                Ok(())
            }
            DbError::Closed => write!(f, "[E{}] database is closed", code),
            DbError::SequenceOverflow => write!(f, "[E{}] sequence counter overflow", code),
            DbError::InvalidKey { context, key_len } => {
                write!(f, "[E{}] invalid key: {} ({} bytes)", code, context, key_len)
            }
            DbError::InvalidValue { context, value_len } => {
                write!(f, "[E{}] invalid value: {} ({} bytes)", code, context, value_len)
            }
            DbError::BatchTooLarge { size, max } => {
                write!(f, "[E{}] batch too large: {} ops (max {})", code, size, max)
            }
            DbError::SnapshotExpired { snapshot_seq, current_seq } => {
                write!(f, "[E{}] snapshot expired: seq {} (current {})", code, snapshot_seq, current_seq)
            }
            DbError::UtxoSpent { tx_hash, output_index } => {
                write!(f, "[E{}] UTXO already spent: {}:{}", code, hex::encode(tx_hash), output_index)
            }
            DbError::UtxoInvalid { context } => {
                write!(f, "[E{}] invalid UTXO: {}", code, context)
            }
            DbError::Config(msg) => write!(f, "[E{}] invalid configuration: {}", code, msg),
            DbError::CacheFull { current, max } => {
                write!(f, "[E{}] cache full: {} entries (max {})", code, current, max)
            }
            DbError::Serialization { context } => {
                write!(f, "[E{}] serialization error: {}", code, context)
            }
            DbError::Crypto(msg) => write!(f, "[E{}] crypto error: {}", code, msg),
            DbError::Internal { code: inner, context } => {
                write!(f, "[E{}:{}] internal error: {}", code, inner, context)
            }
        }
    }
}

impl std::error::Error for DbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self { DbError::Io { source, .. } => Some(source), _ => None }
    }
}

impl From<io::Error> for DbError {
    fn from(e: io::Error) -> Self {
        let code = match e.kind() {
            io::ErrorKind::NotFound => ErrorCode::IoDirectoryNotFound,
            io::ErrorKind::PermissionDenied => ErrorCode::IoPermissionDenied,
            _ => ErrorCode::IoGeneric,
        };
        DbError::Io { code, source: e, path: None, context: "io error" }
    }
}

impl From<bincode::Error> for DbError {
    fn from(e: bincode::Error) -> Self {
        let context = match e.as_ref() {
            bincode::ErrorKind::Io(_) => "bincode io error",
            bincode::ErrorKind::InvalidCharEncoding => "bincode invalid char",
            bincode::ErrorKind::SequenceMustHaveLength => "bincode sequence length",
            bincode::ErrorKind::Custom(_) => "bincode custom error",
            _ => "bincode error",
        };
        DbError::Serialization { context }
    }
}

// ─── Tests ────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn severity_fatal() {
        assert!(DbError::Integrity("test").is_fatal());
        assert!(DbError::ChecksumMismatch { path: PathBuf::from("test"), offset: 0, stored: [0;32], computed: [1;32] }.is_fatal());
        assert!(DbError::SstableTruncated { path: PathBuf::from("test"), expected: 100, actual: 50 }.is_fatal());
        assert!(DbError::WalSegmentMissing { segment: 42 }.is_fatal());
        assert!(DbError::ManifestVersionMismatch { path: PathBuf::from("test"), expected: 3, found: 2 }.is_fatal());
        assert!(DbError::RecoveryFailed { reason: "WAL missing" }.is_fatal());
        assert!(DbError::Crypto("test").is_fatal());
    }

    #[test] fn severity_recoverable() {
        assert!(DbError::Io { code: ErrorCode::IoGeneric, source: io::Error::new(io::ErrorKind::Other, "test"), path: None, context: "test" }.is_recoverable());
        assert!(DbError::DiskFull { path: PathBuf::from("test"), available: 0, needed: 1 }.is_recoverable());
        assert!(DbError::DirectoryNotFound(PathBuf::from("test")).is_recoverable());
        assert!(DbError::CompactionBackpressure { queued_files: 10, max_files: 5 }.is_recoverable());
        assert!(DbError::RecoveryPartial { recovered: 80, total: 100 }.is_recoverable());
    }

    #[test] fn severity_user() {
        assert!(!DbError::NotFound { key_hash: [0;32], key_len: 1 }.is_fatal());
        assert!(!DbError::Closed.is_fatal());
        assert!(!DbError::InvalidKey { context: "test", key_len: 1 }.is_fatal());
        assert!(!DbError::Config("test".into()).is_fatal());
        assert!(!DbError::InvalidKey { context: "test", key_len: 1 }.is_fatal());
        assert!(!DbError::Config("test".into()).is_fatal());
        assert!(!DbError::SnapshotExpired { snapshot_seq: 10, current_seq: 100 }.is_fatal());
        assert!(!DbError::UtxoSpent { tx_hash: [0;32], output_index: 0 }.is_fatal());
    }

    #[test] fn retry_after() {
        assert_eq!(DbError::Io { code: ErrorCode::IoGeneric, source: io::Error::new(io::ErrorKind::Other, "test"), path: None, context: "test" }.retry_after(), Some(Duration::from_millis(100)));
        assert_eq!(DbError::DiskFull { path: PathBuf::from("test"), available: 0, needed: 1 }.retry_after(), Some(Duration::from_secs(5)));
        assert_eq!(DbError::CompactionBackpressure { queued_files: 10, max_files: 5 }.retry_after(), Some(Duration::from_secs(2)));
        assert_eq!(DbError::RecoveryPartial { recovered: 80, total: 100 }.retry_after(), Some(Duration::from_secs(3)));
        assert_eq!(DbError::NotFound { key_hash: [0;32], key_len: 1 }.retry_after(), None);
        assert_eq!(DbError::Closed.retry_after(), None);
    }

    #[test] fn should_throttle() {
        assert!(DbError::DiskFull { path: PathBuf::from("test"), available: 0, needed: 1 }.should_throttle());
        assert!(DbError::CompactionBackpressure { queued_files: 10, max_files: 5 }.should_throttle());
        assert!(DbError::RecoveryPartial { recovered: 80, total: 100 }.should_throttle());
        assert!(!DbError::NotFound { key_hash: [0;32], key_len: 1 }.should_throttle());
    }

    #[test] fn error_codes_unique() {
        use std::collections::HashSet;
        let codes = vec![
            ErrorCode::IoGeneric, ErrorCode::IoDiskFull, ErrorCode::IoPermissionDenied,
            ErrorCode::IoLocked, ErrorCode::IoDirectoryNotFound, ErrorCode::CompactionBackpressure,
            ErrorCode::CorruptionWal, ErrorCode::CorruptionSstable, ErrorCode::CorruptionMemtable,
            ErrorCode::CorruptionManifest, ErrorCode::ManifestVersionMismatch,
            ErrorCode::IntegrityViolation, ErrorCode::ChecksumMismatch,
            ErrorCode::WalSegmentMissing, ErrorCode::SstableTruncated,
            ErrorCode::CompactionCorrupted, ErrorCode::RecoveryFailed, ErrorCode::RecoveryPartial,
            ErrorCode::NotFound, ErrorCode::AlreadyOpen, ErrorCode::Closed,
            ErrorCode::SequenceOverflow,
            ErrorCode::InvalidKey, ErrorCode::InvalidValue, ErrorCode::BatchTooLarge,
            ErrorCode::SnapshotExpired, ErrorCode::UtxoSpent, ErrorCode::UtxoInvalid,
            ErrorCode::ConfigInvalid, ErrorCode::CacheFull,
            ErrorCode::Serialization, ErrorCode::Crypto, ErrorCode::Internal,
        ];
        let unique: HashSet<_> = codes.iter().map(|c| *c as u32).collect();
        assert_eq!(unique.len(), codes.len());
    }

    #[test] fn display_formatting() {
        assert!(DbError::NotFound { key_hash: [0xAA;32], key_len: 10 }.to_string().contains("E3000"));
        assert!(DbError::ChecksumMismatch { path: PathBuf::from("test"), offset: 0, stored: [0;32], computed: [1;32] }.to_string().contains("E2006"));
        assert!(DbError::WalSegmentMissing { segment: 42 }.to_string().contains("recovery impossible"));
        assert!(DbError::ManifestVersionMismatch { path: PathBuf::from("test"), expected: 3, found: 2 }.to_string().contains("E2004"));
        assert!(DbError::RecoveryPartial { recovered: 80, total: 100 }.to_string().contains("E2011"));
        assert!(DbError::DirectoryNotFound(PathBuf::from("test")).to_string().contains("E1004"));
        assert!(DbError::Config("bad setting".into()).to_string().contains("E4000"));
        assert!(DbError::UtxoSpent { tx_hash: [0;32], output_index: 0 }.to_string().contains("E3007"));
    }
}
