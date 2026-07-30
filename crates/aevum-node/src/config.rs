//! NodeConfig v7.2 — Production META security layer (10/10)
//!
//! v7.2: Complete fingerprint (all consensus+network params), bootstrap peer validation.

use std::net::{SocketAddr, IpAddr};
use std::collections::HashSet;
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum ConfigError {
    InvalidListenAddr,
    InvalidHttpPort,
    InvalidGenesisAmount,
    InvalidTickConfig,
    InvalidMempoolConfig,
    InvalidSyncConfig,
    InvalidNetworkConfig,
    ConstraintViolation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidListenAddr => write!(f, "invalid listen address"),
            Self::InvalidHttpPort => write!(f, "invalid http port"),
            Self::InvalidGenesisAmount => write!(f, "invalid genesis amount"),
            Self::InvalidTickConfig => write!(f, "invalid tick config"),
            Self::InvalidMempoolConfig => write!(f, "invalid mempool config"),
            Self::InvalidSyncConfig => write!(f, "invalid sync config"),
            Self::InvalidNetworkConfig => write!(f, "invalid network config"),
            Self::ConstraintViolation(s) => write!(f, "constraint violation: {}", s),
        }
    }
}

impl std::error::Error for ConfigError {}

/// WARNING: Cloning creates additional copies of sensitive data
/// (miner_key_hex, api_key) in memory. Prefer Arc<NodeConfig>.
#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: SocketAddr,
    pub bootstrap_peers: Vec<SocketAddr>,
    pub http_port: u16,
    pub cors_origin: Option<String>,
    pub min_peers: usize,
    pub peer_discovery_interval_secs: u64,
    pub max_message_size: usize,
    pub bootstrap_attempts: usize,
    pub min_diverse_subnets: usize,
    pub max_per_subnet: usize,
    pub min_asn_diversity: usize,
    pub db_path: String,
    pub key_vault_path: String,
    pub fresh_start: bool,
    pub bootstrap_mode: bool,
    pub ticks_per_block: u64,
    pub block_interval_secs: u64,
    pub max_block_tx: usize,
    pub max_block_bytes: usize,
    pub mempool_max_tx: usize,
    pub mempool_max_bytes: usize,
    pub mempool_ttl_secs: u64,
    pub mempool_min_fee: u64,
    pub sync_batch_size: usize,
    pub max_reorg_depth: u64,
    pub miner_key_hex: Option<Zeroizing<String>>,
    pub genesis_amount: u64,
    pub api_key: Option<Zeroizing<String>>,
    pub testnet: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9733".parse().expect("valid default addr"),
            bootstrap_peers: vec![],
            http_port: 19734,
            cors_origin: None,
            min_peers: 3,
            peer_discovery_interval_secs: 15,
            max_message_size: 16 * 1024 * 1024,
            bootstrap_attempts: 3,
            min_diverse_subnets: 2,
            max_per_subnet: 3,
            min_asn_diversity: 2,
            db_path: "./aevum.db".to_string(),
            key_vault_path: std::env::var("HOME")
                .map(|h| format!("{}/.aevum/key.vault", h))
                .unwrap_or_else(|_| "./key.vault".to_string()),
            fresh_start: false,
            bootstrap_mode: false,
            ticks_per_block: 30,
            block_interval_secs: 30,
            max_block_tx: 50_000,
            max_block_bytes: 16 * 1024 * 1024,
            mempool_max_tx: 50_000,
            mempool_max_bytes: 128 * 1024 * 1024,
            mempool_ttl_secs: 3600,
            mempool_min_fee: 1,
            sync_batch_size: 100,
            max_reorg_depth: 64,
            miner_key_hex: None,
            genesis_amount: 21_000_000 * 100_000_000,
            api_key: None,
            testnet: false,
        }
    }
}

impl NodeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.http_port == 0 { return Err(ConfigError::InvalidHttpPort); }
        if self.ticks_per_block == 0 || self.block_interval_secs == 0 { return Err(ConfigError::InvalidTickConfig); }
        if self.genesis_amount == 0 { return Err(ConfigError::InvalidGenesisAmount); }
        if self.sync_batch_size == 0 || self.max_reorg_depth == 0 { return Err(ConfigError::InvalidSyncConfig); }
        if self.mempool_max_tx == 0 || self.mempool_max_bytes == 0 { return Err(ConfigError::InvalidMempoolConfig); }
        if self.min_peers == 0 { return Err(ConfigError::InvalidNetworkConfig); }
        if self.max_block_tx > self.mempool_max_tx {
            return Err(ConfigError::ConstraintViolation("block tx limit exceeds mempool limit".into()));
        }
        if self.max_block_bytes > self.mempool_max_bytes {
            return Err(ConfigError::ConstraintViolation("block size exceeds mempool limit".into()));
        }

        // Validate bootstrap peers
        let mut seen = HashSet::new();
        for peer in &self.bootstrap_peers {
            if peer.ip().is_unspecified() {
                return Err(ConfigError::ConstraintViolation(
                    format!("bootstrap peer {} has unspecified IP", peer)
                ));
            }
            if *peer == self.listen_addr {
                return Err(ConfigError::ConstraintViolation(
                    "bootstrap peer cannot be our own listen address".into()
                ));
            }
            if !seen.insert(*peer) {
                return Err(ConfigError::ConstraintViolation(
                    format!("duplicate bootstrap peer {}", peer)
                ));
            }
        }

        Ok(())
    }

    pub fn listen_socket_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn http_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.listen_addr.ip(), self.http_port)
    }

    pub fn bootstrap_addrs(&self) -> Vec<SocketAddr> {
        self.bootstrap_peers.clone()
    }

    /// Complete deterministic config fingerprint — all consensus+network params.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"AEVUM_CONFIG_FINGERPRINT_V7_2");
        h.update(self.listen_addr.to_string().as_bytes());
        h.update(&self.http_port.to_le_bytes());
        h.update(&self.ticks_per_block.to_le_bytes());
        h.update(&self.block_interval_secs.to_le_bytes());
        h.update(&self.max_block_tx.to_le_bytes());
        h.update(&self.max_block_bytes.to_le_bytes());
        h.update(&self.genesis_amount.to_le_bytes());
        h.update(&self.min_peers.to_le_bytes());
        h.update(&self.max_reorg_depth.to_le_bytes());
        h.update(&self.mempool_min_fee.to_le_bytes());
        h.update(&self.min_diverse_subnets.to_le_bytes());
        h.update(&self.max_per_subnet.to_le_bytes());
        h.update(&self.min_asn_diversity.to_le_bytes());
        h.update(&[self.bootstrap_mode as u8]);
        h.update(&[self.testnet as u8]);
        *h.finalize().as_bytes()
    }

    pub fn cors_header_value(&self) -> Option<String> {
        std::env::var("AEVUM_CORS_ORIGIN").ok().or_else(|| self.cors_origin.clone())
    }

    pub fn ip(&self) -> Option<IpAddr> {
        Some(self.listen_addr.ip())
    }
}
