use std::net::SocketAddr;

#[derive(Clone)]
pub struct NodeConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub db_path: String,
    pub http_port: u16,
    pub miner_key_hex: Option<String>,
    pub developer_address: String,
    pub bootstrap_mode: bool,
    pub ticks_per_block: u64,
    pub min_peers: usize,
    pub peer_discovery_interval_secs: u64,
    pub orchestrator_interval_secs: u64,
    pub pending_solo_cleanup_interval_secs: u64,
    pub genesis_address: String,
    pub genesis_amount: u64,
    pub cors_origin: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:9733".to_string(),
            bootstrap_peers: vec![],
            db_path: "./aevum.db".to_string(),
            http_port: 19734,
            miner_key_hex: None,
            developer_address: "0ffc25780ab973a85612aad6f0b7abb35bd3fd2222387de0364fd522f79c36e3".to_string(),
            bootstrap_mode: false,
            ticks_per_block: 30,
            min_peers: 2,
            peer_discovery_interval_secs: 15,
            orchestrator_interval_secs: 30,
            pending_solo_cleanup_interval_secs: 60,
            genesis_address: "0ffc25780ab973a85612aad6f0b7abb35bd3fd2222387de0364fd522f79c36e3".to_string(),
            genesis_amount: 21_000_000 * 100_000_000,
            cors_origin: "*".to_string(),
        }
    }
}

impl NodeConfig {
    pub fn cors_header_value(&self) -> String {
        std::env::var("AEVUM_CORS_ORIGIN").unwrap_or_else(|_| self.cors_origin.clone())
    }

    pub fn listen_socket_addr(&self) -> SocketAddr {
        self.listen_addr.parse().unwrap_or_else(|_| "0.0.0.0:9733".parse().unwrap())
    }

    pub fn bootstrap_addrs(&self) -> Vec<SocketAddr> {
        self.bootstrap_peers.iter().filter_map(|s| s.parse().ok()).collect()
    }
}
