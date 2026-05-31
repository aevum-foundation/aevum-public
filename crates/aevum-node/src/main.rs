use aevum::consensus::poh::PohSnapshot;
use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::state::UtxoSet;
use aevum::core::transaction::{Transaction, TxOutput};
use aevum::core::jt_utxo::JtUtxo;
use aevum::crypto::keys::PrivateKey;
use aevum::crypto::hash::Hash;
use aevum_node::mempool::Mempool;
use aevum_node::storage::Storage;
use aevum_node::sync::ChainSync;
use aevum_node::p2p::peers::PeersManager;
use aevum_node::p2p::sync::{SyncContext, SyncPhase, create_status, check_sync_timeouts, cleanup_pending_solo_requests};
use aevum_node::p2p::noise::TofuStore;
use aevum_node::p2p::dht::Dht;
use aevum_node::p2p::dht_integration::DhtIntegration;
use aevum_node::encrypted_replication::EncryptedReplication;
use aevum_node::p2p::chain_orchestrator::ChainOrchestrator;
use aevum_node::p2p::connection_manager::ConnectionManager;
use aevum_node::config::NodeConfig;
use aevum_node::http_server::{BalanceCache, SharedBalanceCache, SharedMetrics, NodeMetrics};
use clap::Parser;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc as tokio_mpsc;

const POH_SNAPSHOT_KEY: &str = "poh_snapshot";
const SERIAL_COUNTER_KEY: &str = "serial_counter";

fn create_genesis_block(config: &NodeConfig) -> Block {
    let addr_bytes = hex::decode(&config.genesis_address).expect("Invalid genesis address");
    let mut pk_bytes = [0u8; 32]; pk_bytes.copy_from_slice(&addr_bytes[..32]);
    let founder_key = aevum::crypto::keys::PublicKey::from_bytes(pk_bytes).expect("Invalid genesis key");
    let utxo = JtUtxo::new_global_clean(founder_key, config.genesis_amount, &[1u8; 32], &[1u8; 32], 0, 0, Hash::zero()).expect("Genesis UTXO");
    let output = TxOutput::from_jt_utxo(&utxo, 0);
    let tx = Transaction::new(vec![], vec![output], 0);
    Block::genesis(vec![tx])
}

#[derive(Parser)]
#[command(name = "aevum-node", version = "0.9.32")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:9733")] listen_addr: String,
    #[arg(long, default_value = "")] bootstrap_peers: String,
    #[arg(long, default_value = "./aevum.db")] db_path: String,
    #[arg(long)] miner_key: Option<String>,
    #[arg(long, default_value = "0ffc25780ab973a85612aad6f0b7abb35bd3fd2222387de0364fd522f79c36e3")] developer_address: String,
    #[arg(long, default_value = "19734")] http_port: u16,
    #[arg(long)] bootstrap_mode: bool,
}

fn load_miner_key(hex: &Option<String>) -> Result<Option<PrivateKey>, String> {
    match hex {
        None => Ok(None),
        Some(hex) => {
            let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
            Ok(Some(PrivateKey::from_bytes(arr).map_err(|_| "Invalid Ed25519 key".to_string())?))
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let miner_key_hex = cli.miner_key.clone();

    let config = NodeConfig {
        listen_addr: cli.listen_addr,
        bootstrap_peers: if cli.bootstrap_peers.is_empty() { vec![] } else { cli.bootstrap_peers.split(',').map(|s| s.trim().to_string()).collect() },
        db_path: cli.db_path,
        http_port: cli.http_port,
        miner_key_hex: miner_key_hex.clone(),
        developer_address: cli.developer_address,
        bootstrap_mode: cli.bootstrap_mode,
        ..Default::default()
    };

    let our_key = load_miner_key(&miner_key_hex)?.unwrap_or_else(|| PrivateKey::generate());
    let miner_pubkey = our_key.public_key();
    let storage = Arc::new(StdMutex::new(Storage::open(&std::path::PathBuf::from(&config.db_path))?.with_encryption(&miner_pubkey.to_bytes())));

    let builtin_genesis = create_genesis_block(&config);
    let mut validator = Validator::new(b"aevum_genesis_seed");
    {
        let mut st = storage.lock().unwrap();
        if st.max_genesis_height()?.is_none() {
            if config.bootstrap_mode {
                st.save_genesis_block(&builtin_genesis)?;
                let mut g = builtin_genesis.clone();
                if validator.validate_and_apply(&mut g).is_ok() {
                    tracing::info!("[GENESIS] Bootstrap genesis applied: hash={}", g.block_hash.to_hex());
                }
            } else {
                tracing::info!("[GENESIS] No genesis yet — will download from peers");
            }
        } else if let Ok(Some(existing)) = st.load_genesis_block(0) {
            if existing.block_hash != builtin_genesis.block_hash {
                st.save_my_block(0, &existing).ok();
                st.delete_genesis_block(0).ok();
                st.save_genesis_block(&builtin_genesis)?;
            }
        }
    }

    let max_height = storage.lock().unwrap().max_genesis_height()?.unwrap_or(0);
    tracing::info!("Height: {}", max_height);
    let serial_counter: u64 = storage.lock().unwrap().load_metadata(SERIAL_COUNTER_KEY).ok().flatten()
        .map(|b| bincode::deserialize::<u64>(&b).unwrap_or(0)).unwrap_or(0);
    let serial_counter = Arc::new(StdMutex::new(serial_counter));

    if let Some(snap) = storage.lock().unwrap().load_metadata(POH_SNAPSHOT_KEY)? {
        if let Ok(snap) = bincode::deserialize::<PohSnapshot>(&snap) { validator.restore_poh_from_snapshot(&snap); }
    }
    let utxo_set = storage.lock().unwrap().load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    if utxo_set.is_empty() && max_height > 0 {
        let mut temp_val = Validator::new(b"aevum_genesis_seed");
        for h in 0..=max_height {
            if let Ok(Some(mut block)) = storage.lock().unwrap().load_genesis_block(h) { temp_val.validate_and_apply(&mut block).ok(); }
        }
        validator.load_utxo_set(temp_val.utxo_set().clone());
        validator.genesis_applied = true;
        if let Some(lb) = storage.lock().unwrap().load_genesis_block(max_height)? { validator.set_last_block(lb.block_hash, lb.height, lb.poh_tick_end); }
    } else if !utxo_set.is_empty() {
        validator.load_utxo_set(utxo_set);
        validator.genesis_applied = true;
        if let Some(lb) = storage.lock().unwrap().load_genesis_block(max_height)? { validator.set_last_block(lb.block_hash, lb.height, lb.poh_tick_end); }
    }

    let validator = Arc::new(StdMutex::new(validator));
    let mempool = Arc::new(StdMutex::new(Mempool::new(10_000)));
    let chain_sync = Arc::new(StdMutex::new(ChainSync::new(100)));
    let block_buffer = Arc::new(StdMutex::new(BTreeMap::new()));
    let dev_addr_bytes = hex::decode(&config.developer_address).expect("Invalid dev addr");
    let mut dev_bytes = [0u8; 32]; dev_bytes.copy_from_slice(&dev_addr_bytes[..32]);
    let developer_address = aevum::crypto::keys::PublicKey::from_bytes(dev_bytes).expect("Invalid dev key");

    let metrics: SharedMetrics = Arc::new(NodeMetrics::new());
    let peers = Arc::new(PeersManager::new(our_key.clone(), metrics.clone(), storage.clone()));
    let tofu = Arc::new(tokio::sync::Mutex::new(TofuStore::new()));
    let dht = Arc::new(StdMutex::new(Dht::new(blake3::hash(&miner_pubkey.to_bytes()).into())));
    let replication = Arc::new(StdMutex::new(EncryptedReplication::new(Some(our_key.clone()), 1000)));
    let orchestrator = Arc::new(StdMutex::new(ChainOrchestrator::recover(&storage.lock().unwrap())));
    let network_height = Arc::new(StdMutex::new(max_height));
    let last_peer_discovery = Arc::new(StdMutex::new(Instant::now()));
    let balance_cache: SharedBalanceCache = Arc::new(StdMutex::new(BalanceCache::new()));

    let our_node_id: [u8; 32] = blake3::hash(&miner_pubkey.to_bytes()).into();
    let dht_integration = Arc::new(StdMutex::new(DhtIntegration::new(our_node_id, config.listen_socket_addr(), peers.clone())));

    let shutdown = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({ let s = shutdown.clone(); move || { tracing::info!("Ctrl+C"); s.store(true, Ordering::SeqCst); } }).expect("Ctrl+C handler");

    let sync_ctx = Arc::new(SyncContext {
        validator: validator.clone(), storage: storage.clone(),
        chain_sync: chain_sync.clone(), block_buffer: block_buffer.clone(),
        replication: Some(replication.clone()), dht: dht.clone(),
        orchestrator: orchestrator.clone(), network_height: network_height.clone(),
        sync_phase: Arc::new(parking_lot::Mutex::new(SyncPhase::Idle)),
        sync_peer: Arc::new(parking_lot::Mutex::new(None)),
        pending_solo_requests: Arc::new(StdMutex::new(Vec::new())),
        metrics: metrics.clone(),
    });

    // Sync Timeout Checker
    let tm_ctx = sync_ctx.clone(); let tm_peers = peers.clone(); let tm_shutdown = shutdown.clone();
    std::thread::spawn(move || { while !tm_shutdown.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_secs(5)); check_sync_timeouts(&tm_ctx, &tm_peers); } });

    // Pending Solo Requests Cleanup
    let psc_ctx = sync_ctx.clone(); let psc_shutdown = shutdown.clone();
    std::thread::spawn(move || { while !psc_shutdown.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_secs(config.pending_solo_cleanup_interval_secs)); cleanup_pending_solo_requests(&psc_ctx); } });

    // Ban cleanup + flush PeerDb
    let ban_peers = peers.clone(); let ban_shutdown = shutdown.clone();
    std::thread::spawn(move || { while !ban_shutdown.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_secs(600)); ban_peers.cleanup_bans(); ban_peers.flush_known_addresses(); } });

    // HTTP Server
    let http_config = config.clone();
    let http_validator = validator.clone();
    let http_mempool = mempool.clone();
    let http_peers = peers.clone();
    let http_storage = storage.clone();
    let http_network_height = network_height.clone();
    let http_balance_cache = balance_cache.clone();
    let http_miner_pubkey = miner_pubkey.clone();
    let http_shutdown = shutdown.clone();
    let http_metrics = metrics.clone();
    std::thread::spawn(move || {
        aevum_node::http_server::start(
            http_config, http_validator, http_mempool, http_peers,
            http_storage, http_network_height, http_balance_cache,
            http_miner_pubkey, http_shutdown, http_metrics,
        );
    });

    // ATP Server
    aevum_node::atp_server::start(
        config.listen_addr.clone(), peers.clone(), sync_ctx.clone(), our_key.clone(),
        tofu.clone(), shutdown.clone(),
    );

    // Mining Loop
    let (connect_tx, connect_rx) = tokio_mpsc::unbounded_channel();
    if let Some(mk) = load_miner_key(&miner_key_hex)? {
        aevum_node::mining_loop::start(
            mk, validator.clone(), mempool.clone(), storage.clone(),
            developer_address, serial_counter.clone(), peers.clone(), sync_ctx.clone(),
            network_height.clone(), last_peer_discovery.clone(), our_key.clone(),
            tofu.clone(), dht_integration.clone(), connect_tx, shutdown.clone(),
            balance_cache.clone(), metrics.clone(),
        );
    }

    // DHT Connect Loop
    aevum_node::connect_loop::start(
        connect_rx, our_key.clone(), tofu.clone(), peers.clone(),
        sync_ctx.clone(), dht_integration, shutdown.clone(),
    );

    // Connection Manager
    let cm = ConnectionManager::new(
        peers.clone(), sync_ctx.clone(), our_key.clone(), tofu.clone(),
        config.bootstrap_peers.clone(), shutdown.clone(),
    );
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2).thread_name("aevum-connmgr").enable_all().build().unwrap();
        rt.block_on(async move { cm.run().await; });
    });

    // Orchestrator Loop
    aevum_node::orchestrator_loop::start(
        validator.clone(), storage.clone(), network_height.clone(),
        peers.clone(), orchestrator.clone(), sync_ctx.sync_phase.clone(), shutdown.clone(),
        metrics.clone(),
    );

    // Heartbeat
    let hb_ctx = sync_ctx.clone(); let hb_peers = peers.clone(); let shutdown_hb = shutdown.clone();
    std::thread::spawn(move || {
        while !shutdown_hb.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(30));
            let status = create_status(&hb_ctx);
            if let Ok(data) = bincode::serialize(&status) { hb_peers.broadcast(data); }
        }
    });

    tracing::info!("🚀 Aevum Node v0.9.32 — ATP Protocol");
    while !shutdown.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_secs(1)); }
    Ok(())
}
