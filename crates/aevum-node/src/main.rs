use aevum::consensus::poh::PohSnapshot;
use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::economics::Economics;
use aevum::core::state::UtxoSet;
use aevum::core::transaction::Transaction;
use aevum::crypto::keys::PrivateKey;
use aevum_node::mempool::Mempool;
use aevum_node::storage::Storage;
use aevum_node::sync::ChainSync;
use aevum_node::science_api::{ScienceTaskRequest, parse_science_task, estimate_task};
use aevum_node::task_market::TaskMarket;
use aevum_node::task_pool::TaskPool;
use aevum_node::p2p::peers::PeersManager;
use aevum_node::p2p::sync::{AtpMessage, SyncContext, create_status, handle_atp_message};
use aevum_node::p2p::gossip::GossipManager;
use aevum_node::p2p::noise::{AtpCipher, TofuStore};
use aevum_node::p2p::connection::AtpConnection;
use aevum_node::p2p::sync_engine::SyncEngine;
use aevum_node::p2p::peer_score::PeerScoring;
use aevum_node::p2p::addr_manager::AddrManager;
use aevum_node::p2p::snapshots::SnapshotManager;
use clap::Parser;
use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tiny_http::{Response, Method, Header, StatusCode};

const POH_SNAPSHOT_KEY: &str = "poh_snapshot";
const SERIAL_COUNTER_KEY: &str = "serial_counter";
const TICKS_PER_BLOCK: u64 = 100;

#[derive(Parser)]
#[command(name = "aevum-node", version = "0.3.0")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:9733")] listen_addr: String,
    #[arg(long, default_value = "")] bootstrap_peers: String,
    #[arg(long, default_value = "./aevum.db")] db_path: PathBuf,
    #[arg(long)] miner_key: Option<String>,
    #[arg(long)] miner_key_file: Option<PathBuf>,
    #[arg(long)] developer_address: String,
    #[arg(long, default_value = "19734")] http_port: u16,
    #[arg(long, default_value = "genesis.json")] genesis_file: PathBuf,
}

fn load_miner_key(cli: &Cli) -> Result<Option<PrivateKey>, String> {
    let hex_str = if let Some(ref key) = cli.miner_key { Some(key.clone()) }
    else if let Some(ref path) = cli.miner_key_file {
        match std::fs::read_to_string(path) { Ok(s) => Some(s.trim().to_string()), Err(e) => return Err(format!("Cannot read key file: {}", e)) }
    } else { None };
    match hex_str {
        None => Ok(None),
        Some(hex) => {
            let bytes = hex::decode(&hex).map_err(|e| format!("Invalid hex: {}", e))?;
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
            Ok(Some(PrivateKey::from_bytes(arr).map_err(|_| "Invalid Ed25519 key".to_string())?))
        }
    }
}

fn cors_response(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(body);
    resp.add_header(Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
    resp.add_header(Header::from_bytes("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap());
    resp.add_header(Header::from_bytes("Access-Control-Allow-Headers", "Content-Type").unwrap());
    resp
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let start_time = Instant::now();

    let storage = Arc::new(StdMutex::new(Storage::open(&cli.db_path)?));
    {
        let mut st = storage.lock().unwrap();
        if st.max_height()?.is_none() && cli.genesis_file.exists() {
            let data = std::fs::read_to_string(&cli.genesis_file)?;
            let mut block: Block = serde_json::from_str(&data)?;
            block.block_hash = block.compute_hash();
            st.save_block(&block)?;
            tracing::info!("Genesis loaded");
        }
    }

    let max_height = storage.lock().unwrap().max_height()?.unwrap_or(0);
    tracing::info!("Height: {}", max_height);

    let serial_counter: u64 = storage.lock().unwrap().load_metadata(SERIAL_COUNTER_KEY).ok().flatten()
        .map(|b| bincode::deserialize::<u64>(&b).unwrap_or(0)).unwrap_or(0);
    let serial_counter = Arc::new(StdMutex::new(serial_counter));

    let mut validator = Validator::new(b"aevum_genesis_seed");
    if let Some(snap) = storage.lock().unwrap().load_metadata(POH_SNAPSHOT_KEY)? {
        if let Ok(snap) = bincode::deserialize::<PohSnapshot>(&snap) { validator.restore_poh_from_snapshot(&snap); }
    }
    let utxo_set = storage.lock().unwrap().load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    if !utxo_set.is_empty() {
        validator.load_utxo_set(utxo_set);
        if let Some(lb) = storage.lock().unwrap().load_block(max_height)? { validator.set_last_block(lb.block_hash, lb.height, lb.poh_tick_end); }
    } else if let Some(gb) = storage.lock().unwrap().load_block(0)? { let mut gb = gb; validator.validate_and_apply(&mut gb)?; }

    let validator = Arc::new(StdMutex::new(validator));
    let mempool = Arc::new(StdMutex::new(Mempool::new(10_000)));
    let chain_sync = Arc::new(StdMutex::new(ChainSync::new(100)));
    let block_buffer = Arc::new(StdMutex::new(BTreeMap::new()));

    let miner_key = load_miner_key(&cli)?;
    let dev_addr_bytes = hex::decode(&cli.developer_address).expect("Invalid dev addr");
    let mut dev_bytes = [0u8; 32]; dev_bytes.copy_from_slice(&dev_addr_bytes[..32]);
    let developer_address = aevum::crypto::keys::PublicKey::from_bytes(dev_bytes).expect("Invalid dev key");

    let our_key = miner_key.clone().unwrap_or_else(|| PrivateKey::generate());
    let peers = Arc::new(PeersManager::new(our_key.clone()));
    let gossip = Arc::new(StdMutex::new(GossipManager::new()));
    let tofu = Arc::new(StdMutex::new(TofuStore::new()));
    let peer_scoring = Arc::new(StdMutex::new(PeerScoring::new()));
    let addr_manager = Arc::new(StdMutex::new(AddrManager::new(10000)));

    let sync_ctx = Arc::new(SyncContext {
        validator: validator.clone(),
        storage: storage.clone(),
        chain_sync: chain_sync.clone(),
        block_buffer: block_buffer.clone(),
    });

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_ctrl = shutdown.clone();
    ctrlc::set_handler(move || {
        tracing::info!("Ctrl+C received");
        shutdown_ctrl.store(true, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    // ============================================================
    // ATP ПОТОК
    // ============================================================
    let server_listen_addr = cli.listen_addr.clone();
    let atp_peers = peers.clone();
    let atp_ctx = sync_ctx.clone();
    let atp_key = our_key.clone();
    let atp_tofu = tofu.clone();
    let atp_shutdown = shutdown.clone();
    let bootstrap_peers: Vec<String> = if cli.bootstrap_peers.is_empty() { vec![] } else { cli.bootstrap_peers.split(',').map(|s| s.trim().to_string()).collect() };

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4).thread_name("aevum-atp").enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = match TcpListener::bind(&server_listen_addr).await {
                Ok(l) => l, Err(e) => { tracing::error!("Bind: {}", e); return; }
            };
            tracing::info!("[ATP] Listening on {}", server_listen_addr);

            if !bootstrap_peers.is_empty() {
                let dp = atp_peers.clone(); let dc = atp_ctx.clone(); let dk = atp_key.clone(); let dt = atp_tofu.clone(); let ds = atp_shutdown.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    for addr_str in &bootstrap_peers {
                        if ds.load(Ordering::SeqCst) { break; }
                        if let Ok(addr) = addr_str.trim().parse::<SocketAddr>() {
                            for retry in 0..5 {
                                if retry > 0 { tokio::time::sleep(Duration::from_secs(5 * (retry + 1) as u64)).await; }
                                match aevum_node::p2p::peers::dial_peer(addr, dk.clone(), &dt).await {
                                    Ok((cipher, peer_id, reader, writer)) => {
                                        tracing::info!("✅ CONNECTED to {}", hex::encode(&peer_id));
                                        AtpConnection::new(cipher, peer_id, addr, dp.clone(), dc.clone(), false).run(reader, writer).await;
                                        break;
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                    }
                });
            }

            while !atp_shutdown.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
                    Ok(Ok((stream, addr))) => {
                        if !atp_peers.can_accept(&addr) { continue; }
                        let pc = atp_peers.clone(); let cc = atp_ctx.clone(); let kc = atp_key.clone(); let tc = atp_tofu.clone();
                        tokio::spawn(async move {
                            match aevum_node::p2p::peers::accept_connection(stream, kc, &tc).await {
                                Ok((cipher, peer_id, remote_addr, reader, writer)) => {
                                    tracing::info!("✅ Accepted from {}", hex::encode(&peer_id));
                                    AtpConnection::new(cipher, peer_id, remote_addr, pc, cc, true).run(reader, writer).await;
                                }
                                Err(e) => tracing::warn!("Accept failed: {}", e),
                            }
                        });
                    }
                    Ok(Err(e)) => tracing::error!("Accept error: {}", e),
                    Err(_) => {}
                }
            }
        });
    });

    // HTTP
    let http_port = cli.http_port;
    let mempool_http = mempool.clone(); let validator_http = validator.clone(); let peers_http = peers.clone();
    let shutdown_http = shutdown.clone(); let start_time_http = start_time;
    std::thread::spawn(move || {
        let addr = format!("0.0.0.0:{}", http_port);
        let server = match tiny_http::Server::http(&addr) { Ok(s) => s, Err(e) => { tracing::error!("HTTP: {}", e); return; } };
        tracing::info!("HTTP API on http://{}", addr);
        while !shutdown_http.load(Ordering::SeqCst) {
            if let Ok(Some(mut request)) = server.recv_timeout(Duration::from_secs(1)) {
                match (request.url(), request.method()) {
                    ("/health", _) => { request.respond(cors_response("{\"status\":\"ok\"}")).ok(); }
                    ("/status", _) => {
                        let (height, utxos, poh_tick, supply, uptime) = {
                            let val = validator_http.lock().unwrap();
                            (val.last_block_height(), val.utxo_set().len(), val.poh().current_tick_number(), val.utxo_set().total_supply(), start_time_http.elapsed().as_secs())
                        };
                        let pc = peers_http.peer_count(); let ms = mempool_http.lock().unwrap().len();
                        let s = format!("{{\"height\":{},\"peers\":{},\"mempool\":{},\"utxos\":{},\"poh_tick\":{},\"supply\":{},\"uptime_sec\":{}}}", height, pc, ms, utxos, poh_tick, supply, uptime);
                        request.respond(cors_response(&s)).ok();
                    }
                    ("/tx", &Method::Post) => {
                        let mut body = String::new(); request.as_reader().read_to_string(&mut body).ok();
                        if let Ok(tx) = serde_json::from_str::<Transaction>(&body) { mempool_http.lock().unwrap().insert(tx).ok(); request.respond(cors_response("ok")).ok(); }
                        else { request.respond(cors_response("err")).ok(); }
                    }
                    _ => { request.respond(Response::from_string("404").with_status_code(StatusCode(404))).ok(); }
                }
            }
        }
    });

    // ============================================================
    // МАЙНИНГ
    // ============================================================
    let mut mining_handle = None;
    if let Some(mk) = miner_key {
        let vm = validator.clone(); let mm = mempool.clone(); let sm = storage.clone();
        let dam = developer_address; let sc = serial_counter.clone(); let shm = shutdown.clone(); let pm = peers.clone(); let s_m = sync_ctx.clone();
        let handle = std::thread::spawn(move || {
            while !shm.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(1));
                let (tick_result, txs_backup, height, poh) = {
                    let mut val = vm.lock().unwrap(); let mut mem = mm.lock().unwrap();
                    val.tick_poh(); let poh = val.poh().current_tick_number();
                    if poh % 10 == 0 || !mem.is_empty() { (true, mem.take_batch(100), val.last_block_height() + 1, poh) }
                    else { (false, vec![], 0, poh) }
                };
                if tick_result {
                    let mut txs = txs_backup.clone();
                    let mut val = vm.lock().unwrap(); let mut st = sm.lock().unwrap();
                    let total_fees: u64 = txs.iter().map(|tx| {
                        let a: u64 = tx.outputs.iter().map(|o| o.amount).sum();
                        if a > 0 { Economics::calculate_fee(a).0 } else { 0 }
                    }).sum();
                    let mut serial = sc.lock().unwrap(); *serial += 2;
                    let coinbase = Economics::create_coinbase(&mk.public_key(), height, total_fees, &dam, *serial, poh);
                    txs.insert(0, coinbase);
                    let mut block = Block::new(val.last_block_hash(), height, poh, poh + TICKS_PER_BLOCK, txs, val.utxo_set().state_root(), val.utxo_set().total_supply() + total_fees, None);
                    if val.validate_and_apply(&mut block).is_ok() {
                        st.save_block(&block).ok(); if let Err(e) = st.save_utxo_set(val.utxo_set()) { tracing::error!("Failed to save UTXO: {}", e); }
                        let _ = bincode::serialize(&val.poh_snapshot()).ok().and_then(|s| st.save_metadata(POH_SNAPSHOT_KEY, &s).ok());
                        let _ = bincode::serialize(&*serial).ok().and_then(|s| st.save_metadata(SERIAL_COUNTER_KEY, &s).ok());
                        // UTXO снапшот каждые 1000 блоков
                        if height % 1000 == 0 {
                            let _ = SnapshotManager::save_if_needed(&sm, height, val.utxo_set());
                        }
                        drop(val); drop(st); drop(serial);
                        tracing::info!("⛏️  Mined block at height {}", height);
                        let status = create_status(&s_m);
                        if let Ok(data) = bincode::serialize(&status) { pm.broadcast(data); }
                    } else { let mut mem = mm.lock().unwrap(); for tx in txs_backup { mem.insert(tx).ok(); } }
                }
            }
        });
        mining_handle = Some(handle);
    }

    // Heartbeat
    let hb_ctx = sync_ctx.clone(); let hb_peers = peers.clone(); let shutdown_hb = shutdown.clone();
    std::thread::spawn(move || {
        while !shutdown_hb.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(30));
            let h = hb_ctx.validator.lock().unwrap().last_block_height();
            tracing::info!("❤️ Heartbeat: height={}, peers={}", h, hb_peers.peer_count());
            let status = create_status(&hb_ctx);
            if let Ok(data) = bincode::serialize(&status) { hb_peers.broadcast(data); }
        }
    });

    tracing::info!("🚀 Aevum Node v0.3.0 — ATP Protocol");

    while !shutdown.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_secs(1)); }

    tracing::info!("Shutting down...");
    if let Some(h) = mining_handle { h.join().ok(); }
    Ok(())
}
