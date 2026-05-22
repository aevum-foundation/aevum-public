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
use aevum_node::p2p::peers::PeersManager;
use aevum_node::p2p::sync::{AtpMessage, SyncContext, create_status, handle_atp_message};
use aevum_node::p2p::noise::{AtpCipher, TofuStore};
use aevum_node::p2p::connection::AtpConnection;
use aevum_node::p2p::pex::PeerExchange;
use aevum_node::p2p::peer_score::PeerScoring;
use aevum_node::p2p::addr_manager::AddrManager;
use aevum_node::p2p::snapshots::SnapshotManager;
use aevum_node::encrypted_replication::EncryptedReplication;
use aevum_node::p2p::chain_orchestrator::ChainOrchestrator;
use clap::Parser;
use std::collections::BTreeMap;
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
#[command(name = "aevum-node", version = "0.4.0")]
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
    let our_key = load_miner_key(&cli)?.unwrap_or_else(|| PrivateKey::generate());
    let miner_pubkey = our_key.public_key();

    let storage = Arc::new(StdMutex::new(
        Storage::open(&cli.db_path)?.with_encryption(&miner_pubkey.to_bytes())
    ));

    {
        let mut st = storage.lock().unwrap();
        if st.max_genesis_height()?.is_none() && cli.genesis_file.exists() {
            let data = std::fs::read_to_string(&cli.genesis_file)?;
            let mut block: Block = serde_json::from_str(&data)?;
            block.block_hash = block.compute_hash();
            st.save_genesis_block(&block)?;
        }
    }

    let max_height = storage.lock().unwrap().max_genesis_height()?.unwrap_or(0);
    tracing::info!("Height: {}", max_height);

    let serial_counter: u64 = storage.lock().unwrap().load_metadata(SERIAL_COUNTER_KEY).ok().flatten()
        .map(|b| bincode::deserialize::<u64>(&b).unwrap_or(0)).unwrap_or(0);
    let serial_counter = Arc::new(StdMutex::new(serial_counter));

    let mut validator = Validator::new(b"aevum_genesis_seed");
    if let Some(snap) = storage.lock().unwrap().load_metadata(POH_SNAPSHOT_KEY)? {
        if let Ok(snap) = bincode::deserialize::<PohSnapshot>(&snap) { validator.restore_poh_from_snapshot(&snap); }
    }
    
    let utxo_set = storage.lock().unwrap().load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    
    // Проверка целостности: если UTXO не соответствует количеству блоков — перестроить
    if utxo_set.total_supply() == 0 || utxo_set.len() < max_height as usize {
        tracing::info!("UTXO mismatch: supply={}, utxos={}, blocks={}. Rebuilding...",
            utxo_set.total_supply(), utxo_set.len(), max_height);
        let mut temp_val = Validator::new(b"aevum_genesis_seed");
        for h in 0..=max_height {
            if let Ok(Some(mut block)) = storage.lock().unwrap().load_genesis_block(h) {
                temp_val.validate_and_apply(&mut block).ok();
            }
        }
        validator.load_utxo_set(temp_val.utxo_set().clone());
        if let Some(lb) = storage.lock().unwrap().load_genesis_block(max_height)? {
            validator.set_last_block(lb.block_hash, lb.height, lb.poh_tick_end);
        }
        validator.last_poh_tick_end = validator.poh().current_tick_number();
        tracing::info!("UTXO rebuilt: supply={}, utxos={}", validator.utxo_set().total_supply(), validator.utxo_set().len());
    } else if !utxo_set.is_empty() {
        validator.load_utxo_set(utxo_set);
        validator.genesis_applied = true;
        if let Some(lb) = storage.lock().unwrap().load_genesis_block(max_height)? {
            validator.set_last_block(lb.block_hash, lb.height, lb.poh_tick_end);
        }
    } else if let Some(gb) = storage.lock().unwrap().load_genesis_block(0)? {
        let mut gb = gb; validator.validate_and_apply(&mut gb)?;
    }

    let validator = Arc::new(StdMutex::new(validator));
    let mempool = Arc::new(StdMutex::new(Mempool::new(10_000)));
    let chain_sync = Arc::new(StdMutex::new(ChainSync::new(100)));
    let block_buffer = Arc::new(StdMutex::new(BTreeMap::new()));

    let dev_addr_bytes = hex::decode(&cli.developer_address).expect("Invalid dev addr");
    let mut dev_bytes = [0u8; 32]; dev_bytes.copy_from_slice(&dev_addr_bytes[..32]);
    let developer_address = aevum::crypto::keys::PublicKey::from_bytes(dev_bytes).expect("Invalid dev key");

    let peers = Arc::new(PeersManager::new(our_key.clone()));
    let tofu = Arc::new(StdMutex::new(TofuStore::new()));
    let dht = Arc::new(StdMutex::new(aevum_node::p2p::dht::Dht::new(blake3::hash(&miner_pubkey.to_bytes()).into())));
    let replication = Arc::new(StdMutex::new(EncryptedReplication::new(Some(our_key.clone()), 1000)));
    let orchestrator = Arc::new(StdMutex::new(ChainOrchestrator::recover(&storage.lock().unwrap())));

    let sync_ctx = Arc::new(SyncContext {
        validator: validator.clone(), storage: storage.clone(),
        chain_sync: chain_sync.clone(), block_buffer: block_buffer.clone(),
        replication: Some(replication.clone()), dht: dht.clone(),
        orchestrator: orchestrator.clone(),
    });

    let shutdown = Arc::new(AtomicBool::new(false));
    ctrlc::set_handler({
        let s = shutdown.clone();
        move || { tracing::info!("Ctrl+C"); s.store(true, Ordering::SeqCst); }
    }).expect("Ctrl+C handler");

    // ATP
    let server_listen_addr = cli.listen_addr.clone();
    let atp_peers = peers.clone(); let atp_ctx = sync_ctx.clone(); let atp_key = our_key.clone(); let atp_tofu = tofu.clone(); let atp_shutdown = shutdown.clone();
    let bootstrap_peers: Vec<String> = if cli.bootstrap_peers.is_empty() { vec![] } else { cli.bootstrap_peers.split(',').map(|s| s.trim().to_string()).collect() };

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).thread_name("aevum-atp").enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = match TcpListener::bind(&server_listen_addr).await { Ok(l) => l, Err(e) => { tracing::error!("Bind: {}", e); return; } };
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
                                        let conn = AtpConnection::new(cipher, peer_id, addr, dp.clone(), dc.clone(), false);
                                        let conn_handle = tokio::spawn(async move { conn.run(reader, writer).await; });
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        aevum_node::p2p::pex::PeerExchange::request_peers(&dp, &peer_id);
                                        let _ = conn_handle.await; break;
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
    let shutdown_http = shutdown.clone(); let start_time = Instant::now();
    std::thread::spawn(move || {
        let server = match tiny_http::Server::http(&format!("0.0.0.0:{}", http_port)) { Ok(s) => s, Err(_) => return };
        while !shutdown_http.load(Ordering::SeqCst) {
            if let Ok(Some(mut req)) = server.recv_timeout(Duration::from_secs(1)) {
                match (req.url(), req.method()) {
                    ("/health", _) => { req.respond(cors_response("{\"status\":\"ok\"}")).ok(); }
                    ("/status", _) => {
                        let val = validator_http.lock().unwrap();
                        let s = format!("{{\"height\":{},\"peers\":{},\"mempool\":{},\"utxos\":{},\"poh_tick\":{},\"supply\":{},\"uptime_sec\":{}}}",
                            val.last_block_height(), peers_http.peer_count(), mempool_http.lock().unwrap().len(),
                            val.utxo_set().len(), val.poh().current_tick_number(), val.utxo_set().total_supply(), start_time.elapsed().as_secs());
                        req.respond(cors_response(&s)).ok();
                    }
                    _ => { req.respond(Response::from_string("404").with_status_code(StatusCode(404))).ok(); }
                }
            }
        }
    });

    // МАЙНИНГ
    if let Some(mk) = load_miner_key(&cli)? {
        let vm = validator.clone(); let mm = mempool.clone(); let sm = storage.clone();
        let dam = developer_address; let sc = serial_counter.clone(); let shm = shutdown.clone(); let pm = peers.clone(); let s_m = sync_ctx.clone();
        std::thread::spawn(move || {
            while !shm.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(1));
                let mut val = vm.lock().unwrap();
                let mut mem = mm.lock().unwrap();
                val.tick_poh();
                let poh = val.poh().current_tick_number();
                let active_miners = pm.peer_count().max(1) as u64;
                let target_ticks = 100u64.saturating_sub((active_miners / 10).min(80));
                let should_mine = poh % target_ticks == 0 || !mem.is_empty();
                let txs_backup = if should_mine { mem.take_batch(100) } else { vec![] };
                let height = val.last_block_height() + 1;
                drop(mem); drop(val);
                
                if should_mine {
                    let mut val = vm.lock().unwrap();
                    let mut st = sm.lock().unwrap();
                    let mut txs = txs_backup.clone();
                    let total_fees: u64 = txs.iter().map(|tx| {
                        let a: u64 = tx.outputs.iter().map(|o| o.amount).sum();
                        if a > 0 { Economics::calculate_fee(a).0 } else { 0 }
                    }).sum();
                    let mut serial = sc.lock().unwrap(); *serial += 2;
                    let coinbase = Economics::create_coinbase(&mk.public_key(), height, total_fees, &dam, *serial, poh);
                    drop(serial);
                    txs.insert(0, coinbase);
                    let mut block = Block::new(val.last_block_hash(), height, poh, poh + TICKS_PER_BLOCK, txs,
                        val.utxo_set().get_state_root(),
                        val.utxo_set().total_supply() + Economics::block_reward_satoshi(height) + total_fees, None);
                    if val.validate_and_apply(&mut block).is_ok() {
                        st.save_genesis_block(&block).ok();
                        st.save_utxo_set(val.utxo_set()).ok();
                        let _ = bincode::serialize(&val.poh_snapshot()).ok().and_then(|s| st.save_metadata(POH_SNAPSHOT_KEY, &s).ok());
                        tracing::info!("BLOCK MINED: height={}", height);
                        drop(val); drop(st);
                        if let Ok(mut orch) = s_m.orchestrator.lock() {
                            let mut v = vm.lock().unwrap(); let mut s = sm.lock().unwrap();
                            let _ = orch.process_chain(&mut v, &mut s, &s_m, &pm);
                        }
                        let status = create_status(&s_m);
                        if let Ok(data) = bincode::serialize(&status) { pm.broadcast(data); }
                    } else {
                        drop(val); drop(st);
                        let mut mem = mm.lock().unwrap();
                        for tx in txs_backup { mem.insert(tx).ok(); }
                    }
                }
            }
        });
    }

    // Heartbeat
    let hb_ctx = sync_ctx.clone(); let hb_peers = peers.clone(); let shutdown_hb = shutdown.clone();
    std::thread::spawn(move || {
        while !shutdown_hb.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(30));
            let h = hb_ctx.validator.lock().unwrap().last_block_height();
            let status = create_status(&hb_ctx);
            if let Ok(data) = bincode::serialize(&status) { hb_peers.broadcast(data); }
        }
    });

    while !shutdown.load(Ordering::SeqCst) { std::thread::sleep(Duration::from_secs(1)); }
    Ok(())
}
