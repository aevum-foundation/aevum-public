use aevum::consensus::validator::Validator;
use aevum::core::transaction::Transaction;
use aevum::crypto::keys::PublicKey;
use crate::mempool::Mempool;
use crate::storage::Storage;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::AtpMessage;
use crate::config::NodeConfig;
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tiny_http::{Response, Method, Header, StatusCode};

const MAX_HISTORY_LIMIT: usize = 100;
const MAX_UTXOS_LIMIT: usize = 500;

pub struct BalanceCache {
    pub balances: BTreeMap<String, u64>,
    pub last_update: Instant,
}

fn cors_response(body: &str, origin: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut resp = Response::from_string(body);
    resp.add_header(Header::from_bytes("Access-Control-Allow-Origin", origin).unwrap());
    resp.add_header(Header::from_bytes("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap());
    resp.add_header(Header::from_bytes("Access-Control-Allow-Headers", "Content-Type").unwrap());
    resp
}

pub fn start(
    config: NodeConfig,
    validator: Arc<StdMutex<Validator>>,
    mempool: Arc<StdMutex<Mempool>>,
    peers: Arc<PeersManager>,
    storage: Arc<StdMutex<Storage>>,
    network_height: Arc<StdMutex<u64>>,
    balance_cache: Arc<StdMutex<BalanceCache>>,
    miner_pubkey: PublicKey,
    shutdown: Arc<AtomicBool>,
) {
    let cors_origin = config.cors_header_value();
    let genesis_addr = config.genesis_address.clone();

    std::thread::spawn(move || {
        let server = match tiny_http::Server::http(&format!("0.0.0.0:{}", config.http_port)) {
            Ok(s) => s,
            Err(e) => { tracing::error!("HTTP server failed: {}", e); return; }
        };
        let start_time = Instant::now();

        while !shutdown.load(Ordering::SeqCst) {
            match server.recv_timeout(Duration::from_secs(1)) {
                Ok(Some(mut req)) => {
                    let url = req.url().to_string();
                    let method = req.method();

                    match url.as_str() {
                        u if u == "/health" => {
                            let val = validator.lock().unwrap();
                            let nh = *network_height.lock().unwrap();
                            let synced = val.last_block_height() >= nh;
                            let s = format!("{{\"status\":\"ok\",\"height\":{},\"peers\":{},\"synced\":{},\"uptime_sec\":{}}}",
                                val.last_block_height(), peers.peer_count(), synced, start_time.elapsed().as_secs());
                            req.respond(cors_response(&s, &cors_origin)).ok();
                        }
                        u if u.starts_with("/status") => {
                            let val = validator.lock().unwrap();
                            let nh = *network_height.lock().unwrap();
                            let synced = val.last_block_height() >= nh;
                            let s = format!("{{\"height\":{},\"peers\":{},\"mempool\":{},\"utxos\":{},\"poh_tick\":{},\"supply\":{},\"uptime_sec\":{},\"network_height\":{},\"synced\":{}}}",
                                val.last_block_height(), peers.peer_count(), mempool.lock().unwrap().len(),
                                val.utxo_set().len(), val.poh().current_tick_number(), val.utxo_set().total_supply(),
                                start_time.elapsed().as_secs(), nh, synced);
                            req.respond(cors_response(&s, &cors_origin)).ok();
                        }
                        u if u.starts_with("/balance") => {
                            let val = validator.lock().unwrap();
                            let utxo_set = val.utxo_set();
                            let mut cache = balance_cache.lock().unwrap();
                            if cache.last_update.elapsed() > Duration::from_secs(30) {
                                cache.balances.clear();
                                for (_, utxo) in utxo_set.all() {
                                    let addr = hex::encode(utxo.owner().to_bytes());
                                    *cache.balances.entry(addr).or_insert(0) += utxo.amount();
                                }
                                cache.last_update = Instant::now();
                            }
                            let miner_addr = hex::encode(miner_pubkey.to_bytes());
                            let miner_balance = cache.balances.get(&miner_addr).copied().unwrap_or(0) as f64 / 100_000_000.0;
                            let founder_balance = cache.balances.get(&genesis_addr).copied().unwrap_or(0) as f64 / 100_000_000.0;
                            let total = utxo_set.total_supply() as f64 / 100_000_000.0;
                            let s = format!("{{\"miner\":\"{}\",\"miner_aev\":{:.8},\"founder_aev\":{:.8},\"total_aev\":{:.8}}}",
                                &miner_addr[..16], miner_balance, founder_balance, total);
                            req.respond(cors_response(&s, &cors_origin)).ok();
                        }
                        u if u.starts_with("/utxos") => {
                            let val = validator.lock().unwrap();
                            let utxo_set = val.utxo_set();
                            let addr_param = url.split("address=").nth(1).unwrap_or("");
                            let mut result = String::from("[");
                            let mut count = 0usize;
                            for (_, u) in utxo_set.all() {
                                if count >= MAX_UTXOS_LIMIT { break; }
                                if addr_param.is_empty() || hex::encode(u.owner().to_bytes()).starts_with(addr_param) {
                                    result.push_str(&format!("{{\"amount\":{},\"height\":{},\"tx_hash\":\"{}\"}},",
                                        u.amount(), u.created_height(), hex::encode(u.tx_hash().as_bytes())));
                                    count += 1;
                                }
                            }
                            if result.ends_with(',') { result.pop(); }
                            result.push(']');
                            req.respond(cors_response(&result, &cors_origin)).ok();
                        }
                        u if u.starts_with("/history") => {
                            let addr_param = url.split("address=").nth(1).unwrap_or("");
                            let mut limit = url.split("limit=").nth(1).and_then(|s| s.split("&").next()).and_then(|s| s.parse::<usize>().ok()).unwrap_or(10);
                            if limit > MAX_HISTORY_LIMIT { limit = MAX_HISTORY_LIMIT; }
                            let st = storage.lock().unwrap();
                            let h = st.max_genesis_height().unwrap_or(None).unwrap_or(0);
                            let mut result = String::from("[");
                            let mut found = 0usize;
                            for bh in (0..=h).rev() {
                                if found >= limit { break; }
                                if let Ok(Some(block)) = st.load_genesis_block(bh) {
                                    for tx in &block.transactions {
                                        let mut involved = addr_param.is_empty();
                                        if !involved {
                                            for i in &tx.inputs { if hex::encode(i.public_key.to_bytes()).starts_with(&addr_param) { involved = true; break; } }
                                            if !involved { for o in &tx.outputs { if hex::encode(o.owner.to_bytes()).starts_with(&addr_param) { involved = true; break; } } }
                                        }
                                        if involved {
                                            result.push_str(&format!("{{\"height\":{},\"tx_hash\":\"{}\",\"fee\":{}}},", bh, tx.tx_hash.to_hex(), tx.fee));
                                            found += 1;
                                        }
                                    }
                                }
                            }
                            if result.ends_with(',') { result.pop(); }
                            result.push(']');
                            req.respond(cors_response(&result, &cors_origin)).ok();
                        }
                        u if u.starts_with("/tx") && method == &Method::Post => {
                            let mut body = String::new(); req.as_reader().read_to_string(&mut body).ok();
                            if let Ok(tx) = serde_json::from_str::<Transaction>(&body) {
                                mempool.lock().unwrap().insert(tx.clone()).ok();
                                if let Ok(data) = bincode::serialize(&AtpMessage::Transaction { tx_hash: [0u8; 32], ttl: 0, bytes: bincode::serialize(&tx).unwrap_or_default() }) {
                                    peers.broadcast(data);
                                }
                                req.respond(cors_response("{\"status\":\"ok\"}", &cors_origin)).ok();
                            } else { req.respond(cors_response("{\"status\":\"err\"}", &cors_origin)).ok(); }
                        }
                        _ => {
                            req.respond(Response::from_string("404").with_status_code(StatusCode(404))).ok();
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
        tracing::info!("HTTP server stopped");
    });
}
