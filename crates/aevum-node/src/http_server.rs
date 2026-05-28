use aevum::consensus::validator::Validator;
use aevum::core::transaction::Transaction;
use aevum::crypto::keys::PublicKey;
use crate::mempool::Mempool;
use crate::storage::Storage;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::AtpMessage;
use crate::config::NodeConfig;
use axum::{
    extract::{Query, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MAX_HISTORY_LIMIT: usize = 100;
const MAX_HISTORY_SCAN_BLOCKS: u64 = 10_000;
const MAX_UTXOS_LIMIT: usize = 500;
const TX_RATE_LIMIT_PER_IP: u64 = 10;
const TX_RATE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct BalanceCache {
    pub balances: BTreeMap<String, u64>,
    pub needs_rebuild: bool,
}

impl BalanceCache {
    pub fn new() -> Self { Self { balances: BTreeMap::new(), needs_rebuild: true } }
    pub fn rebuild(&mut self, utxo_set: &aevum::core::state::UtxoSet) {
        self.balances.clear();
        for (_, utxo) in utxo_set.all() {
            let addr = hex::encode(utxo.owner().to_bytes());
            *self.balances.entry(addr).or_insert(0) += utxo.amount();
        }
        self.needs_rebuild = false;
    }
    pub fn add_reward(&mut self, miner_hex: &str, amount_satoshi: u64) {
        *self.balances.entry(miner_hex.to_string()).or_insert(0) += amount_satoshi;
    }
    pub fn get(&self, addr: &str) -> u64 { self.balances.get(addr).copied().unwrap_or(0) }
}

pub type SharedBalanceCache = Arc<StdMutex<BalanceCache>>;
pub fn new_shared_balance_cache() -> SharedBalanceCache { Arc::new(StdMutex::new(BalanceCache::new())) }

#[derive(Clone)]
struct AppState {
    validator: Arc<StdMutex<Validator>>,
    mempool: Arc<StdMutex<Mempool>>,
    peers: Arc<PeersManager>,
    storage: Arc<StdMutex<Storage>>,
    network_height: Arc<StdMutex<u64>>,
    balance_cache: SharedBalanceCache,
    miner_pubkey: PublicKey,
    genesis_addr: String,
    start_time: Instant,
    tx_rate_limiter: Arc<StdMutex<HashMap<SocketAddr, (Instant, u64)>>>,
}

#[derive(Deserialize)]
struct UtxoQuery { address: Option<String> }

#[derive(Deserialize)]
struct HistoryQuery { address: Option<String>, limit: Option<usize> }

#[derive(Serialize)]
struct HealthResponse { status: String, height: u64, peers: usize, synced: bool, uptime_sec: u64 }

#[derive(Serialize)]
struct StatusResponse { height: u64, peers: usize, mempool: usize, utxos: usize, poh_tick: u64, supply: u64, uptime_sec: u64, network_height: u64, synced: bool }

#[derive(Serialize)]
struct BalanceResponse { miner: String, miner_aev: f64, founder_aev: f64, total_aev: f64 }

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let val = state.validator.lock().unwrap();
    let nh = *state.network_height.lock().unwrap();
    Json(HealthResponse {
        status: "ok".into(), height: val.last_block_height(),
        peers: state.peers.peer_count(), synced: val.last_block_height() >= nh,
        uptime_sec: state.start_time.elapsed().as_secs(),
    })
}

async fn status_handler(State(state): State<AppState>) -> Json<StatusResponse> {
    let val = state.validator.lock().unwrap();
    let nh = *state.network_height.lock().unwrap();
    Json(StatusResponse {
        height: val.last_block_height(), peers: state.peers.peer_count(),
        mempool: state.mempool.lock().unwrap().len(), utxos: val.utxo_set().len(),
        poh_tick: val.poh().current_tick_number(), supply: val.utxo_set().total_supply(),
        uptime_sec: state.start_time.elapsed().as_secs(), network_height: nh,
        synced: val.last_block_height() >= nh,
    })
}

async fn balance_handler(State(state): State<AppState>) -> Json<BalanceResponse> {
    let miner_addr = hex::encode(state.miner_pubkey.to_bytes());
    let mut cache = state.balance_cache.lock().unwrap();
    if cache.needs_rebuild {
        let val = state.validator.lock().unwrap();
        cache.rebuild(&val.utxo_set());
    }
    let miner_balance = cache.get(&miner_addr) as f64 / 100_000_000.0;
    let founder_balance = cache.get(&state.genesis_addr) as f64 / 100_000_000.0;
    let total_supply = state.validator.lock().unwrap().utxo_set().total_supply() as f64 / 100_000_000.0;
    Json(BalanceResponse {
        miner: miner_addr[..16].into(), miner_aev: miner_balance,
        founder_aev: founder_balance, total_aev: total_supply,
    })
}

async fn utxos_handler(State(state): State<AppState>, Query(q): Query<UtxoQuery>) -> String {
    let val = state.validator.lock().unwrap();
    let utxo_set = val.utxo_set();
    let mut result = String::from("[");
    let mut count = 0usize;
    for (_, u) in utxo_set.all() {
        if count >= MAX_UTXOS_LIMIT { break; }
        if q.address.as_ref().map_or(true, |a| hex::encode(u.owner().to_bytes()).starts_with(a)) {
            if count > 0 { result.push(','); }
            result.push_str(&format!("{{\"amount\":{},\"height\":{},\"tx_hash\":\"{}\"}}",
                u.amount(), u.created_height(), hex::encode(u.tx_hash().as_bytes())));
            count += 1;
        }
    }
    result.push(']');
    result
}

async fn history_handler(State(state): State<AppState>, Query(q): Query<HistoryQuery>) -> String {
    let limit = q.limit.unwrap_or(10).min(MAX_HISTORY_LIMIT);
    let mut st = state.storage.lock().unwrap();
    let h = st.max_genesis_height().unwrap_or(None).unwrap_or(0);
    let scan_start = h.saturating_sub(MAX_HISTORY_SCAN_BLOCKS);
    let mut result = String::from("[");
    let mut found = 0usize;
    for bh in (scan_start..=h).rev() {
        if found >= limit { break; }
        if bh % 1000 == 0 && bh != h { drop(st); std::thread::sleep(Duration::from_millis(1)); st = state.storage.lock().unwrap(); }
        if let Ok(Some(block)) = st.load_genesis_block(bh) {
            for tx in &block.transactions {
                if found >= limit { break; }
                let involved = q.address.as_ref().map_or(true, |a| {
                    tx.inputs.iter().any(|i| hex::encode(i.public_key.to_bytes()).starts_with(a))
                    || tx.outputs.iter().any(|o| hex::encode(o.owner.to_bytes()).starts_with(a))
                });
                if involved {
                    if found > 0 { result.push(','); }
                    result.push_str(&format!("{{\"height\":{},\"tx_hash\":\"{}\",\"fee\":{}}}",
                        bh, tx.tx_hash.to_hex(), tx.fee));
                    found += 1;
                }
            }
        }
    }
    result.push(']');
    result
}

async fn tx_handler(State(state): State<AppState>, headers: axum::http::HeaderMap, body: String) -> impl IntoResponse {
    let peer_addr = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<SocketAddr>().ok())
        .unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());

    let mut limiter = state.tx_rate_limiter.lock().unwrap();
    let entry = limiter.entry(peer_addr).or_insert((Instant::now(), 0));
    let now = Instant::now();
    if now.duration_since(entry.0) > TX_RATE_WINDOW { *entry = (now, 1); }
    else if entry.1 >= TX_RATE_LIMIT_PER_IP { return (StatusCode::TOO_MANY_REQUESTS, "Too many transactions").into_response(); }
    else { entry.1 += 1; }
    drop(limiter);

    match serde_json::from_str::<Transaction>(&body) {
        Ok(tx) => {
            if tx.inputs.is_empty() && tx.outputs.len() == 1 { return (StatusCode::BAD_REQUEST, "Coinbase not accepted").into_response(); }
            else if tx.inputs.is_empty() { return (StatusCode::BAD_REQUEST, "No inputs").into_response(); }
            else if tx.outputs.is_empty() { return (StatusCode::BAD_REQUEST, "No outputs").into_response(); }
            state.mempool.lock().unwrap().insert(tx.clone()).ok();
            if let Ok(data) = bincode::serialize(&AtpMessage::Transaction { tx_hash: [0u8; 32], ttl: 0, bytes: bincode::serialize(&tx).unwrap_or_default() }) {
                state.peers.broadcast(data);
            }
            (StatusCode::OK, "{\"status\":\"ok\"}").into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, "Invalid JSON").into_response(),
    }
}

pub fn start(
    config: NodeConfig,
    validator: Arc<StdMutex<Validator>>,
    mempool: Arc<StdMutex<Mempool>>,
    peers: Arc<PeersManager>,
    storage: Arc<StdMutex<Storage>>,
    network_height: Arc<StdMutex<u64>>,
    balance_cache: SharedBalanceCache,
    miner_pubkey: PublicKey,
    shutdown: Arc<AtomicBool>,
) {
    let state = AppState {
        validator, mempool, peers, storage, network_height, balance_cache, miner_pubkey,
        genesis_addr: config.genesis_address.clone(),
        start_time: Instant::now(),
        tx_rate_limiter: Arc::new(StdMutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/status", get(status_handler))
        .route("/balance", get(balance_handler))
        .route("/utxos", get(utxos_handler))
        .route("/history", get(history_handler))
        .route("/tx", post(tx_handler))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse().unwrap();
    let listener = std::net::TcpListener::bind(addr).unwrap();
    listener.set_nonblocking(true).ok();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, app).with_graceful_shutdown(async move {
                while !shutdown.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_secs(1)).await; }
            }).await.unwrap();
        });
    });
}
