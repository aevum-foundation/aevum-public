use aevum::consensus::validator::Validator;
use aevum::core::transaction::Transaction;
use aevum::crypto::keys::PublicKey;
use crate::mempool::Mempool;
use crate::storage::Storage;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::AtpMessage;
use crate::config::NodeConfig;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::time::{Duration, Instant};

const MAX_HISTORY_LIMIT: usize = 100;
const MAX_HISTORY_SCAN_BLOCKS: u64 = 10_000;
const MAX_UTXOS_LIMIT: usize = 500;
const TX_RATE_LIMIT_PER_IP: u64 = 10;
const TX_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_REQUEST_SIZE: usize = 256_000;
const MAX_THREADS: usize = 64;
const ACCEPT_BACKLOG: usize = 128;

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
    pub fn mark_dirty(&mut self) { self.needs_rebuild = true; }
    pub fn add_reward(&mut self, miner_hex: &str, amount_satoshi: u64) {
        *self.balances.entry(miner_hex.to_string()).or_insert(0) += amount_satoshi;
    }
    pub fn get(&self, addr: &str) -> u64 { self.balances.get(addr).copied().unwrap_or(0) }
}

pub type SharedBalanceCache = Arc<StdMutex<BalanceCache>>;
pub fn new_shared_balance_cache() -> SharedBalanceCache { Arc::new(StdMutex::new(BalanceCache::new())) }

pub struct NodeMetrics {
    pub height: AtomicU64,
    pub supply: AtomicU64,
    pub network_height: AtomicU64,
    pub peers: AtomicUsize,
    pub utxos: AtomicUsize,
    pub mempool: AtomicUsize,
    pub poh_tick: AtomicU64,
    pub synced: AtomicBool,
    pub uptime: Instant,
}

impl NodeMetrics {
    pub fn new() -> Self {
        Self {
            height: AtomicU64::new(0), supply: AtomicU64::new(0),
            network_height: AtomicU64::new(0), peers: AtomicUsize::new(0),
            utxos: AtomicUsize::new(0), mempool: AtomicUsize::new(0),
            poh_tick: AtomicU64::new(0), synced: AtomicBool::new(false),
            uptime: Instant::now(),
        }
    }
    pub fn update(&self, height: u64, supply: u64, network_height: u64, peers: usize, utxos: usize, mempool: usize, poh_tick: u64, synced: bool) {
        self.height.store(height, Ordering::Relaxed);
        self.supply.store(supply, Ordering::Relaxed);
        self.network_height.store(network_height, Ordering::Relaxed);
        self.peers.store(peers, Ordering::Relaxed);
        self.utxos.store(utxos, Ordering::Relaxed);
        self.mempool.store(mempool, Ordering::Relaxed);
        self.poh_tick.store(poh_tick, Ordering::Relaxed);
        self.synced.store(synced, Ordering::Relaxed);
    }
    pub fn update_chain(&self, height: u64, supply: u64, network_height: u64, utxos: usize, poh_tick: u64, synced: bool) {
        self.height.store(height, Ordering::Relaxed);
        self.supply.store(supply, Ordering::Relaxed);
        self.network_height.store(network_height, Ordering::Relaxed);
        self.utxos.store(utxos, Ordering::Relaxed);
        self.poh_tick.store(poh_tick, Ordering::Relaxed);
        self.synced.store(synced, Ordering::Relaxed);
    }
}

pub type SharedMetrics = Arc<NodeMetrics>;

struct AppState {
    metrics: SharedMetrics,
    validator: Arc<StdMutex<Validator>>,
    mempool: Arc<StdMutex<Mempool>>,
    peers: Arc<PeersManager>,
    storage: Arc<StdMutex<Storage>>,
    balance_cache: SharedBalanceCache,
    miner_pubkey: PublicKey,
    genesis_addr: String,
    tx_rate_limiter: Arc<StdMutex<HashMap<SocketAddr, (Instant, u64)>>>,
}

fn url_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) { result.push(byte as char); }
            else { result.push('%'); result.push_str(&hex); }
        } else if c == '+' { result.push(' '); }
        else { result.push(c); }
    }
    result
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in query.split('&') {
        if part.is_empty() { continue; }
        let mut kv = part.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) { map.insert(url_decode(k), url_decode(v)); }
    }
    map
}

fn ok_response(body: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).into_bytes()
}

fn err_response(code: u16, msg: &str) -> Vec<u8> {
    let body = format!("{{\"error\":\"{}\"}}", msg);
    let status = match code { 429 => "Too Many Requests", 400 => "Bad Request", 503 => "Service Unavailable", _ => "Not Found" };
    format!("HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", code, status, body.len(), body).into_bytes()
}

fn read_http_body(stream: &mut TcpStream, headers: &str, initial_body: &str) -> Result<String, ()> {
    let content_length = headers.lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if content_length == 0 { return Ok(String::new()); }
    let already_read = initial_body.len();
    if already_read >= content_length { return Ok(initial_body[..content_length].to_string()); }
    let mut body = initial_body.to_string();
    let mut remaining = vec![0u8; content_length - already_read];
    if stream.read_exact(&mut remaining).is_ok() { body.push_str(&String::from_utf8_lossy(&remaining)); }
    Ok(body)
}

fn handle(state: &AppState, method: &str, path: &str, query: &str, body: &str, peer_addr: SocketAddr) -> Vec<u8> {
    let params = parse_query(query);
    match (method, path) {
        (_, "/health") => {
            let m = &state.metrics;
            let s = serde_json::json!({"status":"ok","height":m.height.load(Ordering::Relaxed),"peers":m.peers.load(Ordering::Relaxed),"synced":m.synced.load(Ordering::Relaxed),"uptime_sec":m.uptime.elapsed().as_secs()});
            ok_response(&s.to_string())
        }
        (_, p) if p.starts_with("/status") => {
            let m = &state.metrics;
            let s = serde_json::json!({"height":m.height.load(Ordering::Relaxed),"peers":m.peers.load(Ordering::Relaxed),"mempool":m.mempool.load(Ordering::Relaxed),"utxos":m.utxos.load(Ordering::Relaxed),"poh_tick":m.poh_tick.load(Ordering::Relaxed),"supply":m.supply.load(Ordering::Relaxed),"uptime_sec":m.uptime.elapsed().as_secs(),"network_height":m.network_height.load(Ordering::Relaxed),"synced":m.synced.load(Ordering::Relaxed)});
            ok_response(&s.to_string())
        }
        (_, p) if p.starts_with("/balance") => {
            let mut cache = state.balance_cache.lock().unwrap();
            if cache.needs_rebuild {
                if let Ok(val) = state.validator.try_lock() {
                    cache.rebuild(&val.utxo_set());
                }
            }
            let mut balances: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
            let mut total: u64 = 0;
            for (addr, amount) in &cache.balances {
                let short = if addr.len() > 16 { &addr[..16] } else { addr.as_str() };
                balances.insert(short.to_string(), serde_json::json!(*amount as f64 / 100_000_000.0));
                total += amount;
            }
            let miner_addr = hex::encode(state.miner_pubkey.to_bytes());
            let s = serde_json::json!({
                "miner": &miner_addr[..miner_addr.len().min(16)],
                "miner_aev": cache.get(&miner_addr) as f64 / 100_000_000.0,
                "founder_aev": cache.get(&state.genesis_addr) as f64 / 100_000_000.0,
                "total_aev": total as f64 / 100_000_000.0,
                "all_balances": balances
            });
            ok_response(&s.to_string())
        }
        (_, p) if p.starts_with("/utxos") => {
            let addr_filter = params.get("address");
            let mut items = Vec::new(); let mut count = 0;
            if let Ok(val) = state.validator.try_lock() {
                for (_, u) in val.utxo_set().all() {
                    if count >= MAX_UTXOS_LIMIT { break; }
                    if addr_filter.map_or(true, |a| hex::encode(u.owner().to_bytes()).starts_with(a)) {
                        items.push(serde_json::json!({"amount":u.amount(),"height":u.created_height(),"tx_hash":hex::encode(u.tx_hash().as_bytes()),"nullifier":hex::encode(u.nullifier().as_bytes()),"output_index":u.output_index()}));
                        count += 1;
                    }
                }
            }
            ok_response(&serde_json::Value::Array(items).to_string())
        }
        (_, p) if p.starts_with("/history") => {
            let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(10).min(MAX_HISTORY_LIMIT);
            let addr_filter = params.get("address").cloned();
            let mut st = state.storage.lock().unwrap();
            let h = st.max_genesis_height().unwrap_or(None).unwrap_or(0);
            let scan_start = h.saturating_sub(MAX_HISTORY_SCAN_BLOCKS);
            let mut items = Vec::new(); let mut found = 0;
            for bh in (scan_start..=h).rev() {
                if found >= limit { break; }
                if bh % 1000 == 0 && bh != h { drop(st); std::thread::sleep(Duration::from_millis(1)); st = state.storage.lock().unwrap(); }
                if let Ok(Some(block)) = st.load_genesis_block(bh) {
                    for tx in &block.transactions {
                        if found >= limit { break; }
                        let involved = addr_filter.as_ref().map_or(true, |a|
                            tx.inputs.iter().any(|i| hex::encode(i.public_key.to_bytes()).starts_with(a))
                            || tx.outputs.iter().any(|o| hex::encode(o.owner.to_bytes()).starts_with(a)));
                        if involved { items.push(serde_json::json!({"height":bh,"tx_hash":tx.tx_hash.to_hex(),"fee":tx.fee})); found += 1; }
                    }
                }
            }
            ok_response(&serde_json::Value::Array(items).to_string())
        }
        ("POST", p) if p.starts_with("/tx") => {
            let mut limiter = state.tx_rate_limiter.lock().unwrap();
            let entry = limiter.entry(peer_addr).or_insert((Instant::now(), 0));
            let now = Instant::now();
            if now.duration_since(entry.0) > TX_RATE_WINDOW { *entry = (now, 1); }
            else if entry.1 >= TX_RATE_LIMIT_PER_IP { return err_response(429, "Rate limited"); }
            else { entry.1 += 1; }
            drop(limiter);
            match serde_json::from_str::<Transaction>(body) {
                Ok(tx) => {
                    if tx.inputs.is_empty() { return err_response(400, "No inputs"); }
                    if tx.outputs.is_empty() { return err_response(400, "No outputs"); }
                    state.mempool.lock().unwrap().insert(tx.clone()).ok();
                    if let Ok(data) = bincode::serialize(&AtpMessage::Transaction { tx_hash: [0u8; 32], ttl: 0, bytes: bincode::serialize(&tx).unwrap_or_default() }) { state.peers.broadcast(data); }
                    ok_response("{\"status\":\"ok\"}")
                }
                Err(_) => err_response(400, "Invalid JSON"),
            }
        }
        _ => err_response(404, "Not found"),
    }
}

fn handle_client(mut stream: TcpStream, state: Arc<AppState>) {
    let peer = stream.peer_addr().unwrap_or_else(|_| "127.0.0.1:0".parse().unwrap());
    let mut buf = [0u8; MAX_REQUEST_SIZE];
    let n = match stream.read(&mut buf) { Ok(n) if n > 0 => n, _ => return };
    let request_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = match request_str.lines().next() { Some(l) => l, None => return };
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 { return; }
    let method = parts[0];
    let full_path = parts[1];
    let (path, query) = if let Some(pos) = full_path.find('?') { (&full_path[..pos], &full_path[pos+1..]) } else { (full_path, "") };
    let header_end = request_str.find("\r\n\r\n").unwrap_or(request_str.len());
    let headers = &request_str[..header_end];
    let initial_body = if header_end + 4 < request_str.len() { &request_str[header_end+4..] } else { "" };
    let body = read_http_body(&mut stream, headers, initial_body).unwrap_or_default();
    let resp = handle(&state, method, path, query, &body, peer);
    let _ = stream.write_all(&resp);
}

pub fn start(
    config: NodeConfig,
    validator: Arc<StdMutex<Validator>>,
    mempool: Arc<StdMutex<Mempool>>,
    peers: Arc<PeersManager>,
    storage: Arc<StdMutex<Storage>>,
    _network_height: Arc<StdMutex<u64>>,
    balance_cache: SharedBalanceCache,
    miner_pubkey: PublicKey,
    shutdown: Arc<AtomicBool>,
    metrics: SharedMetrics,
) {
    let state = Arc::new(AppState {
        metrics: metrics.clone(),
        validator, mempool, peers, storage, balance_cache, miner_pubkey,
        genesis_addr: config.genesis_address.clone(),
        tx_rate_limiter: Arc::new(StdMutex::new(HashMap::new())),
    });

    let addr: SocketAddr = format!("0.0.0.0:{}", config.http_port).parse().unwrap();
    let listener = TcpListener::bind(addr).unwrap();
    // Неблокирующий режим — accept не зависает
    listener.set_nonblocking(true).ok();
    tracing::info!("HTTP server listening on {} (nonblocking, max {} threads)", addr, MAX_THREADS);

    let active_threads = Arc::new(AtomicUsize::new(0));
    // Очередь принятых соединений — не теряем клиентов
    let pending: Arc<StdMutex<VecDeque<TcpStream>>> = Arc::new(StdMutex::new(VecDeque::new()));
    let pending_clone = pending.clone();
    let state_clone = state.clone();
    let shutdown_clone = shutdown.clone();
    let active_clone = active_threads.clone();

    // Фоновый поток-acceptor — не блокирует главный цикл
    std::thread::spawn(move || {
        loop {
            if shutdown_clone.load(Ordering::SeqCst) { break; }
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut q = pending_clone.lock().unwrap();
                    if q.len() < ACCEPT_BACKLOG { q.push_back(stream); }
                    // Иначе отбрасываем — backlog полон
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });

    // Главный цикл — запускает обработчики из очереди
    loop {
        if shutdown.load(Ordering::SeqCst) { break; }
        
        let stream = {
            let mut q = pending.lock().unwrap();
            q.pop_front()
        };

        if let Some(stream) = stream {
            // Ждём свободный слот
            while active_threads.load(Ordering::Relaxed) >= MAX_THREADS {
                std::thread::sleep(Duration::from_millis(1));
            }
            active_threads.fetch_add(1, Ordering::Relaxed);
            let s = state_clone.clone();
            let a = active_clone.clone();
            std::thread::spawn(move || {
                handle_client(stream, s);
                a.fetch_sub(1, Ordering::Relaxed);
            });
        } else {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
