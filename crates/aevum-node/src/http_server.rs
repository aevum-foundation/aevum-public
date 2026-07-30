//! HTTP Server v5.3 — Production L1 API Gateway with getters (10/10)
//!
//! - /health: lifecycle state + synced flag + atomic metrics
//! - Clone-under-lock, serialize outside lock (no contention)
//! - submit_tx: hash integrity + structural validation + backpressure
//! - Real timestamps for TTL/priority ordering
//! - v5.3: serialize_block uses Block getters

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use actix_web::{web, App, HttpServer, HttpResponse};
use parking_lot::RwLock;

use aevum::core::block::Block;
use aevum::core::transaction::Transaction;
use aevum::crypto::hash::Hash;

use crate::config::NodeConfig;
use crate::mempool::Mempool;
use crate::chain_orchestrator::ChainOrchestrator;
use crate::node_lifecycle::NodeLifecycle;

pub struct NodeMetrics {
    pub height: AtomicU64,
    pub supply: AtomicU64,
    pub network_height: AtomicU64,
    pub peers: AtomicU64,
    pub mempool_size: AtomicU64,
    pub uptime: Instant,
    pub synced: AtomicBool,
}

impl NodeMetrics {
    pub fn new() -> Self {
        Self {
            height: AtomicU64::new(0), supply: AtomicU64::new(0),
            network_height: AtomicU64::new(0), peers: AtomicU64::new(0),
            mempool_size: AtomicU64::new(0), uptime: Instant::now(),
            synced: AtomicBool::new(false),
        }
    }

    pub fn update_chain(&self, height: u64, supply: u64, network_height: u64) {
        self.height.store(height, Ordering::Relaxed);
        self.supply.store(supply, Ordering::Relaxed);
        self.network_height.store(network_height, Ordering::Relaxed);
    }
}

pub type SharedMetrics = Arc<NodeMetrics>;

struct AppState {
    metrics: SharedMetrics,
    chain: Arc<RwLock<ChainOrchestrator>>,
    mempool: Arc<Mempool>,
    config: NodeConfig,
    shutdown: Arc<AtomicBool>,
    lifecycle: Arc<NodeLifecycle>,
}

fn decode_hash(hex_str: &str) -> Result<Hash, ()> {
    let bytes = hex::decode(hex_str).map_err(|_| ())?;
    if bytes.len() != 32 { return Err(()); }
    let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes);
    Ok(Hash(arr))
}

fn serialize_block(block: &Block) -> serde_json::Value {
    serde_json::json!({
        "height": block.height(),
        "hash": hex::encode(block.block_hash().0),
        "prev_hash": hex::encode(block.prev_hash().0),
        "tx_count": block.transactions().len(),
        "total_supply": block.total_supply(),
        "poh_tick_start": block.poh_tick_start(),
        "poh_tick_end": block.poh_tick_end(),
        "is_presence_block": block.is_presence_block(),
    })
}

async fn health(data: web::Data<AppState>) -> HttpResponse {
    let m = &data.metrics;
    let state = data.lifecycle.get();
    HttpResponse::Ok().json(serde_json::json!({
        "state": state.as_str(),
        "ready_for_clients": state.is_ready_for_clients(),
        "can_mine": state.can_mine(),
        "synced": m.synced.load(Ordering::Relaxed),
        "height": m.height.load(Ordering::Relaxed),
        "supply": m.supply.load(Ordering::Relaxed),
        "network_height": m.network_height.load(Ordering::Relaxed),
        "peers": m.peers.load(Ordering::Relaxed),
        "mempool": m.mempool_size.load(Ordering::Relaxed),
        "uptime_secs": m.uptime.elapsed().as_secs(),
    }))
}

async fn get_tip(data: web::Data<AppState>) -> HttpResponse {
    let tip = data.chain.read().canonical_tip().cloned();
    match tip {
        Some(b) => HttpResponse::Ok().json(serialize_block(&b)),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "no_tip"})),
    }
}

async fn get_block_by_height(data: web::Data<AppState>, path: web::Path<u64>) -> HttpResponse {
    let block = data.chain.read().get_block(path.into_inner()).clone();
    match block {
        Some(b) => HttpResponse::Ok().json(serialize_block(&b)),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "not_found"})),
    }
}

async fn get_block_by_hash(data: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let hash = match decode_hash(&path.into_inner()) {
        Ok(h) => h, Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid_hash"})),
    };
    let block = data.chain.read().get_block_by_hash(&hash).clone();
    match block {
        Some(b) => HttpResponse::Ok().json(serialize_block(&b)),
        None => HttpResponse::NotFound().json(serde_json::json!({"error": "not_found"})),
    }
}

async fn submit_tx(data: web::Data<AppState>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let tx_hex = match body.get("tx").and_then(|v| v.as_str()) {
        Some(v) => v, None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "missing_tx"})),
    };
    let tx_bytes = match hex::decode(tx_hex) {
        Ok(b) => b, Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid_hex"})),
    };
    let tx: Transaction = match bincode::deserialize(&tx_bytes) {
        Ok(t) => t, Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "invalid_tx"})),
    };

    if tx.recompute_hash() != tx.tx_hash {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "hash_mismatch"}));
    }
    if !tx.is_coinbase() && !tx.is_heartbeat() && tx.inputs.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "no_inputs"}));
    }
    if data.mempool.len() > data.config.mempool_max_tx {
        return HttpResponse::TooManyRequests().json(serde_json::json!({"error": "mempool_full"}));
    }

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let tx_hash_hex = hex::encode(tx.tx_hash.0);
    let accepted = data.mempool.insert(tx, now);
    data.metrics.mempool_size.store(data.mempool.len() as u64, Ordering::Relaxed);

    if accepted {
        HttpResponse::Ok().json(serde_json::json!({"status": "accepted", "tx_hash": tx_hash_hex}))
    } else {
        HttpResponse::BadRequest().json(serde_json::json!({"status": "rejected", "tx_hash": tx_hash_hex}))
    }
}

async fn mempool_stats(data: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "count": data.mempool.len(), "total_bytes": data.mempool.total_bytes(),
    }))
}

pub async fn run_server(
    metrics: SharedMetrics,
    chain: Arc<RwLock<ChainOrchestrator>>,
    mempool: Arc<Mempool>,
    config: NodeConfig,
    shutdown: Arc<AtomicBool>,
    lifecycle: Arc<NodeLifecycle>,
) -> std::io::Result<()> {
    let state = web::Data::new(AppState { metrics, chain, mempool, config: config.clone(), shutdown, lifecycle });
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .wrap(actix_web::middleware::Logger::default())
            .route("/health", web::get().to(health))
            .route("/tip", web::get().to(get_tip))
            .route("/block/{height}", web::get().to(get_block_by_height))
            .route("/block/hash/{hash}", web::get().to(get_block_by_hash))
            .route("/tx", web::post().to(submit_tx))
            .route("/mempool", web::get().to(mempool_stats))
    })
    .bind(config.http_socket_addr().to_string())?
    .run()
    .await
}
