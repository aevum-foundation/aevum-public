use aevum::consensus::validator::Validator;
use crate::storage::Storage;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncPhase};
use crate::p2p::chain_orchestrator::ChainOrchestrator;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ORCHESTRATOR_INTERVAL: u64 = 30;
const MAX_HEADERS_PER_REQUEST: u64 = 2000;
const SNAPSHOT_THRESHOLD: u64 = 5000;
const SOLO_REQUEST_COOLDOWN: Duration = Duration::from_secs(60);
const PEER_CACHE_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);
const PEER_CACHE_MAX_AGE: Duration = Duration::from_secs(3600);

static ORCHESTRATOR_SYNC_REQUESTS: AtomicU64 = AtomicU64::new(0);
static ORCHESTRATOR_SOLO_REQUESTS: AtomicU64 = AtomicU64::new(0);

pub fn orchestrator_metrics() -> (u64, u64) {
    (ORCHESTRATOR_SYNC_REQUESTS.load(Ordering::Relaxed),
     ORCHESTRATOR_SOLO_REQUESTS.load(Ordering::Relaxed))
}

pub fn start(
    validator: Arc<StdMutex<Validator>>,
    _storage: Arc<StdMutex<Storage>>,
    network_height: Arc<StdMutex<u64>>,
    peers: Arc<PeersManager>,
    _orchestrator: Arc<StdMutex<ChainOrchestrator>>,
    sync_phase: Arc<parking_lot::Mutex<SyncPhase>>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let mut peer_solo_requests: HashMap<[u8; 20], Instant> = HashMap::new();
        let mut last_cleanup = Instant::now();

        while !shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(ORCHESTRATOR_INTERVAL));

            // Не мешаем активной синхронизации
            {
                let phase = sync_phase.lock();
                if *phase != SyncPhase::Idle && *phase != SyncPhase::Synced {
                    tracing::debug!("[ORCH] Sync in progress ({:?}), skipping", *phase);
                    continue;
                }
            }

            let our_h = validator.lock().unwrap().last_block_height();
            let nh = *network_height.lock().unwrap();
            let diff = nh.saturating_sub(our_h);
            tracing::info!("[ORCH] tick: our={}, network={}, diff={}", our_h, nh, diff);

            // Синхронизация если отстаём
            if diff > 50 {
                ORCHESTRATOR_SYNC_REQUESTS.fetch_add(1, Ordering::Relaxed);
                if our_h == 0 || diff > SNAPSHOT_THRESHOLD {
                    tracing::info!("[ORCH] Large diff ({}): requesting snapshot", diff);
                    let req = AtpMessage::SnapshotRequest;
                    if let Ok(data) = bincode::serialize(&req) { peers.broadcast(data); }
                } else if diff > MAX_HEADERS_PER_REQUEST {
                    let chunk_end = our_h + MAX_HEADERS_PER_REQUEST;
                    tracing::info!("[ORCH] Chunked sync: {}-{} (diff {})", our_h + 1, chunk_end, diff);
                    let req = AtpMessage::HeaderRequest { from: our_h + 1, to: chunk_end };
                    if let Ok(data) = bincode::serialize(&req) { peers.broadcast(data); }
                } else {
                    tracing::info!("[ORCH] Syncing: {}-{}", our_h + 1, nh);
                    let req = AtpMessage::HeaderRequest { from: our_h + 1, to: nh };
                    if let Ok(data) = bincode::serialize(&req) { peers.broadcast(data); }
                }
            } else if our_h > nh + 10 {
                tracing::info!("[ORCH] We are ahead: us={}, network={}", our_h, nh);
            }

            // Соло-блоки у отстающих пиров (с cooldown)
            if our_h > 0 {
                let now = Instant::now();
                for peer_entry in &peers.peers {
                    let peer_id = *peer_entry.key();
                    let peer_h = peer_entry.value().peer_height;
                    if peer_h > 0 && peer_h < our_h {
                        if let Some(last) = peer_solo_requests.get(&peer_id) {
                            if now.duration_since(*last) < SOLO_REQUEST_COOLDOWN { continue; }
                        }
                        peer_solo_requests.insert(peer_id, now);
                        ORCHESTRATOR_SOLO_REQUESTS.fetch_add(1, Ordering::Relaxed);
                        tracing::info!("[ORCH] Requesting solo blocks from peer {}", hex::encode(&peer_id[..4]));
                        let req = AtpMessage::SoloChainRequest;
                        if let Ok(data) = bincode::serialize(&req) { peers.send_to(&peer_id, data); }
                    }
                }
            }

            // Очистка устаревших записей кеша пиров
            if last_cleanup.elapsed() >= PEER_CACHE_CLEANUP_INTERVAL {
                let before = peer_solo_requests.len();
                peer_solo_requests.retain(|_, last| last.elapsed() < PEER_CACHE_MAX_AGE);
                let removed = before - peer_solo_requests.len();
                if removed > 0 {
                    tracing::debug!("[ORCH] Cleaned {} stale peer entries", removed);
                }
                last_cleanup = Instant::now();
            }
        }
    });
}
