use aevum::consensus::validator::Validator;
use crate::storage::Storage;
use crate::p2p::peers::PeersManager;
use crate::p2p::chain_orchestrator::ChainOrchestrator;
use crate::p2p::sync::SyncPhase;
use crate::http_server::SharedMetrics;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const ORCHESTRATOR_INTERVAL: u64 = 30;

pub fn start(
    validator: Arc<StdMutex<Validator>>,
    storage: Arc<StdMutex<Storage>>,
    network_height: Arc<StdMutex<u64>>,
    peers: Arc<PeersManager>,
    orchestrator: Arc<StdMutex<ChainOrchestrator>>,
    sync_phase: Arc<parking_lot::Mutex<SyncPhase>>,
    shutdown: Arc<AtomicBool>,
    metrics: SharedMetrics,
) {
    std::thread::spawn(move || {
        while !shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(ORCHESTRATOR_INTERVAL));

            // Не мешаем активной синхронизации
            {
                let phase = sync_phase.lock();
                if phase.is_active() {
                    tracing::debug!("[ORCH] Skipping: sync is active ({:?})", *phase);
                    continue;
                }
            }

            let our_h = validator.lock().unwrap().last_block_height();
            let nh = *network_height.lock().unwrap();
            let peer_count = peers.peer_count();

            tracing::info!("[ORCH] tick: our={}, network={}, diff={}, peers={}", our_h, nh, nh.saturating_sub(our_h), peer_count);

            // Вызываем process_chain для обработки новых блоков
            if let Ok(mut orch) = orchestrator.lock() {
                let mut val = validator.lock().unwrap();
                let mut st = storage.lock().unwrap();
                match orch.process_chain(&mut val, &mut st) {
                    Ok(processed) => {
                        if processed > 0 {
                            tracing::info!("[ORCH] Processed {} blocks", processed);
                        }
                    }
                    Err(e) => tracing::warn!("[ORCH] process_chain error: {}", e),
                }
                drop(val); drop(st);
            }

            // Обновляем метрики
            {
                let val = validator.lock().unwrap();
                let synced = val.last_block_height() >= nh;
                metrics.update(
                    val.last_block_height(), val.utxo_set().total_supply(), nh,
                    peer_count, val.utxo_set().len(), 0, val.poh().current_tick_number(),
                    synced,
                );
            }
        }
    });
}
