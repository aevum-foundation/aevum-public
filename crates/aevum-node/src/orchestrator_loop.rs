use aevum::consensus::validator::Validator;
use crate::storage::Storage;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::AtpMessage;
use crate::p2p::chain_orchestrator::ChainOrchestrator;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const ORCHESTRATOR_INTERVAL: u64 = 30;

pub fn start(
    validator: Arc<StdMutex<Validator>>,
    _storage: Arc<StdMutex<Storage>>,
    network_height: Arc<StdMutex<u64>>,
    peers: Arc<PeersManager>,
    orchestrator: Arc<StdMutex<ChainOrchestrator>>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        while !shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(ORCHESTRATOR_INTERVAL));
            let our_h = validator.lock().unwrap().last_block_height();
            let nh = *network_height.lock().unwrap();
            tracing::info!("[ORCH] tick: our={}, network={}", our_h, nh);

            if nh > our_h + 50 {
                tracing::info!("[ORCH] Network ahead: us={}, network={}, diff={}. Requesting sync...", our_h, nh, nh - our_h);
                let req = AtpMessage::HeaderRequest { from: our_h + 1, to: nh };
                if let Ok(data) = bincode::serialize(&req) { peers.broadcast(data); }
            } else if our_h > nh + 10 {
                tracing::info!("[ORCH] We are ahead: us={}, network={}", our_h, nh);
            }

            if our_h > 0 {
                for peer_entry in &peers.peers {
                    let peer_id = *peer_entry.key();
                    let peer_h = peer_entry.value().peer_height;
                    if peer_h > 0 && peer_h < our_h {
                        let req = AtpMessage::SoloChainRequest;
                        if let Ok(data) = bincode::serialize(&req) { peers.send_to(&peer_id, data); }
                    }
                }
            }
        }
    });
}
