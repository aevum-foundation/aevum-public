use aevum::crypto::keys::PrivateKey;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::SyncContext;
use crate::p2p::noise::TofuStore;
use crate::p2p::connection::AtpConnection;
use crate::p2p::pex::PeerExchange;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const MAX_GLOBAL_CONNECTIONS: usize = 1000;
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub fn start(
    listen_addr: String,
    peers: Arc<PeersManager>,
    sync_ctx: Arc<SyncContext>,
    our_key: PrivateKey,
    tofu: Arc<tokio::sync::Mutex<TofuStore>>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4).thread_name("aevum-atp").enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = match TcpListener::bind(&listen_addr).await {
                Ok(l) => l, Err(e) => { tracing::error!("[ATP] Bind: {}", e); return; }
            };
            let connection_handles: Arc<StdMutex<Vec<JoinHandle<()>>>> = Arc::new(StdMutex::new(Vec::new()));
            let last_gossip: Arc<StdMutex<Instant>> = Arc::new(StdMutex::new(Instant::now()));
            tracing::info!("[ATP] Listening on {} (accept only)", listen_addr);
            while !shutdown.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
                    Ok(Ok((stream, addr))) => {
                        if ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= MAX_GLOBAL_CONNECTIONS { continue; }
                        if !peers.can_accept(&addr) { continue; }
                        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                        let pc = peers.clone(); let cc = sync_ctx.clone(); let kc = our_key.clone(); let tc = tofu.clone();
                        let handles = connection_handles.clone();
                        let lg = last_gossip.clone();
                        let handle = tokio::spawn(async move {
                            match crate::p2p::peers::accept_connection(stream, kc, &tc).await {
                                Ok((cipher, peer_id, remote_addr, reader, writer)) => {
                                    tracing::info!("[ATP] ✅ ACCEPTED from {}", remote_addr);
                                    pc.add_known_address(remote_addr);
                                    let do_gossip = {
                                        let mut last = lg.lock().unwrap();
                                        if last.elapsed() > Duration::from_secs(10) { *last = Instant::now(); true } else { false }
                                    };
                                    if do_gossip {
                                        let gossip_msg = PeerExchange::create_peer_list(&pc, 20);
                                        if let Ok(data) = bincode::serialize(&gossip_msg) { pc.broadcast(data); }
                                    }
                                    AtpConnection::new(cipher, peer_id, remote_addr, pc, cc, true).run(reader, writer).await;
                                }
                                Err(e) => tracing::warn!("[ATP] Accept failed: {}", e),
                            }
                            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                        });
                        handles.lock().unwrap().push(handle);
                    }
                    Ok(Err(e)) => tracing::error!("[ATP] Accept error: {}", e),
                    Err(_) => {}
                }
            }
            let h: Vec<JoinHandle<()>> = connection_handles.lock().unwrap().drain(..).collect();
            for handle in h { let _ = tokio::time::timeout(Duration::from_secs(5), handle).await; }
        });
    });
}
