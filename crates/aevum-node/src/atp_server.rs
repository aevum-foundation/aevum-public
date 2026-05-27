use aevum::crypto::keys::PrivateKey;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::SyncContext;
use crate::p2p::noise::TofuStore;
use crate::p2p::connection::AtpConnection;
use crate::p2p::pex::PeerExchange;
use std::collections::HashSet;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const MAX_GLOBAL_CONNECTIONS: usize = 1000;
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub fn start(
    listen_addr: String,
    peers: Arc<PeersManager>,
    sync_ctx: Arc<SyncContext>,
    our_key: PrivateKey,
    tofu: Arc<StdMutex<TofuStore>>,
    bootstrap_peers: Vec<String>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("aevum-atp")
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            let listener = match TcpListener::bind(&listen_addr).await {
                Ok(l) => l,
                Err(e) => { tracing::error!("[ATP] Bind: {}", e); return; }
            };

            // Дедупликация через HashSet
            let mut addr_set: HashSet<String> = bootstrap_peers.iter().cloned().collect();
            {
                let dht = sync_ctx.dht.lock().unwrap();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                for node in dht.random_nodes(50, now, 300) {
                    addr_set.insert(node.addr.to_string());
                }
            }
            for addr in peers.known_addresses.iter() {
                addr_set.insert(addr.key().to_string());
            }
            let all_addrs: Vec<String> = addr_set.into_iter().collect();
            tracing::info!("[ATP] Bootstrap candidates: {} addresses", all_addrs.len());

            // Хранилище JoinHandle для graceful shutdown
            let connection_handles: Arc<StdMutex<Vec<JoinHandle<()>>>> = Arc::new(StdMutex::new(Vec::new()));
            let ch = connection_handles.clone();
            let ds = shutdown.clone();

            if !all_addrs.is_empty() {
                let dp = peers.clone();
                let dc = sync_ctx.clone();
                let dk = our_key.clone();
                let dt = tofu.clone();

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    let mut connected = false;
                    for addr_str in &all_addrs {
                        if ds.load(Ordering::SeqCst) { break; }
                        if let Ok(addr) = addr_str.trim().parse() {
                            for retry in 0..3 {
                                if retry > 0 {
                                    tokio::time::sleep(Duration::from_secs(5 * (retry + 1) as u64)).await;
                                }
                                match crate::p2p::peers::dial_peer(addr, dk.clone(), &dt).await {
                                    Ok((cipher, peer_id, reader, writer)) => {
                                        tracing::info!("[ATP] ✅Bootstrap CONNECTED to {}", addr);
                                        let conn = AtpConnection::new(cipher, peer_id, addr, dp.clone(), dc.clone(), false);
                                        let handle = tokio::spawn(async move { conn.run(reader, writer).await; });
                                        ch.lock().unwrap().push(handle);
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        PeerExchange::request_peers(&dp, &peer_id);
                                        connected = true;
                                        break;
                                    }
                                    Err(e) => tracing::warn!("[ATP] Bootstrap dial failed {}: {}", addr, e),
                                }
                            }
                        }
                    }
                    if !connected {
                        tracing::warn!("[ATP] Bootstrap: no peers connected from {} candidates", all_addrs.len());
                    }
                });
            }

            // Главный цикл приёма соединений
            while !shutdown.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
                    Ok(Ok((stream, addr))) => {
                        // Глобальный лимит
                        if ACTIVE_CONNECTIONS.load(Ordering::Relaxed) >= MAX_GLOBAL_CONNECTIONS {
                            tracing::warn!("[ATP] Global connection limit reached — rejecting {}", addr);
                            continue;
                        }
                        if !peers.can_accept(&addr) { continue; }

                        ACTIVE_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
                        let pc = peers.clone();
                        let cc = sync_ctx.clone();
                        let kc = our_key.clone();
                        let tc = tofu.clone();
                        let _active = &ACTIVE_CONNECTIONS;
                        let handles = connection_handles.clone();

                        let handle = tokio::spawn(async move {
                            match crate::p2p::peers::accept_connection(stream, kc, &tc).await {
                                Ok((cipher, peer_id, remote_addr, reader, writer)) => {
                                    tracing::info!("[ATP] ✅ ACCEPTED from {}", remote_addr);
                                    AtpConnection::new(cipher, peer_id, remote_addr, pc, cc, true)
                                        .run(reader, writer).await;
                                }
                                Err(e) => tracing::warn!("[ATP] Accept failed: {}", e),
                            }
                            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
                        });
                        handles.lock().unwrap().push(handle);
                    }
                    Ok(Err(e)) => tracing::error!("[ATP] Accept error: {}", e),
                    Err(_) => {} // timeout
                }
            }

            // Graceful shutdown
            tracing::info!("[ATP] Shutting down, joining {} connections...", connection_handles.lock().unwrap().len());
            let handles: Vec<JoinHandle<()>> = connection_handles.lock().unwrap().drain(..).collect();
            for handle in handles {
                let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
            }
            tracing::info!("[ATP] Shutdown complete");
        });
    });
}
