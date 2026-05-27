use aevum::crypto::keys::PrivateKey;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::SyncContext;
use crate::p2p::noise::TofuStore;
use crate::p2p::connection::AtpConnection;
use crate::p2p::pex::PeerExchange;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;

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
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(4).thread_name("aevum-atp").enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = match TcpListener::bind(&listen_addr).await { Ok(l) => l, Err(e) => { tracing::error!("Bind: {}", e); return; } };

            if !bootstrap_peers.is_empty() {
                let dp = peers.clone(); let dc = sync_ctx.clone(); let dk = our_key.clone(); let dt = tofu.clone(); let ds = shutdown.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    for addr_str in &bootstrap_peers {
                        if ds.load(Ordering::SeqCst) { break; }
                        if let Ok(addr) = addr_str.trim().parse() {
                            for retry in 0..5 {
                                if retry > 0 { tokio::time::sleep(Duration::from_secs(5 * (retry + 1) as u64)).await; }
                                match crate::p2p::peers::dial_peer(addr, dk.clone(), &dt).await {
                                    Ok((cipher, peer_id, reader, writer)) => {
                                        tracing::info!("[ATP] ✅Bootstrap CONNECTED to {}", addr);
                                        let conn = AtpConnection::new(cipher, peer_id, addr, dp.clone(), dc.clone(), false);
                                        let conn_handle = tokio::spawn(async move { conn.run(reader, writer).await; });
                                        tokio::time::sleep(Duration::from_millis(100)).await;
                                        PeerExchange::request_peers(&dp, &peer_id);
                                        let _ = conn_handle.await; break;
                                    }
                                    Err(e) => tracing::warn!("[ATP] Bootstrap dial failed {}: {}", addr, e),
                                }
                            }
                        }
                    }
                });
            }

            while !shutdown.load(Ordering::SeqCst) {
                match tokio::time::timeout(Duration::from_secs(1), listener.accept()).await {
                    Ok(Ok((stream, addr))) => {
                        if !peers.can_accept(&addr) { continue; }
                        let pc = peers.clone(); let cc = sync_ctx.clone(); let kc = our_key.clone(); let tc = tofu.clone();
                        tokio::spawn(async move {
                            match crate::p2p::peers::accept_connection(stream, kc, &tc).await {
                                Ok((cipher, peer_id, remote_addr, reader, writer)) => {
                                    tracing::info!("[ATP] ✅ ACCEPTED from {}", remote_addr);
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
}
