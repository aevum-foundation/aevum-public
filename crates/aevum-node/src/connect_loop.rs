use aevum::crypto::keys::PrivateKey;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::SyncContext;
use crate::p2p::noise::TofuStore;
use crate::p2p::connection::AtpConnection;
use crate::p2p::dht_integration::DhtIntegration;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc as tokio_mpsc;
use crate::mining_loop::ConnectCommand;

pub fn start(
    mut connect_rx: tokio_mpsc::UnboundedReceiver<ConnectCommand>,
    our_key: PrivateKey,
    tofu: Arc<tokio::sync::Mutex<TofuStore>>,
    peers: Arc<PeersManager>,
    sync_ctx: Arc<SyncContext>,
    _dht_integration: Arc<StdMutex<DhtIntegration>>,
    shutdown: Arc<AtomicBool>,
) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async move {
            while let Some(cmd) = connect_rx.recv().await {
                if shutdown.load(Ordering::SeqCst) { break; }
                match crate::p2p::peers::dial_peer(cmd.addr, cmd.our_key, &cmd.tofu).await {
                    Ok((cipher, peer_id, reader, writer)) => {
                        tracing::info!("[DHT] Connected to peer {}", cmd.addr);
                        let conn = AtpConnection::new(cipher, peer_id, cmd.addr, cmd.peers.clone(), cmd.ctx.clone(), false);
                        tokio::spawn(async move { conn.run(reader, writer).await; });
                    }
                    Err(e) => tracing::warn!("[DHT] Connect failed {}: {}", cmd.addr, e),
                }
            }
        });
    });
}
