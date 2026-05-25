use crate::p2p::sync::{AtpMessage, SyncContext, SyncPhase};
use crate::p2p::peers::PeersManager;
use crate::p2p::snapshot_cipher::SnapshotCipher;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::time::Duration;
use std::sync::Arc;

pub struct SyncDispatcher {
    ctx: Arc<SyncContext>,
    peers: Arc<PeersManager>,
    peer_id: [u8; 20],
    peer_height: u64,
}

impl SyncDispatcher {
    pub fn new(ctx: Arc<SyncContext>, peers: Arc<PeersManager>, peer_id: [u8; 20]) -> Self {
        Self { ctx, peers, peer_id, peer_height: 0 }
    }

    pub async fn start_sync(&mut self) -> Result<(), String> {
        let our_h = self.ctx.validator.lock().unwrap().last_block_height();
        tracing::info!("[DISPATCH] start_sync: our={}, peer={}", our_h, self.peer_height);

        if our_h == 0 && self.peer_height > 0 {
            let mut phase = self.ctx.sync_phase.lock();
            *phase = SyncPhase::AwaitingSnapshot {
                peer_id: self.peer_id,
                request_time: std::time::Instant::now(),
            };
            drop(phase);

            // Отправляем SnapshotRequest через общий канал
            let req = AtpMessage::SnapshotRequest;
            let data = bincode::serialize(&req).map_err(|e| format!("ser: {:?}", e))?;
            self.peers.send_to(&self.peer_id, data);
            tracing::info!("[DISPATCH] SnapshotRequest sent via channel");

            // Ждём через sync_phase
            for _ in 0..30 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let phase = self.ctx.sync_phase.lock().clone();
                match phase {
                    SyncPhase::AwaitingHeaders { .. } | SyncPhase::Synced => break,
                    SyncPhase::Idle => return Err("Sync reset".into()),
                    _ => {}
                }
            }
        }

        let our_h = self.ctx.validator.lock().unwrap().last_block_height();
        if self.peer_height > our_h {
            let from = our_h + 1;
            let mut phase = self.ctx.sync_phase.lock();
            *phase = SyncPhase::AwaitingHeaders {
                peer_id: self.peer_id, from, to: self.peer_height,
                request_time: std::time::Instant::now(), retries: 0,
            };
            drop(phase);
            let req = AtpMessage::HeaderRequest { from, to: self.peer_height };
            let data = bincode::serialize(&req).map_err(|e| format!("ser: {:?}", e))?;
            self.peers.send_to(&self.peer_id, data);
            tracing::info!("[DISPATCH] HeaderRequest sent {}-{}", from, self.peer_height);
        }

        for _ in 0..60 {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let phase = self.ctx.sync_phase.lock().clone();
            if phase == SyncPhase::Synced || phase == SyncPhase::Idle { break; }
        }

        let final_h = self.ctx.validator.lock().unwrap().last_block_height();
        let nh = *self.ctx.network_height.lock().unwrap();
        if final_h >= nh {
            let mut phase = self.ctx.sync_phase.lock();
            *phase = SyncPhase::Synced;
            tracing::info!("[DISPATCH] Synced at {}", final_h);
        }

        crate::p2p::sync::flush_block_buffer(&self.ctx);
        Ok(())
    }

    pub fn set_peer_height(&mut self, h: u64) { self.peer_height = h; }
}
