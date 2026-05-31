use std::collections::HashSet;
use std::time::{Duration, Instant};

pub type PeerId = [u8; 20];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    Synced,
    Syncing {
        from: u64,
        to: u64,
        peer: PeerId,
        started_at: Instant,
    },
    Failed {
        reason: String,
    },
}

pub struct ChainSync {
    state: SyncState,
    requested_heights: HashSet<u64>,
    batch_size: u64,
    request_timeout: Duration,
}

impl ChainSync {
    pub fn new(batch_size: u64) -> Self {
        ChainSync {
            state: SyncState::Synced,
            requested_heights: HashSet::new(),
            batch_size,
            request_timeout: Duration::from_secs(30),
        }
    }

    pub fn request_blocks(&mut self, from: u64, to: u64, peer: PeerId) {
        let to = to.min(from + self.batch_size - 1);
        self.state = SyncState::Syncing { from, to, peer, started_at: Instant::now() };
        for h in from..=to { self.requested_heights.insert(h); }
    }

    pub fn mark_received(&mut self, height: u64) { self.requested_heights.remove(&height); if self.requested_heights.is_empty() { self.state = SyncState::Synced; } }
    pub fn is_received(&self, height: u64) -> bool { !self.requested_heights.contains(&height) }
    pub fn finish_sync(&mut self) { self.state = SyncState::Synced; self.requested_heights.clear(); }
    pub fn check_timeout(&mut self) {
        if let SyncState::Syncing { started_at, .. } = self.state {
            if started_at.elapsed() > self.request_timeout {
                self.state = SyncState::Failed { reason: "Request timeout".to_string() };
                self.requested_heights.clear();
            }
        }
    }
    pub fn state(&self) -> &SyncState { &self.state }
    pub fn batch_size(&self) -> u64 { self.batch_size }
    pub fn is_synced(&self) -> bool { matches!(self.state, SyncState::Synced) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn random_peer() -> PeerId { let mut p = [0u8; 20]; p[0] = rand::random(); p }
    #[test] fn new_sync_is_synced() { assert!(ChainSync::new(100).is_synced()); }
    #[test] fn request_blocks_changes_state() { let mut s = ChainSync::new(100); s.request_blocks(0, 9, random_peer()); assert!(!s.is_synced()); }
    #[test] fn batch_clamped_to_size() { let mut s = ChainSync::new(100); s.request_blocks(0, 9999, random_peer()); assert!(s.requested_heights.len() <= 100); }
    #[test] fn mark_received_tracks_heights() { let mut s = ChainSync::new(100); s.request_blocks(0, 5, random_peer()); s.mark_received(0); s.mark_received(1); assert!(s.is_received(0)); assert!(!s.is_received(3)); }
    #[test] fn all_received_completes_sync() { let mut s = ChainSync::new(100); s.request_blocks(0, 2, random_peer()); s.mark_received(0); s.mark_received(1); s.mark_received(2); assert!(s.is_synced()); }
    #[test] fn timeout_changes_to_failed() { let mut s = ChainSync::new(100); s.request_timeout = Duration::from_millis(1); s.request_blocks(0, 10, random_peer()); std::thread::sleep(Duration::from_millis(2)); s.check_timeout(); assert!(matches!(s.state(), SyncState::Failed { .. })); }
}
