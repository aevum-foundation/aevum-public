use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    Synced,
    Syncing {
        from: u64,
        to: u64,
        peer: libp2p::PeerId,
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

    /// Запросить блоки у пира. Диапазон обрезается до batch_size.
    pub fn request_blocks(&mut self, from: u64, to: u64, peer: libp2p::PeerId) {
        let to = to.min(from + self.batch_size - 1);
        self.state = SyncState::Syncing {
            from,
            to,
            peer,
            started_at: Instant::now(),
        };
        for h in from..=to {
            self.requested_heights.insert(h);
        }
    }

    /// Отметить высоту как полученную. Если все запрошенные высоты получены — Synced.
    pub fn mark_received(&mut self, height: u64) {
        self.requested_heights.remove(&height);
        if self.requested_heights.is_empty() {
            self.state = SyncState::Synced;
        }
    }

    pub fn is_received(&self, height: u64) -> bool {
        !self.requested_heights.contains(&height)
    }

    pub fn finish_sync(&mut self) {
        self.state = SyncState::Synced;
        self.requested_heights.clear();
    }

    /// Вызывать периодически в главном цикле ноды.
    pub fn check_timeout(&mut self) {
        if let SyncState::Syncing { started_at, .. } = self.state {
            if started_at.elapsed() > self.request_timeout {
                self.state = SyncState::Failed {
                    reason: "Request timeout".to_string(),
                };
                self.requested_heights.clear();
            }
        }
    }

    pub fn state(&self) -> &SyncState {
        &self.state
    }
    pub fn batch_size(&self) -> u64 {
        self.batch_size
    }
    pub fn is_synced(&self) -> bool {
        matches!(self.state, SyncState::Synced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sync_is_synced() {
        assert!(ChainSync::new(100).is_synced());
    }

    #[test]
    fn request_blocks_changes_state() {
        let mut sync = ChainSync::new(100);
        sync.request_blocks(0, 9, libp2p::PeerId::random());
        assert!(!sync.is_synced());
    }

    #[test]
    fn batch_clamped_to_size() {
        let mut sync = ChainSync::new(100);
        sync.request_blocks(0, 9999, libp2p::PeerId::random());
        assert!(sync.requested_heights.len() <= 100);
    }

    #[test]
    fn mark_received_tracks_heights() {
        let mut sync = ChainSync::new(100);
        sync.request_blocks(0, 5, libp2p::PeerId::random());
        sync.mark_received(0);
        sync.mark_received(1);
        assert!(sync.is_received(0));
        assert!(!sync.is_received(3));
    }

    #[test]
    fn all_received_completes_sync() {
        let mut sync = ChainSync::new(100);
        sync.request_blocks(0, 2, libp2p::PeerId::random());
        sync.mark_received(0);
        sync.mark_received(1);
        sync.mark_received(2);
        assert!(sync.is_synced());
    }

    #[test]
    fn timeout_changes_to_failed() {
        let mut sync = ChainSync::new(100);
        sync.request_timeout = Duration::from_millis(1);
        sync.request_blocks(0, 10, libp2p::PeerId::random());
        std::thread::sleep(Duration::from_millis(2));
        sync.check_timeout();
        assert!(matches!(sync.state(), SyncState::Failed { .. }));
    }
}
