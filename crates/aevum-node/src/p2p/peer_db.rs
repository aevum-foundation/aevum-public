use crate::storage::Storage;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ADDR_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
const FLUSH_INTERVAL: Duration = Duration::from_secs(300);

pub struct PeerDb {
    addresses: DashMap<SocketAddr, u64>,
    storage: Arc<StdMutex<Storage>>,
    last_flush: StdMutex<Instant>,
    dirty: AtomicBool,
}

impl PeerDb {
    pub fn load(storage: Arc<StdMutex<Storage>>) -> Self {
        let addresses = storage.lock().unwrap()
            .load_known_addresses()
            .unwrap_or_else(|_| DashMap::new());
        let now = now_secs();
        // Удаляем просроченные
        let to_remove: Vec<SocketAddr> = addresses.iter()
            .filter(|e| now - *e.value() >= ADDR_TTL.as_secs())
            .map(|e| *e.key())
            .collect();
        for addr in to_remove { addresses.remove(&addr); }
        tracing::info!("[PEERDB] Loaded {} addresses", addresses.len());
        PeerDb {
            addresses,
            storage,
            last_flush: StdMutex::new(Instant::now()),
            dirty: AtomicBool::new(false),
        }
    }

    pub fn add(&self, addr: SocketAddr) {
        self.addresses.insert(addr, now_secs());
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn add_and_flush(&self, addr: SocketAddr) {
        self.add(addr);
        self.flush_if_needed();
    }

    pub fn get_all(&self) -> Vec<SocketAddr> {
        let now = now_secs();
        let to_remove: Vec<SocketAddr> = self.addresses.iter()
            .filter(|e| now - *e.value() >= ADDR_TTL.as_secs())
            .map(|e| *e.key())
            .collect();
        for addr in to_remove { self.addresses.remove(&addr); }
        self.addresses.iter().map(|e| *e.key()).collect()
    }

    pub fn len(&self) -> usize { self.addresses.len() }

    pub fn flush_if_needed(&self) {
        if !self.dirty.load(Ordering::Relaxed) {
            let last = self.last_flush.lock().unwrap();
            if last.elapsed() < FLUSH_INTERVAL { return; }
        }
        let now = now_secs();
        let to_remove: Vec<SocketAddr> = self.addresses.iter()
            .filter(|e| now - *e.value() >= ADDR_TTL.as_secs())
            .map(|e| *e.key())
            .collect();
        for addr in to_remove { self.addresses.remove(&addr); }
        match self.storage.lock().unwrap().save_known_addresses(&self.addresses) {
            Ok(_) => {
                self.dirty.store(false, Ordering::Relaxed);
                *self.last_flush.lock().unwrap() = Instant::now();
            }
            Err(e) => tracing::warn!("[PEERDB] Failed to save: {}", e),
        }
    }

    pub fn force_flush(&self) {
        self.dirty.store(true, Ordering::Relaxed);
        *self.last_flush.lock().unwrap() = Instant::now() - FLUSH_INTERVAL;
        self.flush_if_needed();
    }

    /// Итератор для совместимости с bootstrap (как known_addresses)
    pub fn iter(&self) -> dashmap::iter::Iter<SocketAddr, u64> {
        self.addresses.iter()
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
