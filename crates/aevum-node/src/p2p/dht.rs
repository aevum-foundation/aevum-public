use std::collections::{HashMap, HashSet, BinaryHeap};
use std::cmp::Ordering;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use sha2::{Sha256, Digest};
use rand::seq::IteratorRandom;
use rand::thread_rng;

const K: usize = 20;
const KEY_BITS: usize = 256;
const PEER_TIMEOUT: Duration = Duration::from_secs(1800);
const ALPHA: usize = 3;

pub type NodeId = [u8; 32];

fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 32] {
    let mut dist = [0u8; 32];
    for i in 0..32 { dist[i] = a[i] ^ b[i]; }
    dist
}

fn leading_zeros(dist: &[u8; 32]) -> usize {
    for i in 0..32 {
        if dist[i] != 0 { return i * 8 + dist[i].leading_zeros() as usize; }
    }
    256
}

/// Полное 256-битное сравнение (исправлено P1)
fn u256_cmp(a: &[u8; 32], b: &[u8; 32]) -> Ordering {
    for i in 0..32 {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

struct KBucket {
    peers: Vec<PeerEntry>,
    last_updated: Instant,
}

impl KBucket {
    fn new() -> Self {
        Self { peers: Vec::with_capacity(K), last_updated: Instant::now() }
    }

    fn add_peer(&mut self, entry: PeerEntry) -> bool {
        self.peers.retain(|p| p.id != entry.id);
        if self.peers.len() < K {
            self.peers.push(entry);
            self.last_updated = Instant::now();
            true
        } else {
            // P1 fix: возвращаем старейшего для ping-проверки
            false
        }
    }

    fn oldest(&self) -> Option<&PeerEntry> {
        self.peers.iter().min_by_key(|p| p.last_seen)
    }

    fn remove_peer(&mut self, id: &NodeId) {
        self.peers.retain(|p| &p.id != id);
    }

    fn remove_stale(&mut self) {
        self.peers.retain(|p| p.last_seen.elapsed() < PEER_TIMEOUT);
    }

    fn is_empty(&self) -> bool { self.peers.is_empty() }
}

#[derive(Clone, Debug)]
pub struct PeerEntry {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub last_seen: Instant,
}

pub struct KademliaDht {
    our_id: NodeId,
    /// Ленивые бакеты: HashMap вместо массива на 256 (P2 fix)
    buckets: HashMap<usize, KBucket>,
    known_peers: HashMap<NodeId, PeerEntry>,
    blacklist: HashSet<NodeId>,
}

impl KademliaDht {
    pub fn new(our_pubkey: &[u8; 32]) -> Self {
        let our_id = Sha256::digest(our_pubkey).into();
        Self {
            our_id,
            buckets: HashMap::new(),
            known_peers: HashMap::new(),
            blacklist: HashSet::new(),
        }
    }

    fn bucket_index(&self, id: &NodeId) -> usize {
        let dist = xor_distance(&self.our_id, id);
        let lz = leading_zeros(&dist);
        if lz >= KEY_BITS { 0 } else { KEY_BITS - 1 - lz }
    }

    /// Добавить пира. Если бакет заполнен — возвращает старейшего для ping
    pub fn add_peer(&mut self, id: NodeId, addr: SocketAddr) -> (bool, Option<PeerEntry>) {
        if id == self.our_id || self.blacklist.contains(&id) {
            return (false, None);
        }

        let entry = PeerEntry { id, addr, last_seen: Instant::now() };
        self.known_peers.insert(id, entry.clone());
        
        let idx = self.bucket_index(&id);
        let bucket = self.buckets.entry(idx).or_insert_with(KBucket::new);
        
        if bucket.add_peer(entry.clone()) {
            (true, None)
        } else {
            // Бакет заполнен — возвращаем старейшего для ping (P1 fix)
            (false, bucket.oldest().cloned())
        }
    }

    /// Заменить старейшего пира новым (после неудачного ping)
    pub fn replace_peer(&mut self, old_id: &NodeId, new_entry: PeerEntry) {
        let idx = self.bucket_index(&new_entry.id);
        if let Some(bucket) = self.buckets.get_mut(&idx) {
            bucket.remove_peer(old_id);
            bucket.add_peer(new_entry.clone());
        }
        self.known_peers.remove(old_id);
        self.known_peers.insert(new_entry.id, new_entry);
    }

    pub fn update_peer(&mut self, id: &NodeId) {
        if let Some(entry) = self.known_peers.get_mut(id) {
            entry.last_seen = Instant::now();
        }
    }

    pub fn remove_peer(&mut self, id: &NodeId) {
        self.known_peers.remove(id);
        self.blacklist.insert(*id);
        let idx = self.bucket_index(id);
        if let Some(bucket) = self.buckets.get_mut(&idx) {
            bucket.remove_peer(id);
        }
    }

    /// Найти K ближайших пиров (поиск по бакетам + соседним)
    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<PeerEntry> {
        let target_idx = self.bucket_index(target);
        let mut heap = BinaryHeap::new();
        
        // Ищем в бакете target и соседних
        let start = if target_idx > 0 { target_idx - 1 } else { 0 };
        let end = (target_idx + 2).min(KEY_BITS);
        
        for idx in start..end {
            if let Some(bucket) = self.buckets.get(&idx) {
                for entry in &bucket.peers {
                    if entry.last_seen.elapsed() < PEER_TIMEOUT {
                        let dist = xor_distance(target, &entry.id);
                        heap.push(ScoredPeer { entry: entry.clone(), dist });
                    }
                }
            }
        }
        
        // Если не нашли — ищем по всем
        if heap.len() < count {
            for entry in self.known_peers.values() {
                if entry.last_seen.elapsed() < PEER_TIMEOUT {
                    let dist = xor_distance(target, &entry.id);
                    heap.push(ScoredPeer { entry: entry.clone(), dist });
                }
            }
        }
        
        let mut result = Vec::with_capacity(count);
        while let Some(scored) = heap.pop() {
            result.push(scored.entry);
            if result.len() >= count { break; }
        }
        result
    }

    /// Случайные пиры для PEX (выборка без shuffle)
    pub fn get_random_peers(&self, count: usize) -> Vec<PeerEntry> {
        let mut rng = thread_rng();
        self.known_peers
            .values()
            .filter(|p| p.last_seen.elapsed() < PEER_TIMEOUT)
            .choose_multiple(&mut rng, count)
            .into_iter()
            .cloned()
            .collect()
    }

    pub fn cleanup(&mut self) -> usize {
        let before = self.known_peers.len();
        for bucket in self.buckets.values_mut() {
            bucket.remove_stale();
        }
        self.known_peers.retain(|_, p| p.last_seen.elapsed() < PEER_TIMEOUT);
        before - self.known_peers.len()
    }

    pub fn active_peers(&self) -> usize {
        self.known_peers.values().filter(|p| p.last_seen.elapsed() < PEER_TIMEOUT).count()
    }

    pub fn bootstrap_addrs(&self) -> Vec<SocketAddr> {
        self.known_peers.values()
            .filter(|p| p.last_seen.elapsed() < PEER_TIMEOUT)
            .take(20)
            .map(|p| p.addr)
            .collect()
    }

    /// Получить старейшего пира из бакета (для ping)
    pub fn get_oldest_in_bucket(&self, id: &NodeId) -> Option<PeerEntry> {
        let idx = self.bucket_index(id);
        self.buckets.get(&idx)?.oldest().cloned()
    }
}

#[derive(Clone)]
struct ScoredPeer {
    entry: PeerEntry,
    dist: [u8; 32],
}

impl Eq for ScoredPeer {}
impl PartialEq for ScoredPeer {
    fn eq(&self, other: &Self) -> bool { self.dist == other.dist }
}
impl PartialOrd for ScoredPeer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}
impl Ord for ScoredPeer {
    fn cmp(&self, other: &Self) -> Ordering {
        // Инвертированный: ближайшие сверху (min-heap)
        u256_cmp(&other.dist, &self.dist)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_distance() {
        assert_eq!(xor_distance(&[0; 32], &[0xFF; 32]), [0xFF; 32]);
        assert_eq!(xor_distance(&[0; 32], &[0; 32]), [0; 32]);
    }

    #[test]
    fn test_add_and_find() {
        let mut dht = KademliaDht::new(&[1; 32]);
        for i in 1u8..10 {
            let mut id = [i; 32];
            let addr = format!("127.0.0.{}:9733", i).parse().unwrap();
            dht.add_peer(id, addr);
        }
        assert!(dht.active_peers() >= 9);
        
        let closest = dht.find_closest(&[5; 32], 3);
        assert!(!closest.is_empty());
    }

    #[test]
    fn test_replace_peer() {
        let mut dht = KademliaDht::new(&[1; 32]);
        // Заполняем бакет
        for i in 2u8..25 {
            let mut id = [i; 32];
            let addr = format!("127.0.0.{}:9733", i).parse().unwrap();
            dht.add_peer(id, addr);
        }
        // Добавляем ещё одного
        let (added, oldest) = dht.add_peer([25; 32], "127.0.0.25:9733".parse().unwrap());
        assert!(!added);
        assert!(oldest.is_some());
    }

    #[test]
    fn test_cleanup() {
        let mut dht = KademliaDht::new(&[1; 32]);
        dht.add_peer([2; 32], "127.0.0.2:9733".parse().unwrap());
        // Симулируем просрочку
        for (_, entry) in dht.known_peers.iter_mut() {
            entry.last_seen = Instant::now() - PEER_TIMEOUT - Duration::from_secs(1);
        }
        let removed = dht.cleanup();
        assert_eq!(removed, 1);
    }

    #[test]
    fn test_blacklist() {
        let mut dht = KademliaDht::new(&[1; 32]);
        let id = [2; 32];
        dht.add_peer(id, "127.0.0.2:9733".parse().unwrap());
        dht.remove_peer(&id);
        let (added, _) = dht.add_peer(id, "127.0.0.2:9733".parse().unwrap());
        assert!(!added);
    }

    #[test]
    fn test_u256_cmp() {
        let a = [0u8; 32];
        let mut b = [0u8; 32];
        b[31] = 1;
        assert_eq!(u256_cmp(&a, &b), Ordering::Less);
        assert_eq!(u256_cmp(&b, &a), Ordering::Greater);
        assert_eq!(u256_cmp(&a, &a), Ordering::Equal);
    }
}
