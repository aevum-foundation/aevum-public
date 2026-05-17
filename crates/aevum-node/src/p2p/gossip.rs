use crate::p2p::sync::AtpMessage;
use crate::p2p::peers::PeersManager;
use lru::LruCache;
use std::num::NonZeroUsize;

const TTL_MAX: u8 = 3;
const FANOUT: usize = 8;
const SEEN_CACHE_SIZE: usize = 10000;

pub struct GossipManager {
    pub seen_cache: LruCache<[u8; 32], ()>,
}

impl GossipManager {
    pub fn new() -> Self {
        Self {
            seen_cache: LruCache::new(NonZeroUsize::new(SEEN_CACHE_SIZE).unwrap()),
        }
    }

    pub fn handle_transaction(
        &mut self,
        tx_hash: [u8; 32],
        ttl: u8,
        bytes: Vec<u8>,
        peers: &PeersManager,
    ) -> bool {
        if self.seen_cache.contains(&tx_hash) {
            return false;
        }
        
        self.seen_cache.put(tx_hash, ());
        
        if ttl > 0 {
            let new_ttl = ttl - 1;
            let msg = AtpMessage::Transaction {
                tx_hash,
                ttl: new_ttl,
                bytes,
            };
            
            if let Ok(data) = bincode::serialize(&msg) {
                let mut peer_ids: Vec<[u8; 20]> = Vec::new();
                for entry in &peers.peers {
                    peer_ids.push(*entry.key());
                }
                
                let fanout = FANOUT.min(peer_ids.len());
                let step = peer_ids.len().max(1) / fanout.max(1);
                
                for i in 0..fanout {
                    let idx = (i * step) % peer_ids.len().max(1);
                    if idx < peer_ids.len() {
                        peers.send_to(&peer_ids[idx], data.clone());
                    }
                }
            }
            
            return true;
        }
        
        false
    }

    pub fn is_seen(&self, tx_hash: &[u8; 32]) -> bool {
        self.seen_cache.contains(tx_hash)
    }
}
