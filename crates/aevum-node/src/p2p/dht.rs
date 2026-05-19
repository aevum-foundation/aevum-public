use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::net::SocketAddr;

const K_BUCKETS: usize = 256;
const K: usize = 8; // max nodes per bucket (как в BitTorrent)

/// Kademlia Distributed Hash Table
pub struct Dht {
    /// 256 bucket'ов по XOR distance от нашего ID
    buckets: [Vec<DhtNode>; K_BUCKETS],
    /// Наш ID (первые 32 байта = хеш публичного ключа)
    our_id: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct DhtNode {
    pub node_id: [u8; 32],
    pub addr: SocketAddr,
    pub last_seen: u64,
}

impl Dht {
    pub fn new(our_id: [u8; 32]) -> Self {
        Dht {
            buckets: std::array::from_fn(|_| Vec::with_capacity(K)),
            our_id,
        }
    }

    /// XOR distance между двумя ID
    fn distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut dist = [0u8; 32];
        for i in 0..32 { dist[i] = a[i] ^ b[i]; }
        dist
    }

    /// В какой bucket попадёт узел (по старшему биту XOR distance)
    /// Если distance == 0 (свой ID) → bucket 0, но add_or_update отфильтрует
    fn bucket_index(distance: &[u8; 32]) -> usize {
        for i in 0..32 {
            if distance[i] != 0 {
                let bit = 7 - distance[i].leading_zeros() as usize;
                return (i * 8 + bit).min(K_BUCKETS - 1);
            }
        }
        0
    }

    /// Добавить или обновить узел
    pub fn add_or_update(&mut self, node_id: [u8; 32], addr: SocketAddr, now: u64) {
        if node_id == self.our_id { return; }
        let dist = Self::distance(&self.our_id, &node_id);
        let idx = Self::bucket_index(&dist);
        let bucket = &mut self.buckets[idx];

        // Обновляем если уже есть
        if let Some(existing) = bucket.iter_mut().find(|n| n.node_id == node_id) {
            existing.addr = addr;
            existing.last_seen = now;
            return;
        }

        let node = DhtNode { node_id, addr, last_seen: now };

        if bucket.len() < K {
            bucket.push(node);
        } else {
            // Kademlia: ping oldest, если не ответит — заменить
            // Упрощённо: удаляем самый старый
            bucket.sort_by_key(|n| n.last_seen);
            bucket[0] = node;
        }
    }

    /// Найти K ближайших ЖИВЫХ узлов к target_id
    pub fn find_closest(&self, target_id: &[u8; 32], count: usize, now: u64, timeout_secs: u64) -> Vec<DhtNode> {
        let target_dist = Self::distance(target_id, &self.our_id);
        let target_idx = Self::bucket_index(&target_dist);

        let mut closest: Vec<DhtNode> = Vec::new();

        // Собираем из bucket'ов от ближайшего к дальнему
        let mut left = target_idx as i32;
        let mut right = (target_idx + 1) as i32;

        while closest.len() < count && (left >= 0 || right < K_BUCKETS as i32) {
            if left >= 0 {
                closest.extend(self.buckets[left as usize].iter()
                    .filter(|n| now - n.last_seen < timeout_secs)
                    .cloned());
                left -= 1;
            }
            if right < K_BUCKETS as i32 {
                closest.extend(self.buckets[right as usize].iter()
                    .filter(|n| now - n.last_seen < timeout_secs)
                    .cloned());
                right += 1;
            }
        }

        // Сортируем по XOR distance от target
        closest.sort_by_key(|n| u256_from_bytes(&Self::distance(&n.node_id, target_id)));
        closest.truncate(count);
        closest
    }

    /// Случайные живые узлы (для репликации) — правильный shuffle
    pub fn random_nodes(&self, count: usize, now: u64, timeout_secs: u64) -> Vec<DhtNode> {
        let mut all: Vec<DhtNode> = self.buckets.iter()
            .flatten()
            .filter(|n| now - n.last_seen < timeout_secs)
            .cloned()
            .collect();
        all.shuffle(&mut rand::thread_rng());
        all.truncate(count);
        all
    }

    /// Получить случайные ID для refresh каждого bucket
    pub fn refresh_targets(&self) -> Vec<[u8; 32]> {
        let mut targets = Vec::new();
        for bucket in &self.buckets {
            if !bucket.is_empty() {
                let idx = rand::random::<usize>() % bucket.len();
                targets.push(bucket[idx].node_id);
            }
        }
        targets
    }

    /// Очистить мёртвые узлы
    pub fn cleanup(&mut self, now: u64, timeout_secs: u64) {
        for bucket in &mut self.buckets {
            bucket.retain(|n| now - n.last_seen < timeout_secs);
        }
    }

    pub fn total_nodes(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn alive_nodes(&self, now: u64, timeout_secs: u64) -> usize {
        self.buckets.iter()
            .flat_map(|b| b.iter())
            .filter(|n| now - n.last_seen < timeout_secs)
            .count()
    }
}

/// Конвертация [u8; 32] в сортируемый ключ
fn u256_from_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..4 {
        let start = i * 8;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes[start..start + 8]);
        result[i] = u64::from_be_bytes(arr);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_find() {
        let mut dht = Dht::new([0u8; 32]);
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();

        for i in 1..=20 {
            let mut id = [0u8; 32];
            id[0] = i;
            dht.add_or_update(id, addr, 1000);
        }

        let closest = dht.find_closest(&[255u8; 32], 8, 2000, 3600);
        assert_eq!(closest.len(), 8);
        assert!(closest[0].node_id[0] >= 13);
    }

    #[test]
    fn random_nodes_is_random() {
        let mut dht = Dht::new([0u8; 32]);
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();

        for i in 1..=20 {
            let mut id = [0u8; 32];
            id[0] = i;
            dht.add_or_update(id, addr, 1000);
        }

        let r1 = dht.random_nodes(4, 2000, 3600);
        let r2 = dht.random_nodes(4, 2000, 3600);
        // Могут совпасть, но вероятность мала с 20 узлами
        let same = r1.iter().zip(r2.iter()).filter(|(a, b)| a.node_id == b.node_id).count();
        assert!(same < 4); // не все 4 одинаковые
    }

    #[test]
    fn cleanup_removes_dead() {
        let mut dht = Dht::new([0u8; 32]);
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();

        dht.add_or_update([1u8; 32], addr, 1000);
        dht.add_or_update([2u8; 32], addr, 5000);

        dht.cleanup(6000, 3600);
        assert_eq!(dht.total_nodes(), 1); // только [2u8; 32] жив
    }

    #[test]
    fn refresh_targets() {
        let mut dht = Dht::new([0u8; 32]);
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();

        for i in 0..5 {
            let mut id = [0u8; 32];
            id[0] = 1u8 << i;
            dht.add_or_update(id, addr, 1000);
        }

        let targets = dht.refresh_targets();
        assert_eq!(targets.len(), 5);
    }
}
