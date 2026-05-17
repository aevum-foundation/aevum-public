use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use rand::seq::SliceRandom;
use rand::thread_rng;

/// Запись об адресе пира
#[derive(Debug, Clone)]
pub struct AddrEntry {
    pub addr: SocketAddr,
    pub first_seen: Instant,
    pub last_seen: Instant,
    pub last_success: Option<Instant>,
    pub success_count: u32,
    pub fail_count: u32,
    pub score: i32,
    pub is_seed: bool, // DNS seed ноды
}

impl AddrEntry {
    pub fn new(addr: SocketAddr, is_seed: bool) -> Self {
        let now = Instant::now();
        Self {
            addr, is_seed,
            first_seen: now, last_seen: now,
            last_success: None, success_count: 0, fail_count: 0, score: 0,
        }
    }

    pub fn on_success(&mut self) {
        self.success_count += 1;
        self.last_success = Some(Instant::now());
        self.last_seen = Instant::now();
        self.score = (self.score + 10).min(100);
    }

    pub fn on_fail(&mut self) {
        self.fail_count += 1;
        self.last_seen = Instant::now();
        self.score = (self.score - 5).max(-50);
    }

    /// Приоритет для выбора: чем выше, тем лучше
    pub fn priority(&self) -> u64 {
        let age_secs = self.first_seen.elapsed().as_secs();
        let success_bonus = (self.success_count as u64) * 100;
        let seed_bonus = if self.is_seed { 10000 } else { 0 };
        let score_bonus = (self.score.max(0) as u64) * 50;
        age_secs + success_bonus + seed_bonus + score_bonus
    }
}

/// AddrManager — управляет известными адресами пиров
pub struct AddrManager {
    addrs: HashMap<SocketAddr, AddrEntry>,
    max_entries: usize,
}

impl AddrManager {
    pub fn new(max_entries: usize) -> Self {
        Self { addrs: HashMap::with_capacity(max_entries), max_entries }
    }

    /// Добавить или обновить адрес
    pub fn add(&mut self, addr: SocketAddr, is_seed: bool) {
        if self.addrs.len() >= self.max_entries && !self.addrs.contains_key(&addr) {
            // Удаляем худшего
            self.remove_worst();
        }
        self.addrs.entry(addr)
            .and_modify(|e| { e.last_seen = Instant::now(); })
            .or_insert_with(|| AddrEntry::new(addr, is_seed));
    }

    /// Добавить несколько адресов (например от пира)
    pub fn add_batch(&mut self, addrs: Vec<SocketAddr>) {
        for addr in addrs { self.add(addr, false); }
    }

    /// Отметить успешное соединение
    pub fn on_success(&mut self, addr: &SocketAddr) {
        if let Some(e) = self.addrs.get_mut(addr) { e.on_success(); }
    }

    /// Отметить неудачное соединение
    pub fn on_fail(&mut self, addr: &SocketAddr) {
        if let Some(e) = self.addrs.get_mut(addr) { e.on_fail(); }
    }

    /// Получить N лучших адресов для подключения
    pub fn get_best(&self, n: usize, exclude: &[SocketAddr]) -> Vec<SocketAddr> {
        let mut entries: Vec<_> = self.addrs.values()
            .filter(|e| !exclude.contains(&e.addr))
            .collect();
        entries.sort_by_key(|e| -(e.priority() as i64));
        entries.truncate(n);
        entries.iter().map(|e| e.addr).collect()
    }

    /// Получить случайные адреса (для PEX)
    pub fn get_random(&self, n: usize) -> Vec<SocketAddr> {
        let mut entries: Vec<_> = self.addrs.values().collect();
        entries.shuffle(&mut thread_rng());
        entries.truncate(n);
        entries.iter().map(|e| e.addr).collect()
    }

    /// Получить все адреса
    pub fn get_all(&self) -> Vec<SocketAddr> {
        self.addrs.keys().cloned().collect()
    }

    /// Количество известных адресов
    pub fn len(&self) -> usize { self.addrs.len() }

    /// Удалить худший адрес (если лимит превышен)
    fn remove_worst(&mut self) {
        if let Some(worst) = self.addrs.values().filter(|e| !e.is_seed).min_by_key(|e| e.priority()) {
            let addr = worst.addr;
            self.addrs.remove(&addr);
        }
    }

    /// Очистить старые адреса
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        // Не удаляем seed ноды
        self.addrs.retain(|_, e| e.is_seed || now - e.last_seen < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get() {
        let mut am = AddrManager::new(100);
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        am.add(addr, false);
        assert_eq!(am.len(), 1);
        assert_eq!(am.get_best(1, &[]), vec![addr]);
    }

    #[test]
    fn test_success_increases_priority() {
        let mut am = AddrManager::new(100);
        let addr1: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:9734".parse().unwrap();
        am.add(addr1, false);
        am.add(addr2, false);
        am.on_success(&addr2);
        let best = am.get_best(1, &[]);
        assert_eq!(best[0], addr2); // addr2 has higher priority after success
    }

    #[test]
    fn test_seed_priority() {
        let mut am = AddrManager::new(100);
        let addr1: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let addr2: SocketAddr = "192.168.1.1:9733".parse().unwrap();
        am.add(addr1, true); // seed
        am.add(addr2, false);
        let best = am.get_best(1, &[]);
        assert_eq!(best[0], addr1); // seed wins
    }
}
