use std::time::{Duration, Instant};
use std::net::SocketAddr;
use std::collections::HashMap;

/// Оценка пира: от -100 (бан) до 100 (отличный)
#[derive(Debug, Clone)]
pub struct PeerScore {
    pub score: i32,
    pub addr: SocketAddr,
    pub success_handshakes: u32,
    pub failed_handshakes: u32,
    pub valid_blocks: u64,
    pub invalid_blocks: u64,
    pub timeouts: u32,
    pub last_seen: Instant,
    pub last_score_update: Instant,
    pub banned_until: Option<Instant>,
}

impl PeerScore {
    pub fn new(addr: SocketAddr) -> Self {
        let now = Instant::now();
        Self {
            score: 0, addr,
            success_handshakes: 0, failed_handshakes: 0,
            valid_blocks: 0, invalid_blocks: 0, timeouts: 0,
            last_seen: now, last_score_update: now,
            banned_until: None,
        }
    }

    pub fn on_success_handshake(&mut self) { self.success_handshakes += 1; self.add_score(10); }
    pub fn on_failed_handshake(&mut self) { self.failed_handshakes += 1; self.add_score(-10); }
    pub fn on_valid_block(&mut self) { self.valid_blocks += 1; self.add_score(5); }
    pub fn on_invalid_block(&mut self) { self.invalid_blocks += 1; self.add_score(-50); }
    pub fn on_timeout(&mut self) { self.timeouts += 1; self.add_score(-5); }
    pub fn on_fast_response(&mut self) { self.add_score(2); }

    fn add_score(&mut self, delta: i32) {
        self.recover_passive();
        self.score = (self.score + delta).clamp(-100, 100);
        self.last_seen = Instant::now();
        self.last_score_update = Instant::now();
    }

    /// Пассивное восстановление: +1 балл каждые 10 минут если score < 0
    fn recover_passive(&mut self) {
        if self.score < 0 {
            let elapsed = self.last_score_update.elapsed();
            let minutes = elapsed.as_secs() / 600; // каждые 10 минут
            if minutes > 0 {
                self.score = (self.score + minutes as i32).min(0); // до 0 максимум
                self.last_score_update = Instant::now();
            }
        }
    }

    /// Проверить пассивное восстановление (вызывается периодически)
    pub fn check_recovery(&mut self) {
        self.recover_passive();
    }

    pub fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            if Instant::now() < until { return true; }
        }
        false
    }

    pub fn is_penalized(&self) -> bool {
        self.score < 0
    }

    pub fn ban(&mut self, duration_secs: u64) {
        self.banned_until = Some(Instant::now() + Duration::from_secs(duration_secs));
    }

    pub fn unban(&mut self) {
        self.banned_until = None;
    }
}

/// Менеджер репутации пиров
pub struct PeerScoring {
    scores: HashMap<SocketAddr, PeerScore>,
    /// Максимальное время хранения записи без активности
    max_idle: Duration,
}

impl PeerScoring {
    pub fn new() -> Self {
        Self { scores: HashMap::new(), max_idle: Duration::from_secs(3600) }
    }

    pub fn get_or_create(&mut self, addr: SocketAddr) -> &mut PeerScore {
        self.scores.entry(addr).or_insert_with(|| PeerScore::new(addr))
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<&PeerScore> {
        self.scores.get(addr)
    }

    /// Получить топ N лучших пиров (не забаненых и не penalized)
    pub fn top_peers(&self, n: usize) -> Vec<SocketAddr> {
        let mut peers: Vec<_> = self.scores.values()
            .filter(|p| !p.is_banned() && !p.is_penalized())
            .collect();
        peers.sort_by_key(|p| -p.score);
        peers.truncate(n);
        peers.iter().map(|p| p.addr).collect()
    }

    /// Проверить всех на пассивное восстановление
    pub fn check_all_recovery(&mut self) {
        for score in self.scores.values_mut() {
            score.check_recovery();
        }
    }

    /// Очистить старые записи и просроченные баны
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.scores.retain(|_, s| {
            // Удаляем если бан истёк и пир давно не был замечен
            if s.is_banned() && s.banned_until.map_or(true, |u| now > u) {
                return false;
            }
            // Удаляем если пир неактивен больше max_idle и score = 0
            if s.score == 0 && s.last_seen.elapsed() > self.max_idle {
                return false;
            }
            true
        });
    }

    pub fn len(&self) -> usize { self.scores.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_handshake() {
        let mut ps = PeerScoring::new();
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let s = ps.get_or_create(addr);
        s.on_success_handshake();
        assert_eq!(s.score, 10);
    }

    #[test]
    fn test_invalid_block_penalizes() {
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let mut s = PeerScore::new(addr);
        s.on_invalid_block();
        assert!(s.is_penalized());
        assert!(!s.is_banned()); // penalized но не banned
    }

    #[test]
    fn test_ban_timer() {
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let mut s = PeerScore::new(addr);
        s.ban(60);
        assert!(s.is_banned());
    }

    #[test]
    fn test_passive_recovery() {
        let addr: SocketAddr = "127.0.0.1:9733".parse().unwrap();
        let mut s = PeerScore::new(addr);
        s.add_score(-50);
        assert_eq!(s.score, -50);
        // Симулируем прошедшее время
        s.last_score_update = Instant::now() - Duration::from_secs(600);
        s.check_recovery();
        assert_eq!(s.score, -49);
    }
}
