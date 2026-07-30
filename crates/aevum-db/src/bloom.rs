//! BloomFilter v1.1 — Probabilistic key existence filter for SST files
//!
//! ## Исправления с v1.0
//! - [P1-1] `add()`: guard на пустой фильтр
//! - [P1-2] `double_hash()`: h2 | 1 гарантирует ненулевой второй хеш
//! - [P2] Убран лишний +4 в `to_bytes` capacity
//! - [P2] Тесты на corrupted/truncated `from_bytes`
//!
//! ## Параметры
//! - `bits_per_key`: 10 = ~0.8% false positive rate (7 хеш-функций)
//! - Хеш-функция: двойное хеширование Kirsch-Mitzenmacher (h1 + i·h2)
//! - Память: ~1.25 байта на ключ (10 бит / 8)

use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub struct BloomFilter {
    bits: Vec<u64>,
    num_hashes: u32,
    count: usize,
}

impl BloomFilter {
    /// Создать новый фильтр Блума.
    ///
    /// # Аргументы
    /// * `expected_keys` — ожидаемое количество ключей
    /// * `bits_per_key` — бит на ключ (10 = ~0.8% FP, 7 = ~10% FP)
    pub fn new(expected_keys: usize, bits_per_key: u32) -> Self {
        let bits_per_key = bits_per_key.max(1);
        let bits = (expected_keys * bits_per_key as usize).max(64);
        let words = (bits + 63) / 64;
        let num_hashes = ((bits as f64 / expected_keys.max(1) as f64) * 0.693147).ceil() as u32;
        let num_hashes = num_hashes.max(1).min(32);

        BloomFilter {
            bits: vec![0u64; words],
            num_hashes,
            count: 0,
        }
    }

    /// Создать фильтр из готовых данных (при загрузке SST).
    /// Если bits пуст — создаётся минимальный фильтр (1 слово).
    pub fn from_raw(bits: Vec<u64>, num_hashes: u32) -> Self {
        let bits = if bits.is_empty() { vec![0u64; 1] } else { bits };
        BloomFilter {
            bits,
            num_hashes: num_hashes.max(1).min(32),
            count: 0,
        }
    }

    /// Добавить ключ в фильтр.
    pub fn add<T: Hash>(&mut self, key: &T) {
        if self.bits.is_empty() {
            return;
        }
        let (h1, h2) = self.double_hash(key);
        for i in 0..self.num_hashes {
            let idx = self.bit_index(h1, h2, i);
            self.bits[idx / 64] |= 1u64 << (idx % 64);
        }
        self.count += 1;
    }

    /// Проверить, может ли ключ присутствовать.
    /// `false` = ключ точно отсутствует. `true` = возможно присутствует.
    pub fn may_contain<T: Hash>(&self, key: &T) -> bool {
        if self.bits.is_empty() || self.num_hashes == 0 {
            return false;
        }
        let (h1, h2) = self.double_hash(key);
        for i in 0..self.num_hashes {
            let idx = self.bit_index(h1, h2, i);
            if self.bits[idx / 64] & (1u64 << (idx % 64)) == 0 {
                return false;
            }
        }
        true
    }

    /// Количество добавленных ключей (не сохраняется при сериализации).
    pub fn count(&self) -> usize {
        self.count
    }

    /// Размер фильтра в байтах.
    pub fn size_bytes(&self) -> usize {
        self.bits.len() * 8
    }

    /// Количество хеш-функций.
    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    /// Сырые биты для сериализации.
    pub fn bits(&self) -> &[u64] {
        &self.bits
    }

    /// Сериализовать в Vec<u8>.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.bits.len() * 8);
        out.extend_from_slice(&(self.num_hashes as u32).to_le_bytes());
        for word in &self.bits {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// Десериализовать из байтов.
    /// Возвращает None если данные повреждены или слишком короткие.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let num_hashes = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let words = (data.len() - 4) / 8;
        if words == 0 {
            return None;
        }
        // Проверяем что данные не содержат мусора в хвосте
        if (data.len() - 4) % 8 != 0 {
            return None;
        }
        let mut bits = Vec::with_capacity(words);
        for i in 0..words {
            let start = 4 + i * 8;
            if start + 8 > data.len() {
                return None;
            }
            let word = u64::from_le_bytes(data[start..start + 8].try_into().ok()?);
            bits.push(word);
        }
        Some(BloomFilter {
            bits,
            num_hashes: num_hashes.max(1).min(32),
            count: 0,
        })
    }

    // ─── Внутренние ──────────────────────────────────

    /// Двойное хеширование: h1 + i·h2 (Kirsch-Mitzenmacher).
    /// h2 гарантированно нечётный и ненулевой через | 1.
    fn double_hash<T: Hash>(&self, key: &T) -> (u64, u64) {
        let h1 = self.hash_key(key, 0x5bd1e995);
        let h2 = self.hash_key(key, 0xc6a4a793) | 1;
        (h1, h2)
    }

    fn hash_key<T: Hash>(&self, key: &T, seed: u64) -> u64 {
        let mut hasher = rustc_hash::FxHasher::default();
        seed.hash(&mut hasher);
        key.hash(&mut hasher);
        hasher.finish()
    }

    fn bit_index(&self, h1: u64, h2: u64, i: u32) -> usize {
        let h = h1.wrapping_add((i as u64).wrapping_mul(h2));
        (h as usize) % (self.bits.len() * 64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter_returns_false() {
        let bloom = BloomFilter::new(100, 10);
        assert!(!bloom.may_contain(b"anything"));
    }

    #[test]
    fn test_add_and_contain() {
        let mut bloom = BloomFilter::new(100, 10);
        bloom.add(b"hello");
        bloom.add(b"world");
        assert!(bloom.may_contain(b"hello"));
        assert!(bloom.may_contain(b"world"));
    }

    #[test]
    fn test_definitely_not_contains() {
        let mut bloom = BloomFilter::new(100, 10);
        bloom.add(b"aezakmi");
        assert!(!bloom.may_contain(b"never_added"));
    }

    #[test]
    fn test_false_positive_rate() {
        let n = 1000;
        let bits_per_key = 10;
        let mut bloom = BloomFilter::new(n, bits_per_key);

        for i in 0..n {
            bloom.add(&format!("key{}", i));
        }

        let mut fp = 0;
        let test_n = 10000;
        for i in n..n + test_n {
            if bloom.may_contain(&format!("key{}", i)) {
                fp += 1;
            }
        }

        let fp_rate = fp as f64 / test_n as f64;
        assert!(fp_rate < 0.02, "FP rate {} too high for {} bits/key", fp_rate, bits_per_key);
    }

    #[test]
    fn test_count() {
        let mut bloom = BloomFilter::new(100, 10);
        assert_eq!(bloom.count(), 0);
        bloom.add(b"a");
        bloom.add(b"b");
        bloom.add(b"c");
        assert_eq!(bloom.count(), 3);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut bloom = BloomFilter::new(100, 10);
        bloom.add(b"test");
        bloom.add(b"serialize");

        let bytes = bloom.to_bytes();
        let restored = BloomFilter::from_bytes(&bytes).unwrap();

        assert!(restored.may_contain(b"test"));
        assert!(restored.may_contain(b"serialize"));
        assert!(!restored.may_contain(b"missing"));
    }

    #[test]
    fn test_from_bytes_empty() {
        assert!(BloomFilter::from_bytes(&[]).is_none());
        assert!(BloomFilter::from_bytes(&[0xFF; 3]).is_none());
    }

    #[test]
    fn test_from_bytes_truncated() {
        // 9 байт — не кратно 8 (мусор в хвосте)
        let data = vec![0u8; 13]; // 4 + 9 = ни 8 ни 16
        assert!(BloomFilter::from_bytes(&data).is_none());
    }

    #[test]
    fn test_large_filter() {
        let n = 10000;
        let mut bloom = BloomFilter::new(n, 10);
        for i in 0..n {
            bloom.add(&format!("large_key_{}", i));
        }
        for i in 0..n {
            assert!(bloom.may_contain(&format!("large_key_{}", i)));
        }
    }

    #[test]
    fn test_different_bits_per_key() {
        let bloom_7 = {
            let mut b = BloomFilter::new(1000, 7);
            for i in 0..1000 { b.add(&format!("k{}", i)); }
            b
        };
        let bloom_14 = {
            let mut b = BloomFilter::new(1000, 14);
            for i in 0..1000 { b.add(&format!("k{}", i)); }
            b
        };
        assert!(bloom_14.size_bytes() > bloom_7.size_bytes());
    }

    #[test]
    fn test_from_raw() {
        let mut bloom = BloomFilter::new(10, 10);
        bloom.add(b"raw");
        let raw_bits = bloom.bits().to_vec();
        let raw_hashes = bloom.num_hashes();

        let restored = BloomFilter::from_raw(raw_bits, raw_hashes);
        assert!(restored.may_contain(b"raw"));
        assert!(!restored.may_contain(b"not_raw"));
    }

    #[test]
    fn test_from_raw_empty() {
        let bloom = BloomFilter::from_raw(vec![], 7);
        // Должен создать минимальный фильтр, не паниковать при add
        assert_eq!(bloom.num_hashes(), 7);
        // may_contain на пустом должен работать
        assert!(!bloom.may_contain(b"anything"));
    }

    #[test]
    fn test_add_on_empty_raw_does_not_panic() {
        let mut bloom = BloomFilter::from_raw(vec![], 7);
        bloom.add(b"test"); // не должен паниковать
        // h2 | 1 гарантирует что второй хеш не ноль
        let (h1, h2) = bloom.double_hash(b"test");
        assert!(h2 != 0, "h2 must be non-zero");
    }
}
