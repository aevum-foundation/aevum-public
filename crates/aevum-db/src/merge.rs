//! MergingIterator v2.4 — LSM-safe deterministic merge

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use crate::error::{DbError, DbResult};
use crate::memtable::{MemEntry, MemValue};

#[derive(Debug, Clone)]
pub struct HeapEntry {
    pub key: Vec<u8>,
    pub value: MemValue,
    pub seq: u64,
    pub iter_idx: usize,
}

impl Eq for HeapEntry {}
impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool { self.key == other.key && self.seq == other.seq }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.key.cmp(&self.key)
            .then_with(|| self.seq.cmp(&other.seq))
            .then_with(|| self.iter_idx.cmp(&other.iter_idx))
    }
}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

pub struct MergingIterator {
    heap: BinaryHeap<HeapEntry>,
    iters: Vec<Box<dyn Iterator<Item = DbResult<(Vec<u8>, MemEntry)>>>>,
    exhausted: Vec<bool>,
    last_key: Option<Vec<u8>>,
}

impl MergingIterator {
    pub fn new(iters: Vec<Box<dyn Iterator<Item = DbResult<(Vec<u8>, MemEntry)>>>>) -> Self {
        let n = iters.len();
        let mut mi = Self { heap: BinaryHeap::with_capacity(n), iters, exhausted: vec![false; n], last_key: None };
        for i in 0..n { mi.push_next(i); }
        mi
    }

    fn push_next(&mut self, idx: usize) {
        if self.exhausted[idx] { return; }
        match self.iters[idx].next() {
            Some(Ok((key, entry))) => {
                self.heap.push(HeapEntry { key, value: entry.value, seq: entry.seq, iter_idx: idx });
            }
            Some(Err(_)) => { self.exhausted[idx] = true; }
            None => { self.exhausted[idx] = true; }
        }
    }

    pub fn next_entry(&mut self) -> DbResult<Option<HeapEntry>> {
        let entry = match self.heap.pop() {
            Some(e) => e,
            None => return Ok(None),
        };
        if let Some(ref prev) = self.last_key {
            if *prev > entry.key { return Err(DbError::Integrity("merge: key ordering violation")); }
        }
        self.last_key = Some(entry.key.clone());
        let idx = entry.iter_idx;
        self.push_next(idx);
        Ok(Some(entry))
    }
}

impl Iterator for MergingIterator {
    type Item = DbResult<(Vec<u8>, MemEntry)>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.next_entry() {
            Ok(Some(e)) => Some(Ok((e.key, MemEntry { seq: e.seq, value: e.value }))),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memtable::{MemEntry, MemValue};

    fn e(k: &[u8], s: u64) -> DbResult<(Vec<u8>, MemEntry)> {
        Ok((k.to_vec(), MemEntry { seq: s, value: MemValue::new_value(b"v".to_vec()) }))
    }

    #[test] fn ordered_merge() {
        let mi = MergingIterator::new(vec![
            Box::new(vec![e(b"a", 1), e(b"c", 3)].into_iter()),
            Box::new(vec![e(b"b", 2), e(b"d", 4)].into_iter()),
        ]);
        let keys: Vec<Vec<u8>> = mi.map(|r| r.unwrap().0).collect();
        assert_eq!(keys, vec![b"a", b"b", b"c", b"d"]);
    }

    #[test] fn empty() {
        let mi = MergingIterator::new(vec![Box::new(std::iter::empty())]);
        assert_eq!(mi.count(), 0);
    }
}
