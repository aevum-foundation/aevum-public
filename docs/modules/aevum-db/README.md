# aevum-db — Storage Engine

## Module Responsibility
`aevum-db` is a custom LSM-tree storage engine built specifically for blockchain data. It provides persistent storage for blocks, transactions, and UTXO state with high write throughput and fast recovery.

## Key Components
- **`wal.rs`** — Write-Ahead Log with hash-chain integrity.
- **`memtable.rs`** — In-memory buffer with MVCC support.
- **`sstable.rs`** — Sorted String Table with LRU block cache.
- **`compaction.rs`** — Background compaction for space reclamation.
- **`recovery.rs`** — Crash recovery with integrity verification.
- **`sharded_memtable.rs`** — 64-shard parallel write buffer.

## Interaction with Other Modules
- **Used by** `aevum-node` for block and state storage.
- **Used by** `aevum-consensus` during validation.
- **Uses** `aevum-crypto` for data integrity checks.

## Public Interfaces (Overview)
- Key-value store with atomic batch writes.
- Snapshot isolation for consistent reads.
- Crash recovery with hash-chain verification.

## Uniqueness for Aevum
This is not a fork of LevelDB or RocksDB. It's a from-scratch implementation in Rust with built-in cryptographic protection (hash-chained WAL, per-file encryption keys). The design prioritizes determinism and security.

## Related Modules
- **Depends on:** `aevum-crypto`
- **Used by:** `aevum-node`, `aevum-consensus`, `aevum-settlement`
