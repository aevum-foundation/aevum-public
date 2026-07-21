# Aevum Protocol — Architecture Overview

The protocol is organized into 25 independent crates, each responsible for a specific layer of the system. Together they form a sovereign compute network.

## Core Layer
| Crate | Responsibility |
| :--- | :--- |
| `aevum-core` | Blocks, transactions, UTXO, state, DNA, state transitions |
| `aevum-crypto` | Cryptographic primitives: Ed25519, X25519, BLAKE3, SHA3, ML-KEM, ML-DSA |
| `aevum-consensus` | Proof of History (PoH), validator set, block validation |
| `aevum-node` | Full node: P2P, mempool, sync, HTTP API, mining loop |
| `aevum-db` | LSM storage engine: WAL + SSTable + compaction |

## Settlement & Compute
| Crate | Responsibility |
| :--- | :--- |
| `aevum-l2` | L2 transactions, economics, smart contracts, fraud proofs |
| `aevum-settlement` | Batch finality, fraud challenges, proof aggregation |
| `aevum-execution` | ChunkVM — deterministic execution sandbox |
| `aevum-compute-market` | GPU compute marketplace (PoUPR) |

## Network & Privacy
| Crate | Responsibility |
| :--- | :--- |
| `aevum-onion` | Tor-style onion routing — circuit-based anonymity |
| `aevum-intelligence` | Crawlers + Prisma AML — risk scoring and pattern detection |
| `aevum-lora` | LoRa mesh networking — radio-based p2p communication |

## Infrastructure & Governance
| Crate | Responsibility |
| :--- | :--- |
| `aevum-zk` | Zero-knowledge proofs: verifier, circuits, aggregation |
| `aevum-pq` | Post-quantum cryptography: ML-KEM, ML-DSA, SLH-DSA, hybrid signatures |
| `aevum-bridge` | L1↔L2 bridge with deterministic finality |
| `aevum-identity` | Decentralized identity (DID) + reputation graph |
| `aevum-dao` | On-chain governance, proposals, voting, treasury |
| `aevum-api` | REST/gRPC gateway for external clients |
| `aevum-metrics` | Prometheus observability and health monitoring |

## Key Design Principles
1.  **Determinism:** Same input → same state transition on all nodes.
2.  **Integer-only math:** No f64 — fully deterministic across platforms.
3.  **Bounded everything:** All vectors have max capacity with LRU eviction.
4.  **No censorship at network layer:** Network propagation is independent of asset provenance.
5.  **Post-quantum ready:** All critical paths can be upgraded to ML-DSA/ML-KEM without breaking consensus.
