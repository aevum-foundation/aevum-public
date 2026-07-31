# Aevum Protocol Standard v1.0

## 1. Philosophy
Aevum is a **Presence-Provenance Sovereign Compute Protocol**.
- L1 = Proof of Presence + DNA-anchored emission.
- L2 = Deterministic compute settlement + fast transactions.
- Prisma = Compliance through mathematics, not censorship.

## 2. Economic Constants
| Parameter | Value |
| :--- | :--- |
| Max Supply | 371,000,000 AEV |
| Genesis Supply | 21,000,000 AEV |
| Block Time | 30 seconds |
| Blocks per Epoch | 2,880 (~24 hours) |
| Block Reward | 20 AEV |
| Epoch Reward | 57,600 AEV |
| Halving Interval | 867,240 blocks |
| Tail Emission | 10 AEV (after 4 halvings) |

## 3. Epoch & Participation
| Parameter | Value |
| :--- | :--- |
| Epoch Length | 2,880 blocks (~24 hours) |
| Max Participants | 100,000 |
| Full Nodes (Infrastructure) | 20,000 (20%) |
| Light Nodes (Queue) | 80,000 (80%) |
| Full Node Bonus | +12.5% (1.25x) |
| Bridge Node Bonus | +15% (1.5x) + per-chain bonus |

## 4. Network Constants
| Parameter | Value |
| :--- | :--- |
| Max Peers | 10,000 |
| Mesh Size | 6–12 peers |
| Max Fanout | 8 |
| Token Bucket Capacity | 100 |
| Token Refill Rate | 10/sec |
| Peer TTL | 3600 sec |
| Ban Duration | 86400 sec (24h) |
| Seen Messages Cache | 100,000 |

## 5. Unique Features
- **JT-UTXO:** Confidentiality + auditability built into the protocol.
- **Prisma:** Risk scoring without censorship. We warn, we don't freeze.
- **DNA:** Full asset provenance with built-in anti-censorship.
- **PoUPR:** Useful mining — GPU/CPU work that actually matters.
- **PQ-Stack:** Post-quantum ready (ML-KEM, ML-DSA, SLH-DSA).
- **Onion Routing:** Tor-style anonymity integrated at the network layer.
- **LoRa Mesh:** Radio-based peer-to-peer communication.

## 6. Module Map
```

crates/
├── aevum-core/          # Blocks, transactions, UTXO, state, DNA
├── aevum-crypto/        # Ed25519, X25519, BLAKE3, SHA3, PQ
├── aevum-consensus/     # PoH, validator set, block validation
├── aevum-node/          # Full node: P2P, mempool, sync, API
├── aevum-db/            # LSM storage: WAL + SSTable
├── aevum-l2/            # L2 transactions, economics, contracts
├── aevum-settlement/    # Batch finality, fraud challenges
├── aevum-execution/     # ChunkVM — deterministic sandbox
├── aevum-compute-market/# GPU marketplace (PoUPR)
├── aevum-onion/         # Tor-style onion routing
├── aevum-intelligence/  # Crawlers + Prisma AML
├── aevum-lora/          # LoRa mesh networking
├── aevum-zk/            # Zero-knowledge proofs
├── aevum-pq/            # Post-quantum cryptography
├── aevum-bridge/        # L1↔L2 bridge
├── aevum-identity/      # DID + reputation graph
├── aevum-dao/           # Governance, proposals, voting
├── aevum-api/           # REST/gRPC gateway
└── aevum-metrics/       # Prometheus observability

```
