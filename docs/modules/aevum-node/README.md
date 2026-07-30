# aevum-node — Full Node Implementation

## Module Responsibility
`aevum-node` is the main entry point for running a full Aevum node. It integrates all other modules into a single executable, providing P2P networking, block synchronization, transaction pool management, HTTP API, and the mining loop.

## Key Components
- **`main.rs`** — Node entry point with CLI argument parsing.
- **`node_builder.rs`** — Dependency injection and service orchestration.
- **`p2p_manager.rs`** — Network layer coordinator (gossip, relay, registry).
- **`sync.rs`** — Chain synchronization with orphan resolution.
- **`mempool.rs`** — Transaction pool with fee-bucket ordering.
- **`mining_loop.rs`** — Block production and epoch reward distribution.
- **`http_server.rs`** — REST API for external clients.
- **`connection_manager.rs`** — Inbound/outbound peer management.
- **`presence_gossip.rs`** — Heartbeat propagation for Proof of Presence.

## Interaction with Other Modules
- **Uses** `aevum-core` for block/transaction structures.
- **Uses** `aevum-consensus` for validation.
- **Uses** `aevum-db` for persistent storage.
- **Uses** `aevum-l2` for compute settlement.
- **Uses** `aevum-onion` for anonymity routing.
- **Uses** `aevum-pq` for post-quantum cryptography.

## Public Interfaces (Overview)
- Node startup and shutdown.
- P2P peer discovery and connection management.
- Transaction submission and propagation.
- Block production and mining.
- REST API for status, blocks, and transactions.

## Uniqueness for Aevum
The node is built with a **modular, zero-dependency philosophy**. It does not rely on external libraries for networking, storage, or cryptography — everything is implemented from scratch in Rust. This ensures determinism and reduces attack surface.

## Related Modules
- **Depends on:** All other modules
- **Used by:** End users and node operators
