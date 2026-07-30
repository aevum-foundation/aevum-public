# aevum-core — Protocol Core

## Module Responsibility
`aevum-core` is the foundation of the entire protocol. It defines the basic entities: blocks, transactions, UTXO outputs, and establishes the rules for their creation, verification, and transformation. This module does not contain network or consensus logic but provides them with "building blocks."

## Key Components
- **`block.rs`** — Block structure, header, hash computation.
- **`transaction.rs`** — Transaction definition, inputs and outputs (UTXO), version management.
- **`jt_utxo.rs`** — Confidential UTXO model with support for tags and nullifiers.
- **`state.rs`** — State management (UTXO set), state root computation.
- **`state_transition.rs`** — State transition rules when applying a block.
- **`economics.rs`** — Base emission and fee model (constants).
- **`dna.rs`** and **`dna_state.rs`** — Token provenance model (DNA) and DNA root management.
- **`compute.rs`** and **`compute_namespace.rs`** — Task type definitions for useful mining (PoUPR).

## Interaction with Other Modules
- **`aevum-consensus`** uses block and transaction structures for validation.
- **`aevum-node`** uses `chain_state` to manage the blockchain.
- **`aevum-db`** stores serialized blocks and UTXOs defined in this module.
- **`aevum-l2`** extends the transaction model for Layer 2 operations.

## Public Interfaces (Overview)
The module provides:
- Functions for creating and validating blocks and transactions.
- Methods for working with UTXO state.
- Base economic constants.
- Models for useful compute tasks.

## Uniqueness for Aevum
This module lays the groundwork for the protocol's main innovations: **JT-UTXO (confidentiality with auditability)**, **DNA provenance tracking**, and **PoUPR (useful mining)**. Its architecture is designed for determinism and security across all system layers.

## Related Modules
- **Depends on:** `aevum-crypto`
- **Used by:** `aevum-consensus`, `aevum-node`, `aevum-db`, `aevum-l2`, `aevum-settlement`
