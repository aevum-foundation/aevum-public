# aevum-consensus — Consensus & Epoch Engine

## Module Responsibility
`aevum-consensus` implements the **Proof of Presence** mechanism and manages the epoch-based reward distribution. It defines how nodes prove their online presence, how epochs are formed, and how rewards are distributed among participants.

## Key Components
- **`poh_generator.rs`** — Proof of History tick generation.
- **`validator.rs`** — Block validation logic.
- **`verifier.rs`** — Structural and consensus verification.
- **`execution_contract.rs`** — 8-stage block execution pipeline.
- **`rules/`** — Formal validation rules (heartbeat, coinbase, PoH, supply).
- **`trust.rs`** — Delegate trust model for bootstrap nodes.
- **`dos_protection.rs`** — Rate limiting and circuit breaker for DoS attacks.

## Interaction with Other Modules
- **Uses** `aevum-core` for block and transaction structures.
- **Uses** `aevum-db` to load state for verification.
- **Used by** `aevum-node` to validate blocks during sync and mining.

## Public Interfaces (Overview)
- Block validation pipeline (`validate_block_structural`, `validate_block_full`).
- PoH tick generation and verification.
- Epoch-based reward distribution logic.

## Uniqueness for Aevum
This module implements Aevum's core innovation: **Proof of Presence**. Instead of PoW or PoS, rewards are based on node presence in the network, making the system fair and energy-efficient.

## Related Modules
- **Depends on:** `aevum-core`, `aevum-crypto`
- **Used by:** `aevum-node`, `aevum-mining-loop`
