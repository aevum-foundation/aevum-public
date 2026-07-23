# Proof of Presence — Aevum Reward System

## Concept
Aevum uses **Proof of Presence** instead of Proof of Work or Proof of Stake. Participants are rewarded not for hash rate or staking, but for **being present** in the network and sending regular **heartbeat** messages.

This is an energy-efficient and decentralized approach that incentivizes participants to keep nodes online, ensuring network reliability and liveness.

---

## Core Components
| Component | File | Role |
| :--- | :--- | :--- |
| **UptimeManager** | `crates/aevum-node/src/miner_uptime.rs` | Tracks node activity, manages Light-node queue |
| **MiningLoop** | `crates/aevum-node/src/mining_loop.rs` | Distributes rewards at the end of each epoch |
| **emission.rs** | `crates/aevum/src/emission.rs` | Contains economic constants |

---

## Algorithm Workflow

### 1. Presence Tracking (UptimeManager)

- Each miner / node sends a **heartbeat** every ~5 minutes (each block).
- A node is considered **active** if its heartbeat was received within the last **300 ticks** (~25 minutes).
- All active nodes are divided into two categories:
  - **Full nodes** — participate in rewards immediately.
  - **Light nodes** — join a queue.
- The Light-node queue rotates: each node gets a chance to receive rewards, ensuring fairness.

### 2. Participant Collection (MiningLoop)

Every **288 blocks (~24 hours)** an epoch ends:

1.  `recover_participants()` is called to collect the list of active nodes.
2.  Then `select_epoch_participants()` forms the final list:
    - **Full nodes** — up to **20%** of total slots.
    - **Light nodes** — **10%** reserved, the rest are filled from the queue.
3.  The total number of epoch participants is capped at **100,000** (`MAX_EPOCH_PARTICIPANTS`).

### 3. Reward Distribution

- The epoch reward (`epoch_reward`) is split **equally** among all participants.
- Any remainder (dust) from the division is sent to the **Founder address**.
- Distribution occurs in **batches of 10,000 outputs per block** to avoid network overload.
- If the number of participants exceeds the reward, the reward per participant may be less than 1 satoshi — in this case, it is not paid out, and the entire amount goes to the founder.

### 4. Example

Currently, the network has **4 servers**. All are active and sending heartbeats. At the end of the epoch:
- `recover_participants()` finds 4 active nodes.
- `select_epoch_participants()` includes them in the list.
- `epoch_reward` is divided into 4 equal shares.
- All 4 servers receive the same reward.

---

## Self-Check Questions

1.  **How often is node activity checked?** — every 5 minutes (each block).
2.  **What counts as an active node?** — a node that sent a heartbeat within the last 300 ticks (~25 minutes).
3.  **How are participants accumulated for the epoch?** — the Light-node queue rotates, giving each a chance.
4.  **What is the maximum number of epoch participants?** — 100,000.
5.  **What happens to the division remainder?** — it goes to the Founder address.
6.  **Why batches of 10,000 outputs?** — to prevent network congestion during reward distribution.

---

## Related Constants (from `emission.rs`)

| Constant | Value | Description |
| :--- | :--- | :--- |
| `EPOCH_LENGTH_BLOCKS` | 288 | Epoch duration in blocks (~24 hours) |
| `MAX_EPOCH_PARTICIPANTS` | 100,000 | Maximum participants per epoch |
| `GENESIS_SUPPLY_SAT` | 21,000,000 * 1e8 | Initial supply |
| `INITIAL_REWARD_SAT` | 200 * 1e8 | Initial block reward |
| `HALVING_INTERVAL` | 867,240 | Halving interval |
