# Node Roles in Aevum — Proof of Service

Aevum uses a **four-level node role system** to reward participants based on their contribution to the network. The more value you provide, the higher your reward — and the stricter the verification.

---

## Role Levels

| Level | Role | Bonus | Verification | Queue | Who |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | **Light** | 0% (1.0x) | ❌ No | ✅ Yes | Regular users (PC/phones) |
| 2 | **Archive** | +10% (1.1x) | ✅ Yes (10 blocks) | ❌ No | Enthusiasts storing full history |
| 3 | **Full** | +12.5% (1.25x) | ✅ Yes (5 blocks) | ❌ No | Servers running a full Aevum node |
| 4 | **Bridge** | +15%+ (1.5x) | ✅ Yes (3 blocks) | ❌ No | Top servers running nodes of other blockchains |

---

## Detailed Description

### Level 1: Light (Presence)
- **Who:** Regular users (phones, PCs, laptops).
- **What they do:** Simply stay present in the network and send heartbeats.
- **Reward:** Base (1.0x).
- **Verification:** None (too many nodes to verify).
- **Queue:** Yes — each Light node gets a chance through rotation.

### Level 2: Archive (History)
- **Who:** Enthusiasts who store the full blockchain history.
- **What they do:** Store all historical blocks, help new nodes sync.
- **Reward:** +10% (1.1x).
- **Verification:** Yes — checked to ensure they really store history.
- **Queue:** No — always in the pool.

### Level 3: Full (Full Node)
- **Who:** Servers running a full Aevum node.
- **What they do:** Store full history, provide fast data access, participate in consensus, verify other nodes.
- **Reward:** +12.5% (1.25x).
- **Verification:** Yes — checked to ensure they actually run a full node.
- **Queue:** No — always in the pool.

### Level 4: Bridge (Cross-Chain)
- **Who:** Top servers running a full Aevum node **plus** nodes of other blockchains (Bitcoin, Ethereum, Solana, etc.).
- **What they do:** Everything a Full node does, plus enable bridge functionality, store state of other chains, allow Aevum to read and analyze transactions from other blockchains.
- **Reward:** +15% (1.5x) + bonus for each additional blockchain.
- **Verification:** Yes — checked to ensure they actually hold nodes of other networks.
- **Queue:** No — always in the pool.

---

## Verification Mechanism (Proof of Service)

Each node verifies other nodes. The higher the role, the more checks they perform.

| Role | Challenge Blocks | Pass Threshold |
| :--- | :--- | :--- |
| Archive | 10 blocks | 80% |
| Full | 5 blocks | 80% |
| Bridge | 3 blocks | 80% |

- **Verifiers per target:** 3
- **Targets per verifier:** 3

If a node fails verification:
- Its role is downgraded
- It loses part of its reward (or stake, if applicable)

---

## How It Works in an Epoch

1. All active nodes are collected.
2. Nodes are filtered by role:
   - Full / Archive / Bridge → sorted by reputation → top 20,000 selected.
   - Light → taken from the queue → top 80,000 selected.
3. Total participants are capped at 100,000.
4. Rewards are distributed **by weight** (role + reputation + checks).

---

## Related Constants (from `emission.rs` and `proof_of_service.rs`)

| Constant | Value | Description |
| :--- | :--- | :--- |
| `EPOCH_LENGTH_BLOCKS` | 288 | Epoch duration (~24 hours) |
| `MAX_EPOCH_PARTICIPANTS` | 100,000 | Max participants per epoch |
| `MAX_FULL_NODES` | 20,000 | Max Full/Archive/Bridge nodes |
| `MAX_LIGHT_NODES` | 80,000 | Max Light nodes |
| `ARCHIVE_SERVICE_BPS` | 1000 | Archive bonus (10%) |
| `FULL_SERVICE_BPS` | 1250 | Full node bonus (12.5%) |
| `BRIDGE_SERVICE_BPS` | 1500 | Bridge bonus (15%) |
| `PASS_THRESHOLD_PERCENT` | 80% | Minimum blocks to pass verification |

---

## What Makes This System Unique

1. **Fairness:** Light nodes get a chance through queue rotation.
2. **Meritocracy:** Higher roles earn more but are verified more strictly.
3. **Security:** Full and Bridge nodes are heavily checked, making attacks expensive.
4. **Usefulness:** Bridge nodes that hold other blockchains provide real infrastructure value.
5. **Self-cleaning:** Nodes that fail checks lose their role and rewards.

---

## Future Improvements

1. **Bridge bonus per blockchain:** Extra reward for each additional chain held.
2. **Role degradation:** Automatic downgrade if a node stops fulfilling its duties.
3. **Uptime monitoring:** Track availability for Full/Bridge nodes.
