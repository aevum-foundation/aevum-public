# Aevum Protocol — Public Repository

Layer-1 blockchain with jurisdictional tags (JT-UTXO), ZK privacy, and GPU mining for science.

## Quick Start (Miner)

```bash
git clone https://github.com/aevum-foundation/aevum-public.git
cd aevum-public
cargo build --release
./target/release/cli-wallet create-address
./target/release/aevum-node --miner-key YOUR_KEY --developer-address 0ffc25780ab973a85612aad6f0b7abb35bd3fd2222387de0364fd522f79c36e3 --bootstrap-peers 186.246.14.202:9733
```

What's Open Source Now

· Core blockchain (blocks, UTXO, PoH, mining)
· ATP — Aevum Transport Protocol (own P2P stack, zero libp2p)
· CLI wallet (balance, send, create-address)
· HTTP API (/health, /status, /tx)

What's Coming in 6 Months (Currently Closed)

· ZK Proof System — trustless verification
· Prisma Filter — jurisdictional awareness
· Science Engine — distributed GPU computing
· Governance Oracle — miner voting

Closed modules will be open-sourced when the network reaches 10,000+ miners — making forks meaningless.

Community

· Telegram: https://t.me/aevumchain
· Email: aevumaltcoin@gmail.com
