use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use aevum::core::economics::Economics;
use aevum::crypto::keys::{PrivateKey, PublicKey};
use crate::mempool::Mempool;
use crate::storage::Storage;
use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{SyncContext, AtpMessage, create_status, flush_block_buffer};
use crate::p2p::noise::TofuStore;
use crate::p2p::dht_integration::DhtIntegration;
use crate::http_server::{SharedBalanceCache, SharedMetrics};
use std::sync::{Arc, Mutex as StdMutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::net::SocketAddr;
use tokio::sync::mpsc as tokio_mpsc;

const TICKS_PER_BLOCK: u64 = 30;
const MIN_PEERS: usize = 2;
const PEER_DISCOVERY_INTERVAL: u64 = 15;
const POH_SNAPSHOT_KEY: &str = "poh_snapshot";

pub struct ConnectCommand {
    pub addr: SocketAddr,
    pub our_key: PrivateKey,
    pub tofu: Arc<tokio::sync::Mutex<TofuStore>>,
    pub peers: Arc<PeersManager>,
    pub ctx: Arc<SyncContext>,
}

pub fn start(
    miner_key: PrivateKey,
    validator: Arc<StdMutex<Validator>>,
    mempool: Arc<StdMutex<Mempool>>,
    storage: Arc<StdMutex<Storage>>,
    developer_address: PublicKey,
    serial_counter: Arc<StdMutex<u64>>,
    peers: Arc<PeersManager>,
    sync_ctx: Arc<SyncContext>,
    network_height: Arc<StdMutex<u64>>,
    last_peer_discovery: Arc<StdMutex<Instant>>,
    our_key: PrivateKey,
    tofu: Arc<tokio::sync::Mutex<TofuStore>>,
    dht_integration: Arc<StdMutex<DhtIntegration>>,
    connect_tx: tokio_mpsc::UnboundedSender<ConnectCommand>,
    shutdown: Arc<AtomicBool>,
    balance_cache: SharedBalanceCache,
    metrics: SharedMetrics,
) {
    std::thread::spawn(move || {
        let genesis_requested = Arc::new(AtomicBool::new(false));
        let gr = genesis_requested.clone();

        while !shutdown.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));

            // Кешируем часто читаемые значения — меньше локаний
            let network_h = *network_height.lock().unwrap();
            let peer_count = peers.peer_count();

            // 1. Проверяем генезис ПЕРЕД метриками и майнингом
            {
                let val = validator.lock().unwrap();
                if !val.genesis_applied {
                    drop(val);
                    let st = storage.lock().unwrap();
                    if let Ok(Some(genesis)) = st.load_genesis_block(0) {
                        drop(st);
                        let mut v = validator.lock().unwrap();
                        let mut g = genesis.clone();
                        if v.validate_and_apply(&mut g).is_ok() {
                            v.last_block_hash = genesis.block_hash;
                            tracing::info!("[MINING] Genesis applied from local storage");
                        }
                        drop(v);
                        flush_block_buffer(&sync_ctx);
                    } else {
                        drop(st);
                        if peer_count > 0 && !gr.load(Ordering::SeqCst) {
                            gr.store(true, Ordering::SeqCst);
                            let req = AtpMessage::HeaderRequest { from: 0, to: 0 };
                            if let Ok(data) = bincode::serialize(&req) { peers.broadcast(data); }
                            tracing::info!("[MINING] Genesis requested from peers");
                        }
                    }
                    continue;
                }
            }

            // 2. Обновляем метрики (только после genesis_applied)
            {
                let val = validator.lock().unwrap();
                let our_h = val.last_block_height();
                let synced = our_h >= network_h;
                let mempool_len = mempool.lock().unwrap().len();
                metrics.update(
                    our_h, val.utxo_set().total_supply(), network_h,
                    peer_count, val.utxo_set().len(), mempool_len,
                    val.poh().current_tick_number(), synced,
                );
                drop(val);
            }

            // 3. Peer discovery если мало пиров
            if peer_count < MIN_PEERS && last_peer_discovery.lock().unwrap().elapsed().as_secs() > PEER_DISCOVERY_INTERVAL {
                *last_peer_discovery.lock().unwrap() = Instant::now();
                let candidates = dht_integration.lock().unwrap().get_bootstrap_candidates();
                if !candidates.is_empty() {
                    for addr in &candidates {
                        if peers.can_connect_to(addr) {
                            peers.mark_connecting(*addr);
                            let _ = connect_tx.send(ConnectCommand {
                                addr: *addr, our_key: our_key.clone(), tofu: tofu.clone(),
                                peers: peers.clone(), ctx: sync_ctx.clone(),
                            });
                        }
                    }
                } else if let Ok(addr) = "186.246.14.202:9733".parse::<SocketAddr>() {
                    if peers.can_connect_to(&addr) {
                        peers.mark_connecting(addr);
                        let _ = connect_tx.send(ConnectCommand {
                            addr, our_key: our_key.clone(), tofu: tofu.clone(),
                            peers: peers.clone(), ctx: sync_ctx.clone(),
                        });
                    }
                }
            }

            // 4. Ждём синхронизации перед майнингом
            let our_h = validator.lock().unwrap().last_block_height();
            if peer_count > 0 && our_h < network_h {
                continue;
            }

            // 5. Майнинг
            let mut val = validator.lock().unwrap();
            let mut mem = mempool.lock().unwrap();
            val.tick_poh();
            let poh = val.poh().current_tick_number();
            let active_miners = peer_count.max(1) as u64;
            let target_ticks = TICKS_PER_BLOCK.saturating_sub((active_miners / 10).min(TICKS_PER_BLOCK - 10));
            let should_mine = (poh % target_ticks == 0 || !mem.is_empty())
                && (peer_count == 0 || val.last_block_height() >= network_h);
            let txs_backup = if should_mine { mem.take_batch(100) } else { vec![] };
            let height = val.last_block_height() + 1;
            drop(mem); drop(val);

            if should_mine {
                let mut val = validator.lock().unwrap();
                let mut st = storage.lock().unwrap();
                let supply = val.utxo_set().total_supply();
                let mut txs = txs_backup.clone();
                let total_fees: u64 = txs.iter().map(|tx| {
                    let a: u64 = tx.outputs.iter().map(|o| o.amount).sum();
                    if a > 0 { Economics::calculate_fee(a).0 } else { 0 }
                }).sum();
                let mut serial = serial_counter.lock().unwrap();
                *serial += 2;
                let coinbase = Economics::create_coinbase(&miner_key.public_key(), height, total_fees, &developer_address, *serial, poh);
                drop(serial);
                txs.insert(0, coinbase);
                let mut block = Block::new(
                    val.last_block_hash(), height, poh, poh + TICKS_PER_BLOCK, txs,
                    val.utxo_set().get_state_root(), supply + Economics::block_reward_satoshi(height) + total_fees, None,
                );
                match val.validate_and_apply(&mut block) {
                    Ok(_) => {
                        st.save_genesis_block(&block).ok();
                        st.save_utxo_set(val.utxo_set()).ok();
                        let _ = bincode::serialize(&val.poh_snapshot())
                            .ok()
                            .and_then(|s| st.save_metadata(POH_SNAPSHOT_KEY, &s).ok());
                        {
                            let mut nnh = network_height.lock().unwrap();
                            if height > *nnh { *nnh = height; }
                        }
                        drop(val); drop(st);
                        if let Ok(mut orch) = sync_ctx.orchestrator.lock() {
                            let mut v = validator.lock().unwrap();
                            let mut s = storage.lock().unwrap();
                            let _ = orch.process_chain(&mut v, &mut s);
                        }
                        let status = create_status(&sync_ctx);
                        if let Ok(data) = bincode::serialize(&status) { peers.broadcast(data); }
                        tracing::info!("⛏️  Mined block {}", height);
                        let miner_hex = hex::encode(miner_key.public_key().to_bytes());
                        let coinbase_amount: u64 = block.transactions[0].outputs.iter().map(|o| o.amount).sum();
                        if let Ok(mut cache) = balance_cache.lock() {
                            cache.add_reward(&miner_hex, coinbase_amount);
                        }
                    }
                    Err(_) => {
                        drop(val); drop(st);
                        let mut mem = mempool.lock().unwrap();
                        for tx in txs_backup { mem.insert(tx).ok(); }
                    }
                }
            }
        }
    });
}
