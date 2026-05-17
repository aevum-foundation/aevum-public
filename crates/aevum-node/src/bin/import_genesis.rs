use aevum::core::block::Block;
use aevum::core::jt_utxo::JtUtxo;
use aevum_node::storage::Storage;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let genesis_json = std::fs::read_to_string("genesis.json")?;
    let genesis: Block = serde_json::from_str(&genesis_json)?;
    let db_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "./aevum.db".to_string());
    let mut storage = Storage::open(&PathBuf::from(&db_path))?;
    storage.save_block(&genesis)?;

    // Сохраняем UTXO из генезис-транзакций
    let mut utxo_set = aevum::core::state::UtxoSet::new();
    for tx in &genesis.transactions {
        for output in &tx.outputs {
            let utxo = JtUtxo::from_tx_output(output, tx.tx_hash);
            utxo_set.add(utxo);
        }
    }
    storage.save_utxo_set(&utxo_set)?;

    println!(
        "Genesis imported at height {} with {} UTXOs",
        genesis.height,
        utxo_set.len()
    );
    Ok(())
}
