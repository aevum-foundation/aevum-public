use aevum::core::address::Address;
use aevum::core::block::Block;
use aevum::core::jt_utxo::JtUtxo;
use aevum::core::transaction::{Transaction, TxOutput};
use aevum::crypto::hash::Hash;
use aevum::wallet::Wallet;
use std::fs;

fn main() {
    let (wallet, mnemonic) = Wallet::new();
    let kp = wallet.derive_keypair(0);
    let founder_public = kp.public.clone();

    println!("Мнемоника основателя:");
    println!("{}", mnemonic.words.join(" "));
    println!();
    println!("Адрес основателя: {}", founder_public.to_hex());
    println!(
        "Приватный ключ (m/0): {}",
        hex::encode(kp.private.to_bytes())
    );
    println!();

    let amount = 21_000_000 * 100_000_000;
    let blinding = [0u8; 32];
    let tag_blinding = [0u8; 32];

    let utxo = JtUtxo::new_global_clean(
        founder_public,
        amount,
        &blinding,
        &tag_blinding,
        0,
        Hash::zero(),
    );
    let output = TxOutput::from_jt_utxo(&utxo);
    let tx = Transaction::new(vec![], vec![output], 0);

    let genesis = Block::genesis(vec![tx]);

    let genesis_json = serde_json::to_string_pretty(&genesis).unwrap();
    fs::write("genesis.json", &genesis_json).unwrap();

    let mnemonic_str = mnemonic.words.join(" ");
    fs::write("genesis_mnemonic.txt", &mnemonic_str).unwrap();
    println!("Генезис сохранён в genesis.json");
}
