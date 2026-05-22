use aevum::core::address::Address;
use aevum::core::block::Block;
use aevum::core::jt_utxo::JtUtxo;
use aevum::core::transaction::{Transaction, TxOutput};
use aevum::core::wire::{BlockWire, WireFormat};
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
    println!("Приватный ключ (m/0): {}", hex::encode(kp.private.to_bytes()));
    println!();

    let amount = 21_000_000 * 100_000_000;
    let blinding = [1u8; 32];
    let tag_blinding = [1u8; 32];

    let utxo = JtUtxo::new_global_clean(
        founder_public,
        amount,
        &blinding,
        &tag_blinding,
        0,
        0,
        Hash::zero(),
    ).expect("Genesis UTXO creation failed");

    let output = TxOutput::from_jt_utxo(&utxo, 0);
    let tx = Transaction::new(vec![], vec![output], 0);

    let genesis = Block::genesis(vec![tx]);

    // Сохраняем JSON (для чтения человеком)
    let genesis_json = serde_json::to_string_pretty(&genesis).unwrap();
    fs::write("genesis.json", &genesis_json).unwrap();
    println!("Генезис (JSON) сохранён в genesis.json");

    // Сохраняем Wire формат (для БД — никогда не меняется)
    let wire = BlockWire::from_core(&genesis).expect("Genesis wire conversion failed");
    let wire_bytes = bincode::serialize(&wire).expect("Genesis wire serialization failed");
    fs::write("genesis.wire", &wire_bytes).unwrap();
    println!("Генезис (Wire) сохранён в genesis.wire");

    // Верифицируем roundtrip
    let loaded = BlockWire::from_core(&genesis).unwrap();
    let back = loaded.to_core().unwrap();
    assert_eq!(genesis.block_hash, back.block_hash);
    assert_eq!(genesis.total_supply, back.total_supply);
    println!("✅ Wire roundtrip проверен — генезис валиден");

    let mnemonic_str = mnemonic.words.join(" ");
    fs::write("genesis_mnemonic.txt", &mnemonic_str).unwrap();
    println!("Мнемоника сохранена в genesis_mnemonic.txt");
}
