use aevum::core::address::{AcceptancePolicy, AcceptanceRule, Address};
use aevum::core::jt_utxo::{JtUtxo, RestrictionLevel};
use aevum::core::transaction::{Transaction, TxInput, TxOutput};
use aevum::core::state::UtxoSet;
use aevum::crypto::keys::{PrivateKey, PublicKey, Keypair};
use aevum::crypto::hash::{AmountCommitment, Hash, TagCommitment};
use aevum::wallet::{Wallet, Mnemonic};
use aevum_node::storage::Storage;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("Aevum CLI Wallet v0.3");
        println!("  balance --address АДРЕС --db ПУТЬ");
        println!("  send --from KEY --to АДРЕС --amount СУММА --db ПУТЬ");
        println!("  create-address");
        println!("  export-key --mnemonic '12 слов'");
        println!("  import --mnemonic '12 слов'");
        println!("  genesis-key");
        println!("  utxos --db ПУТЬ");
        return Ok(());
    }

    let db_path = args.iter().position(|a| a == "--db").and_then(|i| args.get(i+1)).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("./aevum_mainnet.db"));

    match args[1].as_str() {
        "balance" => {
            let addr_hex = args.iter().position(|a| a == "--address").and_then(|i| args.get(i+1)).expect("--address required");
            let storage = Storage::open(&db_path)?;
            let utxo_set = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
            let bytes = hex::decode(addr_hex)?;
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
            let pubkey = PublicKey::from_bytes(arr)?;
            let mut count = 0u64;
            let mut total: u64 = 0;
            for (_, utxo) in utxo_set.all() {
                if utxo.owner().to_bytes() == pubkey.to_bytes() {
                    count += 1;
                    total += utxo.amount;
                }
            }
            println!("Баланс: {:.8} AEV ({} UTXO)", total as f64 / 100_000_000.0, count);
        }

        "send" => {
            let from_hex = args.iter().position(|a| a == "--from").and_then(|i| args.get(i+1)).expect("--from required");
            let to_hex = args.iter().position(|a| a == "--to").and_then(|i| args.get(i+1)).expect("--to required");
            let amount_str = args.iter().position(|a| a == "--amount").and_then(|i| args.get(i+1)).expect("--amount required");
            let amount_f: f64 = amount_str.parse()?;
            let amount: u64 = (amount_f * 100_000_000.0) as u64;

            let from_bytes = hex::decode(from_hex)?;
            let mut from_arr = [0u8; 32]; from_arr.copy_from_slice(&from_bytes[..32]);
            let from_key = PrivateKey::from_bytes(from_arr)?;
            let from_public = from_key.public_key();

            let to_bytes = hex::decode(to_hex)?;
            let mut to_arr = [0u8; 32]; to_arr.copy_from_slice(&to_bytes[..32]);
            let to_public = PublicKey::from_bytes(to_arr)?;

            let storage = Storage::open(&db_path)?;
            let utxo_set = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());

            let mut input_nullifier = Hash::zero();
            let mut input_tx_hash = Hash::zero();
            let mut input_amount: u64 = 0;
            let mut found = false;
            for (nullifier, utxo) in utxo_set.all() {
                if utxo.owner().to_bytes() == from_public.to_bytes() {
                    input_nullifier = *nullifier;
                    input_tx_hash = utxo.tx_hash;
                    input_amount = utxo.amount;
                    found = true;
                    break;
                }
            }
            if !found { panic!("Нет UTXO для отправки."); }

            let input = TxInput {
                tx_hash: input_tx_hash, output_index: 0, nullifier: input_nullifier,
                signature: vec![], public_key: from_public.clone(), signed_hash: Hash::zero(), nonce: 0,
            };

            let to_utxo = JtUtxo::new_global_clean(to_public.clone(), amount, &[0u8; 32], &[0u8; 32], 200, Hash::zero());
            let output1 = TxOutput::from_jt_utxo(&to_utxo);

            let change_amount = input_amount.saturating_sub(amount);
            let change_utxo = JtUtxo::new_global_clean(from_public.clone(), change_amount, &[0u8; 32], &[0u8; 32], 201, Hash::zero());
            let output2 = TxOutput::from_jt_utxo(&change_utxo);

            let mut tx = Transaction::new(vec![input], vec![output1, output2], 0);
            let signature = from_key.sign(tx.tx_hash.as_bytes());
            tx.sign_input(&input_tx_hash, 0, signature.to_vec(), from_public)?;

            let tx_json = serde_json::to_string(&tx)?;
            std::fs::write("signed_tx.json", &tx_json)?;
            println!("Транзакция создана: {}", tx.tx_hash.to_hex());
            println!("Отправьте: curl -X POST http://127.0.0.1:19734/tx -d @signed_tx.json");
        }

        "create-address" => {
            let (wallet, mnemonic) = Wallet::new();
            let addr = wallet.create_address(&AcceptancePolicy::AcceptAll);
            let kp = wallet.derive_keypair(0);
            println!("Мнемоника: {}", mnemonic.words.join(" "));
            println!("Мнемоника: {}", mnemonic.words.join(" "));
            println!("Адрес (m/0): {}", kp.public.to_hex());
        }

        "export-key" => {
            let mnemonic_str = args.iter().position(|a| a == "--mnemonic").and_then(|i| args.get(i+1)).expect("--mnemonic required");
            let words: Vec<String> = mnemonic_str.split_whitespace().map(|s| s.to_string()).collect();
            let mnemonic = Mnemonic { words };
            let seed = mnemonic.to_seed("");
            let wallet = Wallet::from_seed(&seed);
            let kp = wallet.derive_keypair(0);
            println!("Приватный ключ (m/0): {}", hex::encode(kp.private.to_bytes()));
            println!("Публичный ключ: {}", kp.public.to_hex());
        }

        "import" => {
            let mnemonic_str = args.iter().position(|a| a == "--mnemonic").and_then(|i| args.get(i+1)).expect("--mnemonic required");
            let words: Vec<String> = mnemonic_str.split_whitespace().map(|s| s.to_string()).collect();
            let mnemonic = Mnemonic { words };
            let seed = mnemonic.to_seed("");
            let wallet = Wallet::from_seed(&seed);
            println!("Адрес: {}", wallet.public_key().to_hex());
        }

        "genesis-key" => {
            let (wallet, mnemonic) = Wallet::new();
            let kp = wallet.derive_keypair(0);
            println!("Мнемоника: {}", mnemonic.words.join(" "));
            println!("Приватный ключ: {}", hex::encode(kp.private.to_bytes()));
            println!("Публичный ключ: {}", kp.public.to_hex());
        }

        "utxos" => {
            let storage = Storage::open(&db_path)?;
            let utxo_set = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
            println!("Всего UTXO: {}", utxo_set.len());
            for (nullifier, utxo) in utxo_set.all() {
                println!("  {} -> {} ({} AEV)", hex::encode(nullifier.as_bytes()), hex::encode(utxo.owner().to_bytes()), utxo.amount as f64 / 100_000_000.0);
            }
        }
        _ => println!("Неизвестная команда"),
    }
    Ok(())
}
