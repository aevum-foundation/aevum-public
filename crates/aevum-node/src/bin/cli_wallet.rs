use aevum::core::jt_utxo::{JtUtxo, CATEGORY_MASK, CAT_GLOBAL, CAT_COINBASE, CAT_JURISDICTION, CAT_COMPUTE, is_coinbase};
use aevum::core::transaction::{Transaction, TxInput, TxOutput};
use aevum::core::state::UtxoSet;
use aevum::crypto::keys::{PrivateKey, PublicKey};
use aevum::crypto::hash::Hash;
use aevum::wallet::{Wallet, Mnemonic};
use aevum_node::storage::Storage;
use std::io::Write;
use std::path::PathBuf;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::collections::HashMap;
use rand::Rng;
use sha2::{Sha256, Digest};

const FEE_PER_TX_DEFAULT: u64 = 100;
const COINBASE_MATURITY_DEFAULT: u64 = 100;

fn main() {
    if let Err(e) = run() {
        eprintln!("Ошибка: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { print_help(); return Ok(()); }

    let db_path = args.iter().position(|a| a == "--db")
        .and_then(|i| args.get(i + 1)).map(PathBuf::from)
        .unwrap_or_else(|| { eprintln!("--db не указан, используется ./aevum.db"); PathBuf::from("./aevum.db") });

    match args[1].as_str() {
        "balance" => cmd_balance(&args, &db_path)?,
        "send" => cmd_send(&args, &db_path)?,
        "create-address" => cmd_create_address()?,
        "export-key" => cmd_export_key(&args)?,
        "import" => cmd_import(&args)?,
        "encrypt-key" => cmd_encrypt_key(&args)?,
        "decrypt-key" => cmd_decrypt_key(&args)?,
        "genesis-info" => cmd_genesis_info(&args, &db_path)?,
        "compute-status" => cmd_compute_status(&args, &db_path)?,
        "utxos" => cmd_utxos(&args, &db_path)?,
        "help" | "--help" | "-h" => print_help(),
        _ => { eprintln!("Неизвестная команда: {}", args[1]); print_help(); }
    }
    Ok(())
}

fn print_help() {
    println!("Aevum CLI Wallet v0.6");
    println!("Команды:");
    println!("  balance --address <АДРЕС> --db <ПУТЬ>");
    println!("  send --from-key-file <ФАЙЛ> --to <АДРЕС> --amount <СУММА> [--dry-run] --db <ПУТЬ>");
    println!("  create-address");
    println!("  export-key --mnemonic '<12 слов>'");
    println!("  import --mnemonic '<12 слов>'");
    println!("  encrypt-key --key-file <ФАЙЛ> --password <ПАРОЛЬ>");
    println!("  decrypt-key --encrypted-file <ФАЙЛ> --password <ПАРОЛЬ>");
    println!("  genesis-info --db <ПУТЬ>");
    println!("  compute-status --address <АДРЕС> --db <ПУТЬ>");
    println!("  utxos [--address <АДРЕС>] [--limit N] [--offset M] --db <ПУТЬ>");
    println!("  help");
    eprintln!("\n⚠️  Используйте --from-key-file для безопасной отправки.");
}

fn parse_hex_arg(args: &[String], name: &str) -> Result<[u8; 32], String> {
    let hex_str = args.iter().position(|a| a == name).and_then(|i| args.get(i + 1))
        .ok_or_else(|| format!("--{} required", name.trim_start_matches('-')))?;
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex for {}: {}", name, e))?;
    if bytes.len() < 32 { return Err(format!("{} must be 32 bytes", name)); }
    let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
    Ok(arr)
}

fn parse_optional_u64(args: &[String], name: &str) -> Option<u64> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|s| s.parse().ok())
}

fn validate_public_key(bytes: &[u8; 32], label: &str) -> Result<PublicKey, String> {
    PublicKey::from_bytes(*bytes).map_err(|_| format!("Invalid {}: точка не на кривой Ed25519", label))
}

fn read_secret(prompt: &str) -> Result<String, String> {
    eprint!("{}", prompt); std::io::stderr().flush().map_err(|e| e.to_string())?;
    #[cfg(unix)] {
        use std::io::Read;
        let mut termios = termios::Termios::from_fd(0).map_err(|e| format!("termios: {}", e))?;
        let old = termios;
        termios.c_lflag &= !(termios::ECHO | termios::ECHONL);
        termios::tcsetattr(0, termios::TCSANOW, &termios).map_err(|e| format!("tcsetattr: {}", e))?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        termios::tcsetattr(0, termios::TCSANOW, &old).ok();
        eprintln!();
        Ok(input)
    }
    #[cfg(not(unix))] {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        Ok(input)
    }
}

fn random_blinding() -> [u8; 32] {
    let mut rng = rand::thread_rng();
    let mut blinding = [0u8; 32];
    rng.fill(&mut blinding);
    blinding
}

fn get_next_serial(storage: &Storage) -> Result<u64, Box<dyn std::error::Error>> {
    let serial = storage.load_metadata("utxo_serial")?
        .and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(0);
    let next = serial + 1;
    storage.save_metadata("utxo_serial", &bincode::serialize(&next)?)?;
    Ok(next)
}

fn get_next_nonce(storage: &Storage, pubkey: &PublicKey) -> Result<u64, Box<dyn std::error::Error>> {
    let key = format!("nonce_{}", hex::encode(pubkey.to_bytes()));
    let nonce = storage.load_metadata(&key)?
        .and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(0);
    let next = nonce + 1;
    storage.save_metadata(&key, &bincode::serialize(&next)?)?;
    Ok(next)
}

fn get_chain_id(storage: &Storage) -> u32 {
    storage.load_metadata("chain_id").ok().flatten()
        .and_then(|d| bincode::deserialize::<u32>(&d).ok()).unwrap_or(2)
}

fn get_maturity(storage: &Storage) -> u64 {
    storage.load_metadata("coinbase_maturity").ok().flatten()
        .and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(COINBASE_MATURITY_DEFAULT)
}

fn get_fee_per_tx(storage: &Storage) -> u64 {
    storage.load_metadata("fee_per_tx").ok().flatten()
        .and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(FEE_PER_TX_DEFAULT)
}

/// Шифрование ключа: 100 000x SHA256(salt + password) XOR key + 4 байта checksum. 0 зависимостей.
fn encrypt_key(key_bytes: &[u8; 32], password: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill(&mut salt);
    
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&salt);
    let mut derived = hasher.finalize();
    for _ in 0..100_000 { derived = Sha256::digest(&derived); }
    
    let mut encrypted = [0u8; 32];
    for i in 0..32 { encrypted[i] = key_bytes[i] ^ derived[i]; }
    
    // Checksum = SHA256(encrypted[..28])[..4]
    let checksum = Sha256::digest(&encrypted[..28]);
    
    // Формат: [salt 32B][encrypted 32B][checksum 4B] = 68 байт
    let mut output = Vec::with_capacity(68);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&encrypted);
    output.extend_from_slice(&checksum[..4]);
    Ok(output)
}

/// Расшифровка ключа: те же 100 000x SHA256 + XOR + проверка checksum
fn decrypt_key(encrypted: &[u8], password: &str) -> Result<[u8; 32], String> {
    if encrypted.len() < 68 { return Err("Неверный формат зашифрованного ключа".into()); }
    let salt: [u8; 32] = encrypted[..32].try_into().map_err(|_| "Invalid salt")?;
    let ciphertext: [u8; 32] = encrypted[32..64].try_into().map_err(|_| "Invalid ciphertext")?;
    let stored_checksum: [u8; 4] = encrypted[64..68].try_into().map_err(|_| "Invalid checksum")?;
    
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&salt);
    let mut derived = hasher.finalize();
    for _ in 0..100_000 { derived = Sha256::digest(&derived); }
    
    let mut key = [0u8; 32];
    for i in 0..32 { key[i] = ciphertext[i] ^ derived[i]; }
    
    // Проверка checksum
    let computed_checksum = Sha256::digest(&key[..28]);
    if computed_checksum[..4] != stored_checksum {
        return Err("Неверный пароль или файл повреждён".into());
    }
    
    Ok(key)
}

fn load_private_key(args: &[String]) -> Result<PrivateKey, String> {
    if let Some(pos) = args.iter().position(|a| a == "--from-key-file") {
        let path = args.get(pos + 1).ok_or("--from-key-file requires a path")?;
        let content = std::fs::read_to_string(path).map_err(|e| format!("Cannot read key file {}: {}", path, e))?;
        let hex_str = content.trim();
        if hex_str.len() == 64 && hex_str.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
            return PrivateKey::from_bytes(arr).map_err(|_| "Invalid private key in file".to_string());
        } else {
            let password = read_secret("Пароль для расшифровки ключа: ")?;
            let encrypted = hex::decode(hex_str).map_err(|_| "Invalid encrypted key format")?;
            let key_bytes = decrypt_key(&encrypted, password.trim())?;
            return PrivateKey::from_bytes(key_bytes).map_err(|_| "Invalid private key after decryption".to_string());
        }
    }
    if let Some(pos) = args.iter().position(|a| a == "--from-key") {
        eprintln!("⚠️  ПРИВАТНЫЙ КЛЮЧ В КОМАНДНОЙ СТРОКЕ — НЕБЕЗОПАСНО!");
        let hex_str = args.get(pos + 1).ok_or("--from-key requires a hex key")?;
        let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
        let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
        return PrivateKey::from_bytes(arr).map_err(|_| "Invalid private key".to_string());
    }
    let input = read_secret("Приватный ключ (hex): ")?;
    let bytes = hex::decode(input.trim()).map_err(|e| format!("Invalid hex: {}", e))?;
    let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
    PrivateKey::from_bytes(arr).map_err(|_| "Invalid private key".to_string())
}

fn utxo_type_tag(level: u64) -> &'static str {
    match level & CATEGORY_MASK {
        CAT_GLOBAL => "🟢 GLOBAL",
        CAT_COINBASE => "⛏️  COINBASE",
        CAT_JURISDICTION => "🏛️  JURISDICTION",
        CAT_COMPUTE => "🧬 COMPUTE",
        _ => "❓ UNKNOWN",
    }
}

fn cmd_encrypt_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let key_file = args.iter().position(|a| a == "--key-file").and_then(|i| args.get(i + 1)).ok_or("--key-file required")?;
    let password = read_secret("Пароль для шифрования: ")?;
    let confirm = read_secret("Повторите пароль: ")?;
    if password != confirm { return Err("Пароли не совпадают".into()); }
    
    let hex_str = std::fs::read_to_string(key_file)?.trim().to_string();
    let bytes = hex::decode(&hex_str).map_err(|_| "Invalid hex key in file")?;
    if bytes.len() < 32 { return Err("Key must be 32 bytes".into()); }
    let mut key_bytes = [0u8; 32]; key_bytes.copy_from_slice(&bytes[..32]);
    
    let encrypted = encrypt_key(&key_bytes, password.trim())?;
    let enc_file = key_file.to_string() + ".enc";
    std::fs::write(&enc_file, hex::encode(&encrypted))?;
    #[cfg(unix)] std::fs::set_permissions(&enc_file, Permissions::from_mode(0o600))?;
    println!("Ключ зашифрован: {}", enc_file);
    Ok(())
}

fn cmd_decrypt_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let enc_file = args.iter().position(|a| a == "--encrypted-file").and_then(|i| args.get(i + 1)).ok_or("--encrypted-file required")?;
    let password = read_secret("Пароль: ")?;
    
    let hex_str = std::fs::read_to_string(enc_file)?.trim().to_string();
    let encrypted = hex::decode(&hex_str).map_err(|_| "Invalid encrypted file")?;
    let key_bytes = decrypt_key(&encrypted, password.trim())?;
    
    let out_file = enc_file.replace(".enc", ".dec");
    std::fs::write(&out_file, hex::encode(key_bytes))?;
    #[cfg(unix)] std::fs::set_permissions(&out_file, Permissions::from_mode(0o600))?;
    println!("Ключ расшифрован: {}", out_file);
    Ok(())
}

fn cmd_balance(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr_bytes = parse_hex_arg(args, "--address")?;
    let pubkey = validate_public_key(&addr_bytes, "адрес")?;
    let storage = Storage::open(db_path)?;
    let utxo_set = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let current_height = storage.max_height()?.unwrap_or(0);
    let maturity = get_maturity(&storage);

    let mut global_clean: u64 = 0;
    let mut jurisdiction_tagged: HashMap<String, u64> = HashMap::new();
    let mut pending_maturity: u64 = 0;
    let mut compute_rewards: u64 = 0;
    let mut total_available: u64 = 0;
    let mut count = 0u64;

    for (_nullifier, utxo) in utxo_set.all() {
        if utxo.owner().to_bytes() != pubkey.to_bytes() { continue; }
        let amount = utxo.amount();
        let level = utxo.restriction_level();
        count += 1;

        if is_coinbase(level) && !utxo.is_spendable(current_height, maturity) {
            pending_maturity += amount;
        } else {
            total_available += amount;
            if is_coinbase(level) {
                global_clean += amount;
            } else if level & CATEGORY_MASK == CAT_JURISDICTION {
                let tag = format!("🏛️  Jurisdiction 0x{:03X}", level & 0xFF);
                *jurisdiction_tagged.entry(tag).or_insert(0) += amount;
            } else if level & CATEGORY_MASK == CAT_COMPUTE {
                compute_rewards += amount;
            } else {
                global_clean += amount;
            }
        }
    }

    println!("Баланс: {:.8} AEV", (total_available + pending_maturity) as f64 / 100_000_000.0);
    println!("├─ 🟢 Глобальные (чистые):     {:.8} AEV", global_clean as f64 / 100_000_000.0);
    for (tag, amount) in &jurisdiction_tagged {
        println!("├─ {}:        {:.8} AEV", tag, *amount as f64 / 100_000_000.0);
    }
    if compute_rewards > 0 {
        println!("├─ ⛏️  Награды за вычисления:  {:.8} AEV", compute_rewards as f64 / 100_000_000.0);
    }
    if pending_maturity > 0 {
        println!("├─ 🔒 В ожидании (maturity):   {:.8} AEV", pending_maturity as f64 / 100_000_000.0);
    }
    println!("└─ Доступно для траты:        {:.8} AEV", total_available as f64 / 100_000_000.0);
    println!("Всего UTXO: {}", count);
    Ok(())
}

fn cmd_send(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let is_dry_run = args.iter().any(|a| a == "--dry-run");
    let from_key = load_private_key(args)?;
    let from_public = from_key.public_key();
    let to_bytes = parse_hex_arg(args, "--to")?;
    let to_public = validate_public_key(&to_bytes, "адрес назначения")?;
    let amount_str = args.iter().position(|a| a == "--amount").and_then(|i| args.get(i + 1)).ok_or("--amount required")?;
    let amount_f: f64 = amount_str.parse().map_err(|_| "Invalid amount")?;
    if amount_f <= 0.0 { return Err("Amount must be positive".into()); }
    let amount: u64 = (amount_f * 100_000_000.0) as u64;

    let storage = Storage::open(db_path)?;
    let utxo_set = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let current_height = storage.max_height()?.unwrap_or(0);
    let chain_id = get_chain_id(&storage);
    let maturity = get_maturity(&storage);
    let fee_per_tx = get_fee_per_tx(&storage);
    let serial = get_next_serial(&storage)?;
    let nonce = get_next_nonce(&storage, &from_public)?;

    if to_public.to_bytes() == from_public.to_bytes() {
        eprintln!("⚠️  ВНИМАНИЕ: Вы отправляете средства НА СВОЙ СОБСТВЕННЫЙ АДРЕС!");
        eprintln!("    Комиссия {:.8} AEV будет потрачена впустую.", fee_per_tx as f64 / 100_000_000.0);
        eprint!("    Продолжить? [y/N]: ");
        std::io::stderr().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).ok();
        if !answer.trim().to_lowercase().starts_with('y') {
            return Err("Отменено пользователем".into());
        }
    }

    let mut best_utxo: Option<(Hash, Hash, u64, usize, u64)> = None;
    let mut best_excess: u64 = u64::MAX;
    let total_needed = amount + fee_per_tx;

    for (_nullifier, utxo) in utxo_set.all() {
        if utxo.owner().to_bytes() != from_public.to_bytes() { continue; }
        if !utxo.is_spendable(current_height, maturity) { continue; }
        if utxo.amount() >= total_needed {
            let excess = utxo.amount() - total_needed;
            if excess < best_excess {
                best_excess = excess;
                best_utxo = Some((*utxo.nullifier(), *utxo.tx_hash(), utxo.amount(), utxo.output_index(), utxo.restriction_level()));
                if excess == 0 { break; }
            }
        }
    }

    let (input_nullifier, input_tx_hash, input_amount, output_index, restriction_level) =
        best_utxo.ok_or_else(|| format!("Нет UTXO с достаточным балансом (нужно {:.8} AEV + комиссия {:.8})",
            amount as f64 / 100_000_000.0, fee_per_tx as f64 / 100_000_000.0))?;

    let change = input_amount.saturating_sub(total_needed);

    let outputs_sum = amount + change;
    if input_amount != outputs_sum + fee_per_tx {
        return Err(format!(
            "❌ БАГ: Баланс не сходится! Входы: {} != выходы: {} + комиссия: {}. Транзакция не создана.",
            input_amount, outputs_sum, fee_per_tx
        ).into());
    }

    println!("Выбран UTXO:");
    println!("├─ Сумма:      {:.8} AEV", input_amount as f64 / 100_000_000.0);
    println!("├─ Тип:        {}", utxo_type_tag(restriction_level));
    println!("├─ Комиссия:   {:.8} AEV", fee_per_tx as f64 / 100_000_000.0);
    println!("├─ К отправке: {:.8} AEV", amount as f64 / 100_000_000.0);
    if change > 0 { println!("├─ Сдача:      {:.8} AEV", change as f64 / 100_000_000.0); }
    else { println!("├─ Сдача:      0 (точное совпадение)"); }
    println!("├─ Nonce:      {}", nonce);
    println!("├─ Chain ID:   {}", chain_id);
    println!("└─ Совместимость: ✅ Глобальные монеты принимаются всеми");

    if is_dry_run {
        println!("\n🔍 Dry-run: транзакция НЕ создана. Для отправки уберите --dry-run.");
        return Ok(());
    }

    let input = TxInput {
        tx_hash: input_tx_hash, output_index: output_index as u32, nullifier: input_nullifier,
        signature: vec![], public_key: from_public.clone(), signed_hash: Hash::zero(), nonce,
    };

    let change_serial = if change > 0 { get_next_serial(&storage)? } else { 0 };
    let to_utxo = JtUtxo::new_global_clean(to_public.clone(), amount, &random_blinding(), &random_blinding(), serial, current_height, Hash::zero())
        .map_err(|e| format!("UTXO creation: {}", e))?;
    let output1 = TxOutput::from_jt_utxo(&to_utxo, 0);
    let mut outputs = vec![output1];

    if change > 0 {
        let change_utxo = JtUtxo::new_global_clean(from_public.clone(), change, &random_blinding(), &random_blinding(), change_serial, current_height, Hash::zero())
            .map_err(|e| format!("Change UTXO: {}", e))?;
        outputs.push(TxOutput::from_jt_utxo(&change_utxo, 1));
    }

    let mut tx = Transaction::new(vec![input], outputs, fee_per_tx).with_chain_id(chain_id);
    let signature = from_key.sign(tx.tx_hash.as_bytes());
    tx.sign_input(&input_tx_hash, 0, signature.to_vec(), from_public)?;

    let tx_json = serde_json::to_string_pretty(&tx)?;
    let filename = format!("signed_tx_{}.json", &tx.tx_hash.to_hex()[..12]);
    std::fs::write(&filename, &tx_json)?;
    #[cfg(unix)] std::fs::set_permissions(&filename, Permissions::from_mode(0o600))?;

    println!("Транзакция создана: {}", tx.tx_hash.to_hex());
    println!("Сохранена: {}", filename);
    println!("Отправьте: curl -X POST http://127.0.0.1:19734/tx -d @{}", filename);
    Ok(())
}

fn cmd_create_address() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("⚠️  Мнемоника — секретные данные. Безопасное окружение обязательно.");
    let (wallet, mnemonic) = Wallet::new();
    let kp = wallet.derive_keypair(0);
    println!("Мнемоника: {}", mnemonic.words.join(" "));
    println!("Адрес: {}", kp.public.to_hex());
    println!("Приватный ключ (HEX): {}", hex::encode(kp.private.to_bytes()));
    Ok(())
}

fn cmd_export_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("⚠️  Не вводите мнемонику на чужих серверах.");
    let mnemonic_str = args.iter().position(|a| a == "--mnemonic").and_then(|i| args.get(i + 1)).ok_or("--mnemonic required")?;
    let words: Vec<String> = mnemonic_str.split_whitespace().map(|s| s.to_string()).collect();
    if words.len() != 12 && words.len() != 24 { return Err("Мнемоника должна содержать 12 или 24 слова".into()); }
    let mnemonic = Mnemonic { words };
    let seed = mnemonic.to_seed("");
    let wallet = Wallet::from_seed(&seed);
    let kp = wallet.derive_keypair(0);
    println!("Приватный ключ (m/0): {}", hex::encode(kp.private.to_bytes()));
    println!("Публичный ключ: {}", kp.public.to_hex());
    Ok(())
}

fn cmd_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic_str = args.iter().position(|a| a == "--mnemonic").and_then(|i| args.get(i + 1)).ok_or("--mnemonic required")?;
    let words: Vec<String> = mnemonic_str.split_whitespace().map(|s| s.to_string()).collect();
    if words.len() != 12 && words.len() != 24 { return Err("Мнемоника должна содержать 12 или 24 слова".into()); }
    let mnemonic = Mnemonic { words };
    let seed = mnemonic.to_seed("");
    let wallet = Wallet::from_seed(&seed);
    println!("Адрес: {}", wallet.public_key().to_hex());
    Ok(())
}

fn cmd_genesis_info(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::open(db_path)?;
    if let Some(block) = storage.load_block(0)? {
        println!("Генезис-блок: height=0, hash={}", hex::encode(block.block_hash.as_bytes()));
        if let Some(tx) = block.transactions.first() {
            println!("Транзакция: {}", tx.tx_hash.to_hex());
            for (i, output) in tx.outputs.iter().enumerate() {
                println!("  Выход {}: {:.8} AEV -> {}", i, output.amount as f64 / 100_000_000.0, hex::encode(output.owner.to_bytes()));
            }
        }
    } else { println!("Генезис-блок не найден в БД."); }
    Ok(())
}

fn cmd_compute_status(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr_bytes = parse_hex_arg(args, "--address")?;
    let pubkey = validate_public_key(&addr_bytes, "адрес")?;
    let storage = Storage::open(db_path)?;
    let utxo_set = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let current_height = storage.max_height()?.unwrap_or(0);

    let mut total_earned: u64 = 0;
    for (_nullifier, utxo) in utxo_set.all() {
        if utxo.owner().to_bytes() == pubkey.to_bytes() {
            total_earned += utxo.amount();
        }
    }

    println!("Статистика вычислений:");
    println!("├─ Заработано всего:     {:.8} AEV", total_earned as f64 / 100_000_000.0);
    println!("├─ Текущая высота:       {}", current_height);
    println!("└─ Статус:               {}", if current_height > 0 { "сеть активна" } else { "ожидание" });
    println!("\n💡 Запустите aevum-node для участия в вычислениях");
    Ok(())
}

fn cmd_utxos(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::open(db_path)?;
    let utxo_set = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let current_height = storage.max_height()?.unwrap_or(0);
    let maturity = get_maturity(&storage);
    let limit = parse_optional_u64(args, "--limit").unwrap_or(u64::MAX) as usize;
    let offset = parse_optional_u64(args, "--offset").unwrap_or(0) as usize;
    println!("Всего UTXO: {}", utxo_set.len());

    let filter_pubkey = args.iter().position(|a| a == "--address")
        .and_then(|i| args.get(i + 1))
        .map(|hex_str| -> Result<PublicKey, String> {
            let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
            validate_public_key(&arr, "адрес")
        }).transpose()?;

    let mut skipped = 0usize;
    let mut shown = 0usize;
    for (nullifier, utxo) in utxo_set.all() {
        if let Some(ref pk) = filter_pubkey { if utxo.owner().to_bytes() != pk.to_bytes() { continue; } }
        if skipped < offset { skipped += 1; continue; }
        if shown >= limit { break; }
        
        let maturity_str = if is_coinbase(utxo.restriction_level()) && !utxo.is_spendable(current_height, maturity) {
            let remaining = maturity.saturating_sub(current_height.saturating_sub(utxo.created_height()));
            format!(" (зреет {} блоков)", remaining)
        } else { String::new() };
        println!("  {} {} -> {:.8} AEV{} (h: {})",
            utxo_type_tag(utxo.restriction_level()),
            hex::encode(nullifier.as_bytes()),
            utxo.amount() as f64 / 100_000_000.0,
            maturity_str, utxo.created_height());
        shown += 1;
    }
    Ok(())
}
