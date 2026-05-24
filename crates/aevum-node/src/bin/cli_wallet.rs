use aevum::core::address::{AcceptancePolicy, AcceptanceRule};
use aevum::core::jt_utxo::{JtUtxo, CATEGORY_MASK, CAT_GLOBAL, CAT_COINBASE, CAT_JURISDICTION, CAT_COMPUTE, is_coinbase};
use aevum::core::transaction::{Transaction, TxInput, TxOutput};
use aevum::core::state::UtxoSet;
use aevum::crypto::keys::{PrivateKey, PublicKey};
use aevum::crypto::hash::Hash;
use aevum::prisma::policy::Policy;
use aevum::prisma::filter::PrismaFilter;
use aevum::wallet::{Wallet, Mnemonic};
use aevum_node::storage::Storage;
use std::io::Write;
use std::path::PathBuf;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::collections::HashMap;
use rand::Rng;
use sha2::{Sha256, Digest};

extern crate ureq;

const FEE_PERCENT_BASIS: u64 = 10;
const FEE_DENOMINATOR: u64 = 100_000;
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
    let node_url = args.iter().position(|a| a == "--node-url")
        .and_then(|i| args.get(i + 1)).cloned();
    match args[1].as_str() {
        "balance" => if node_url.is_some() { cmd_balance_http(&args, &node_url.unwrap())? } else { cmd_balance(&args, &db_path)? },
        "send" => if node_url.is_some() { cmd_send_http(&args, &node_url.unwrap())? } else { cmd_send(&args, &db_path)? },
        "history" => cmd_history(&args, &db_path)?,
        "create-address" => cmd_create_address()?,
        "export-key" => cmd_export_key(&args)?,
        "import" => cmd_import(&args)?,
        "encrypt-key" => cmd_encrypt_key(&args)?,
        "decrypt-key" => cmd_decrypt_key(&args)?,
        "cross-chain-check" => cmd_cross_chain_check(&args, &db_path)?,
        "risk-check" => cmd_risk_check(&args, &db_path)?,
        "prove-innocence" => cmd_prove_innocence(&args, &db_path)?,
        "verify-innocence" => cmd_verify_innocence(&args)?,
        "prisma-config" => cmd_prisma_config(&args, &db_path)?,
        "genesis-info" => cmd_genesis_info(&args, &db_path)?,
        "compute-status" => cmd_compute_status(&args, &db_path)?,
        "utxos" => cmd_utxos(&args, &db_path)?,
        "help" | "--help" | "-h" => print_help(),
        _ => { eprintln!("Неизвестная команда: {}", args[1]); print_help(); }
    }
    Ok(())
}

fn print_help() {
    println!("Aevum CLI Wallet v1.0");
    println!("  balance --address <АДРЕС> --db <ПУТЬ> [--node-url <URL>]");
    println!("  send --from-key-file <ФАЙЛ> --to <АДРЕС> --amount <СУММА> [--dry-run] --db <ПУТЬ> [--node-url <URL>]");
    println!("  history --address <АДРЕС> [--limit N] --db <ПУТЬ>");
    println!("  create-address");
    println!("  export-key --mnemonic '<12 слов>'");
    println!("  import --mnemonic '<12 слов>'");
    println!("  encrypt-key --key-file <ФАЙЛ> --password <ПАРОЛЬ>");
    println!("  decrypt-key --encrypted-file <ФАЙЛ> --password <ПАРОЛЬ>");
    println!("  prisma-config --address <АДРЕС> [--accept US,EU] [--block KP,IR] [--default-allow|--default-deny] [--show] --db <ПУТЬ>");
    println!("  risk-check --address <АДРЕС> --db <ПУТЬ>");
    println!("  cross-chain-check --chain <BITCOIN|ETHEREUM> --address <АДРЕС> --db <ПУТЬ>");
    println!("  prove-innocence --address <АДРЕС> --oracle-pubkey <КЛЮЧ> --db <ПУТЬ>");
    println!("  verify-innocence --proof <ФАЙЛ>");
    println!("  genesis-info --db <ПУТЬ>");
    println!("  compute-status --address <АДРЕС> --db <ПУТЬ>");
    println!("  utxos [--address <АДРЕС>] [--limit N] [--offset M] --db <ПУТЬ>");
    println!("  Флаг --node-url позволяет работать без остановки ноды (через HTTP API)");
}

// ============================================================
// HTTP МЕТОДЫ (без остановки ноды)
// ============================================================

fn cmd_balance_http(args: &[String], node_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_hex_arg(args, "--address")?;
    let pk = validate_public_key(&addr, "адрес")?;
    let resp = ureq::get(&format!("{}/utxos?address={}", node_url, hex::encode(pk.to_bytes()))).call()?.into_string()?;
    let utxos: Vec<serde_json::Value> = serde_json::from_str(&resp)?;
    let total: u64 = utxos.iter().map(|u| u["amount"].as_u64().unwrap_or(0)).sum();
    println!("Баланс: {:.8} AEV", total as f64 / 100_000_000.0);
    println!("└─ UTXO: {}", utxos.len());
    Ok(())
}

fn cmd_send_http(args: &[String], node_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let dry = args.iter().any(|a| a == "--dry-run");
    let from_key = load_private_key(args)?;
    let from_pk = from_key.public_key();
    let to_bytes = parse_hex_arg(args, "--to")?;
    let to_pk = validate_public_key(&to_bytes, "адрес")?;
    let amt_str = args.iter().position(|a| a == "--amount").and_then(|i| args.get(i + 1)).ok_or("--amount required")?;
    let amt_f: f64 = amt_str.parse().map_err(|_| "Amount")?;
    if amt_f <= 0.0 { return Err("Amount > 0".into()); }
    let amount: u64 = (amt_f * 100_000_000.0) as u64;
    let fee = calculate_fee(amount);
    let need = amount + fee;
    
    let resp = ureq::get(&format!("{}/utxos?address={}", node_url, hex::encode(from_pk.to_bytes()))).call()?.into_string()?;
    let utxos_json: Vec<serde_json::Value> = serde_json::from_str(&resp)?;
    
    let mut total: u64 = 0;
    let mut selected: Vec<&serde_json::Value> = Vec::new();
    for u in &utxos_json {
        if total >= need { break; }
        total += u["amount"].as_u64().unwrap_or(0);
        selected.push(u);
    }
    
    if total < need {
        return Err(format!("Недостаточно: {:.8} AEV, нужно {:.8}", total as f64/100_000_000.0, need as f64/100_000_000.0).into());
    }
    
    let change = total.saturating_sub(need);
    println!("Выбрано UTXO: {}", selected.len());
    println!("├─ Всего:      {:.8} AEV", total as f64/100_000_000.0);
    println!("├─ Комиссия:   {:.8} AEV (0.01%)", fee as f64/100_000_000.0);
    println!("├─ К отправке: {:.8} AEV", amount as f64/100_000_000.0);
    if change > 0 { println!("├─ Сдача:      {:.8} AEV", change as f64/100_000_000.0); }
    
    if dry { println!("\n🔍 Dry-run."); return Ok(()); }
    
    // Создаём входы с реальными tx_hash, nullifier, output_index
    let mut inputs = Vec::new();
    for u in &selected {
        let tx_hash_hex = u["tx_hash"].as_str().unwrap_or("");
        let nullifier_hex = u["nullifier"].as_str().unwrap_or("");
        let oi = u["output_index"].as_u64().unwrap_or(0) as u32;
        let tx_hash_bytes = hex::decode(tx_hash_hex).unwrap_or(vec![0u8; 32]);
        let nullifier_bytes = hex::decode(nullifier_hex).unwrap_or(vec![0u8; 32]);
        let mut th = [0u8; 32]; th.copy_from_slice(&tx_hash_bytes[..32]);
        let mut n = [0u8; 32]; n.copy_from_slice(&nullifier_bytes[..32]);
        inputs.push(TxInput {
            tx_hash: Hash(th), output_index: oi, nullifier: Hash(n),
            signature: vec![], public_key: from_pk.clone(),
            signed_hash: Hash::zero(), nonce: 1,
        });
    }
    
    let mut outs = vec![TxOutput::new(
        to_pk.clone(), amount,
        aevum::crypto::hash::AmountCommitment::dummy(),
        aevum::crypto::hash::TagCommitment::dummy(),
        Hash::zero(), 0,
        aevum::core::jt_utxo::ZkProof::empty(),
        Hash::zero(),
        aevum::core::jt_utxo::RESTRICTION_GLOBAL_CLEAN, 0,
    )];
    
    if change > 0 {
        outs.push(TxOutput::new(
            from_pk.clone(), change,
            aevum::crypto::hash::AmountCommitment::dummy(),
            aevum::crypto::hash::TagCommitment::dummy(),
            Hash::zero(), 1,
            aevum::core::jt_utxo::ZkProof::empty(),
            Hash::zero(),
            aevum::core::jt_utxo::RESTRICTION_GLOBAL_CLEAN, 0,
        ));
    }
    
    let mut tx = Transaction::new(inputs.clone(), outs, fee);
    let sig = from_key.sign(tx.tx_hash.as_bytes());
    for i in 0..selected.len() {
        let tx_hash_hex = selected[i]["tx_hash"].as_str().unwrap_or("");
        let tx_hash_bytes = hex::decode(tx_hash_hex).unwrap_or(vec![0u8; 32]);
        let mut th = [0u8; 32]; th.copy_from_slice(&tx_hash_bytes[..32]);
        tx.sign_input(&Hash(th), i, sig.to_vec(), from_pk.clone()).ok();
    }
    
    let body = serde_json::to_string(&tx)?;
    let resp = ureq::post(&format!("{}/tx", node_url))
        .set("Content-Type", "application/json")
        .send_string(&body)?
        .into_string()?;
    println!("Отправлено: {}", resp);
    println!("Транзакция: {}", tx.tx_hash.to_hex());
    Ok(())
}

// ============================================================
// ВСЕ ОРИГИНАЛЬНЫЕ МЕТОДЫ (полностью сохранены)
// ============================================================

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

fn parse_jurisdiction_list(args: &[String], name: &str) -> Option<Vec<[u8; 4]>> {
    let list_str = args.iter().position(|a| a == name).and_then(|i| args.get(i + 1))?;
    let codes: Vec<[u8; 4]> = list_str.split(',').filter_map(|s| {
        let s = s.trim(); if s.len() == 4 { let mut c = [0u8; 4]; c.copy_from_slice(s.as_bytes()); Some(c) } else { None }
    }).collect();
    if codes.is_empty() { None } else { Some(codes) }
}

fn validate_public_key(bytes: &[u8; 32], label: &str) -> Result<PublicKey, String> {
    PublicKey::from_bytes(*bytes).map_err(|_| format!("Invalid {}: точка не на кривой Ed25519", label))
}

fn read_secret(prompt: &str) -> Result<String, String> {
    eprint!("{}", prompt); std::io::stderr().flush().map_err(|e| e.to_string())?;
    #[cfg(unix)] {
        use std::io::Read;
        let mut termios = termios::Termios::from_fd(0).map_err(|e| format!("termios: {}", e))?;
        let old = termios; termios.c_lflag &= !(termios::ECHO | termios::ECHONL);
        termios::tcsetattr(0, termios::TCSANOW, &termios).map_err(|e| format!("tcsetattr: {}", e))?;
        let mut input = String::new(); std::io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
        termios::tcsetattr(0, termios::TCSANOW, &old).ok(); eprintln!(); Ok(input)
    }
    #[cfg(not(unix))] { let mut input = String::new(); std::io::stdin().read_line(&mut input).map_err(|e| e.to_string())?; Ok(input) }
}

fn random_blinding() -> [u8; 32] { let mut rng = rand::thread_rng(); let mut b = [0u8; 32]; rng.fill(&mut b); b }
fn get_next_serial(storage: &Storage) -> Result<u64, Box<dyn std::error::Error>> {
    let s = storage.load_metadata("utxo_serial")?.and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(0);
    storage.save_metadata("utxo_serial", &bincode::serialize(&(s+1))?)?; Ok(s+1)
}
fn get_next_nonce(storage: &Storage, pk: &PublicKey) -> Result<u64, Box<dyn std::error::Error>> {
    let k = format!("nonce_{}", hex::encode(pk.to_bytes()));
    let n = storage.load_metadata(&k)?.and_then(|d| bincode::deserialize::<u64>(&d).ok()).unwrap_or(0);
    storage.save_metadata(&k, &bincode::serialize(&(n+1))?)?; Ok(n+1)
}
fn get_chain_id(storage: &Storage) -> u32 { storage.load_metadata("chain_id").ok().flatten().and_then(|d| bincode::deserialize(&d).ok()).unwrap_or(2) }
fn get_maturity(storage: &Storage) -> u64 { storage.load_metadata("coinbase_maturity").ok().flatten().and_then(|d| bincode::deserialize(&d).ok()).unwrap_or(COINBASE_MATURITY_DEFAULT) }
fn calculate_fee(amount: u64) -> u64 { let f = amount * FEE_PERCENT_BASIS / FEE_DENOMINATOR; if f == 0 { 1 } else { f } }

fn encrypt_key(key_bytes: &[u8; 32], password: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 32]; rand::thread_rng().fill(&mut salt);
    let mut h = Sha256::new(); h.update(password.as_bytes()); h.update(&salt); let mut d = h.finalize();
    for _ in 0..100_000 { d = Sha256::digest(&d); }
    let mut enc = [0u8; 32]; for i in 0..32 { enc[i] = key_bytes[i] ^ d[i]; }
    let cs = Sha256::digest(&enc[..28]); let mut out = Vec::with_capacity(68);
    out.extend_from_slice(&salt); out.extend_from_slice(&enc); out.extend_from_slice(&cs[..4]); Ok(out)
}

fn decrypt_key(encrypted: &[u8], password: &str) -> Result<[u8; 32], String> {
    if encrypted.len() < 68 { return Err("Неверный формат".into()); }
    let salt: [u8; 32] = encrypted[..32].try_into().map_err(|_| "Salt")?;
    let ct: [u8; 32] = encrypted[32..64].try_into().map_err(|_| "CT")?;
    let sc: [u8; 4] = encrypted[64..68].try_into().map_err(|_| "CS")?;
    let mut h = Sha256::new(); h.update(password.as_bytes()); h.update(&salt); let mut d = h.finalize();
    for _ in 0..100_000 { d = Sha256::digest(&d); }
    let mut key = [0u8; 32]; for i in 0..32 { key[i] = ct[i] ^ d[i]; }
    let cs = Sha256::digest(&key[..28]); if cs[..4] != sc { return Err("Неверный пароль".into()); }
    Ok(key)
}

fn load_private_key(args: &[String]) -> Result<PrivateKey, String> {
    if let Some(pos) = args.iter().position(|a| a == "--from-key-file") {
        let path = args.get(pos + 1).ok_or("--from-key-file requires a path")?;
        let content = std::fs::read_to_string(path).map_err(|e| format!("Read: {}", e))?;
        let hs = content.trim();
        if hs.len() == 64 && hs.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes = hex::decode(hs).map_err(|_| "Hex")?; let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
            return PrivateKey::from_bytes(arr).map_err(|_| "Key".to_string());
        } else {
            let pw = read_secret("Пароль: ")?;
            let enc = hex::decode(hs).map_err(|_| "Enc")?;
            let kb = decrypt_key(&enc, pw.trim())?;
            return PrivateKey::from_bytes(kb).map_err(|_| "Key".to_string());
        }
    }
    let input = read_secret("Приватный ключ (hex): ")?;
    let bytes = hex::decode(input.trim()).map_err(|_| "Hex")?;
    let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes[..32]);
    PrivateKey::from_bytes(arr).map_err(|_| "Key".to_string())
}

fn utxo_type_tag(level: u64) -> &'static str {
    match level & CATEGORY_MASK {
        CAT_GLOBAL => "🟢 GLOBAL", CAT_COINBASE => "⛏️  COINBASE",
        CAT_JURISDICTION => "🏛️  JURISDICTION", CAT_COMPUTE => "🧬 COMPUTE", _ => "❓ UNKNOWN",
    }
}

fn cmd_encrypt_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let kf = args.iter().position(|a| a == "--key-file").and_then(|i| args.get(i + 1)).ok_or("--key-file required")?;
    let pw = read_secret("Пароль: ")?; let pw2 = read_secret("Повторите: ")?;
    if pw != pw2 { return Err("Не совпадают".into()); }
    let hex_str = std::fs::read_to_string(kf)?.trim().to_string();
    let bytes = hex::decode(&hex_str).map_err(|_| "Hex")?;
    let mut kb = [0u8; 32]; kb.copy_from_slice(&bytes[..32]);
    let enc = encrypt_key(&kb, pw.trim())?;
    let ef = kf.to_string() + ".enc"; std::fs::write(&ef, hex::encode(&enc))?;
    #[cfg(unix)] std::fs::set_permissions(&ef, Permissions::from_mode(0o600))?;
    println!("Зашифрован: {}", ef); Ok(())
}

fn cmd_decrypt_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let ef = args.iter().position(|a| a == "--encrypted-file").and_then(|i| args.get(i + 1)).ok_or("--encrypted-file required")?;
    let pw = read_secret("Пароль: ")?;
    let hs = std::fs::read_to_string(ef)?.trim().to_string();
    let enc = hex::decode(&hs).map_err(|_| "Hex")?;
    let kb = decrypt_key(&enc, pw.trim())?;
    let out = ef.replace(".enc", ".dec"); std::fs::write(&out, hex::encode(kb))?;
    #[cfg(unix)] std::fs::set_permissions(&out, Permissions::from_mode(0o600))?;
    println!("Расшифрован: {}", out); Ok(())
}

fn cmd_balance(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_hex_arg(args, "--address")?; let pk = validate_public_key(&addr, "адрес")?;
    let storage = Storage::open(db_path)?;
    let utxos = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let h = storage.max_height()?.unwrap_or(0); let mat = get_maturity(&storage);
    let mut gc=0u64; let mut jt: HashMap<String,u64>=HashMap::new(); let mut pm=0u64; let mut cr=0u64; let mut ta=0u64; let mut cnt=0u64;
    for (_, u) in utxos.all() {
        if u.owner().to_bytes()!=pk.to_bytes() { continue; }
        let a=u.amount(); let l=u.restriction_level(); cnt+=1;
        if is_coinbase(l) && !u.is_spendable(h, mat) { pm+=a; }
        else { ta+=a; if is_coinbase(l) { gc+=a; } else if l&CATEGORY_MASK==CAT_JURISDICTION { let t=format!("🏛️ J0x{:03X}",l&0xFF); *jt.entry(t).or_insert(0)+=a; } else if l&CATEGORY_MASK==CAT_COMPUTE { cr+=a; } else { gc+=a; } }
    }
    println!("Баланс: {:.8} AEV", (ta+pm) as f64/100_000_000.0);
    println!("├─ 🟢 Глобальные:     {:.8} AEV", gc as f64/100_000_000.0);
    for (t,a) in &jt { println!("├─ {}:        {:.8} AEV", t, *a as f64/100_000_000.0); }
    if cr>0 { println!("├─ ⛏️  Compute:  {:.8} AEV", cr as f64/100_000_000.0); }
    if pm>0 { println!("├─ 🔒 Maturity:   {:.8} AEV", pm as f64/100_000_000.0); }
    println!("└─ Доступно:        {:.8} AEV", ta as f64/100_000_000.0);
    println!("Всего UTXO: {}", cnt); Ok(())
}

fn cmd_send(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let dry = args.iter().any(|a| a == "--dry-run");
    let from_key = load_private_key(args)?; let from_pk = from_key.public_key();
    let to_bytes = parse_hex_arg(args, "--to")?; let to_pk = validate_public_key(&to_bytes, "адрес")?;
    let amt_str = args.iter().position(|a| a == "--amount").and_then(|i| args.get(i + 1)).ok_or("--amount required")?;
    let amt_f: f64 = amt_str.parse().map_err(|_| "Amount")?;
    if amt_f <= 0.0 { return Err("Amount > 0".into()); }
    let amount: u64 = (amt_f * 100_000_000.0) as u64;
    let storage = Storage::open(db_path)?;
    let utxos = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let h = storage.max_height()?.unwrap_or(0); let cid = get_chain_id(&storage);
    let mat = get_maturity(&storage); let fee = calculate_fee(amount);
    let serial = get_next_serial(&storage)?; let nonce = get_next_nonce(&storage, &from_pk)?;
    if to_pk.to_bytes() == from_pk.to_bytes() {
        eprintln!("⚠️  ОТПРАВКА НА СВОЙ АДРЕС! Комиссия {:.8} AEV сгорит.", fee as f64/100_000_000.0);
        eprint!("Продолжить? [y/N]: "); std::io::stderr().flush().ok();
        let mut ans = String::new(); std::io::stdin().read_line(&mut ans).ok();
        if !ans.trim().to_lowercase().starts_with('y') { return Err("Отменено".into()); }
    }
    let mut sel: Vec<(Hash,Hash,u64,usize,u64)> = Vec::new(); let mut total: u64 = 0;
    let need = amount + fee;
    for (_, u) in utxos.all() {
        if total >= need { break; }
        if u.owner().to_bytes()!=from_pk.to_bytes()||!u.is_spendable(h,mat) { continue; }
        sel.push((*u.nullifier(),*u.tx_hash(),u.amount(),u.output_index(),u.restriction_level()));
        total += u.amount();
    }
    if total < need { return Err(format!("Недостаточно: {:.8} AEV, нужно {:.8}", total as f64/100_000_000.0, need as f64/100_000_000.0).into()); }
    let change = total.saturating_sub(need);
    println!("Выбрано UTXO: {}", sel.len());
    for (i,(_,_,a,_,rl)) in sel.iter().enumerate() { println!("├─ #{}: {:.8} AEV {}", i+1, *a as f64/100_000_000.0, utxo_type_tag(*rl)); }
    println!("├─ Всего:      {:.8} AEV", total as f64/100_000_000.0);
    println!("├─ Комиссия:   {:.8} AEV (0.01%)", fee as f64/100_000_000.0);
    println!("├─ К отправке: {:.8} AEV", amount as f64/100_000_000.0);
    if change>0 { println!("├─ Сдача:      {:.8} AEV", change as f64/100_000_000.0); }
    else { println!("├─ Сдача:      0"); }
    println!("├─ Nonce: {}", nonce); println!("├─ Chain ID: {}", cid);
    if dry { println!("\n🔍 Dry-run."); return Ok(()); }
    let mut inputs = Vec::new();
    for (n,th,_,oi,_) in &sel { inputs.push(TxInput{tx_hash:*th,output_index:*oi as u32,nullifier:*n,signature:vec![],public_key:from_pk.clone(),signed_hash:Hash::zero(),nonce}); }
    let cs = if change>0 { get_next_serial(&storage)? } else { 0 };
    let to_u = JtUtxo::new_global_clean(to_pk.clone(),amount,&random_blinding(),&random_blinding(),serial,h,Hash::zero()).map_err(|e|format!("UTXO: {}",e))?;
    let o1 = TxOutput::from_jt_utxo(&to_u,0); let mut outs = vec![o1];
    if change>0 { let ch_u = JtUtxo::new_global_clean(from_pk.clone(),change,&random_blinding(),&random_blinding(),cs,h,Hash::zero()).map_err(|e|format!("Ch: {}",e))?; outs.push(TxOutput::from_jt_utxo(&ch_u,1)); }
    let mut tx = Transaction::new(inputs,outs,fee).with_chain_id(cid);
    let sig = from_key.sign(tx.tx_hash.as_bytes());
    for i in 0..sel.len() { tx.sign_input(&sel[i].1,i,sig.to_vec(),from_pk.clone())?; }
    let tj = serde_json::to_string_pretty(&tx)?;
    let fnm = format!("signed_tx_{}.json",&tx.tx_hash.to_hex()[..12]);
    std::fs::write(&fnm,&tj)?; #[cfg(unix)] std::fs::set_permissions(&fnm,Permissions::from_mode(0o600))?;
    println!("Транзакция: {}", tx.tx_hash.to_hex()); println!("Файл: {}", fnm); Ok(())
}

fn cmd_history(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_hex_arg(args, "--address")?; let pk = validate_public_key(&addr, "адрес")?;
    let storage = Storage::open(db_path)?; let h = storage.max_height()?.unwrap_or(0);
    let limit = parse_optional_u64(args, "--limit").unwrap_or(20) as usize;
    println!("История для {}:", hex::encode(&pk.to_bytes()[..8]));
    let mut found = 0usize;
    for bh in (0..=h).rev() { if found>=limit { break; } if let Ok(Some(b)) = storage.load_block(bh) { for tx in &b.transactions { let mut out=false; let mut inc=false; let mut amt:u64=0; for i in &tx.inputs { if i.public_key.to_bytes()==pk.to_bytes() { out=true; } } for o in &tx.outputs { if o.owner.to_bytes()==pk.to_bytes() { inc=true; amt+=o.amount; } } if out||inc { found+=1; let tp = if out&&inc {"🔄"} else if out {"📤"} else {"📥"}; let st = if bh+10>=h {"⏳"} else {"✅"}; println!("{:<6} {:<4} {:<12.8} {:<44} {}", bh, tp, amt as f64/100_000_000.0, tx.tx_hash.to_hex(), st); } } } }
    if found==0 { println!("Нет транзакций."); } else { println!("Показано {}", found); }
    Ok(())
}

fn cmd_cross_chain_check(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let chain = args.iter().position(|a| a == "--chain").and_then(|i| args.get(i + 1)).ok_or("--chain required")?;
    let addr = args.iter().position(|a| a == "--address").and_then(|i| args.get(i + 1)).ok_or("--address required")?;
    let chain_id = match chain.to_uppercase().as_str() { "BITCOIN"|"BTC" => 0u32, "ETHEREUM"|"ETH" => 1, _ => return Err("Поддерживаются: Bitcoin, Ethereum".into()) };
    let storage = Storage::open(db_path)?;
    let h = storage.max_height()?.unwrap_or(0);
    let risk = aevum::oracle::innocence::CrossChainRisk::new(chain_id, addr, h);
    println!("Кросс-чейн проверка: {}:{}", chain, addr);
    println!("├─ Сеть: {}", chain);
    println!("├─ Риск: {:.8}", risk.risk_level as f64);
    println!("├─ Taint: {} хопов", risk.source_taint_distance);
    println!("├─ Описание: {}", risk.taint_origin_description);
    println!("├─ Оракулов: {}", risk.confirmed_by.len());
    println!("└─ Статус: {}", if risk.risk_level == aevum::core::jt_utxo::CAT_GLOBAL { "✅ Чистый" } else { "⚠️  Требует проверки" });
    Ok(())
}
fn cmd_risk_check(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_hex_arg(args, "--address")?;
    let pk = validate_public_key(&addr, "адрес")?;
    let storage = Storage::open(db_path)?;
    let utxos = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let h = storage.max_height()?.unwrap_or(0);
    let filter = aevum::prisma::filter::PrismaFilter::strict();
    println!("Риск адреса {}:", hex::encode(&pk.to_bytes()[..8]));
    let mut found = false;
    for (_, u) in utxos.all() {
        if u.owner().to_bytes() != pk.to_bytes() { continue; }
        found = true;
        let result = filter.check_utxo(u, h, None);
        let status = if result.is_accepted() { "✅ Принимается" } else { "❌ Отклоняется" };
        let cat = u.restriction_level() & aevum::core::jt_utxo::CATEGORY_MASK;
        let cat_name = match cat {
            aevum::core::jt_utxo::CAT_GLOBAL => "Глобальный",
            aevum::core::jt_utxo::CAT_JURISDICTION => "Юрисдикционный",
            aevum::core::jt_utxo::CAT_COMPUTE => "Compute",
            aevum::core::jt_utxo::CAT_RISK_TAG => "⚠️  Риск",
            _ => "Неизвестный",
        };
        let taint = aevum::core::jt_utxo::decay_taint(u.taint_distance, u.taint_timestamp, h);
        println!("├─ Сумма: {:.8} AEV | Категория: {} | Taint: {} хопов | Статус: {}",
            u.amount() as f64 / 100_000_000.0, cat_name, taint, status);
    }
    if !found { println!("├─ Нет UTXO для этого адреса"); }
    println!("└─ Высота: {}", h);
    Ok(())
}

fn cmd_prove_innocence(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_hex_arg(args, "--address")?;
    let pk = validate_public_key(&addr, "адрес")?;
    let oracle_pk_hex = args.iter().position(|a| a == "--oracle-pubkey").and_then(|i| args.get(i + 1)).ok_or("--oracle-pubkey required")?;
    let oracle_bytes = hex::decode(oracle_pk_hex).map_err(|_| "Invalid oracle pubkey")?;
    let mut opk = [0u8; 32]; opk.copy_from_slice(&oracle_bytes[..32]);
    let oracle_pk = PublicKey::from_bytes(opk).map_err(|_| "Invalid oracle key")?;
    let storage = Storage::open(db_path)?;
    let h = storage.max_height()?.unwrap_or(0);
    let sanctions_root = aevum::crypto::hash::Hash([1u8; 32]);
    let risk_root = aevum::crypto::hash::Hash([2u8; 32]);
    let mut msg = Vec::new(); msg.extend_from_slice(sanctions_root.as_bytes()); msg.extend_from_slice(risk_root.as_bytes()); msg.extend_from_slice(&h.to_le_bytes());
    let sig = vec![0u8; 64];
    let proof = aevum::oracle::innocence::InnocenceProof::create(&pk, &sanctions_root, &risk_root, &oracle_pk, sig, h);
    let json = proof.to_json()?;
    let filename = format!("innocence_proof_{}.json", hex::encode(&pk.to_bytes()[..8]));
    std::fs::write(&filename, &json)?;
    println!("Доказательство создано: {}", filename);
    Ok(())
}

fn cmd_verify_innocence(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let proof_file = args.iter().position(|a| a == "--proof").and_then(|i| args.get(i + 1)).ok_or("--proof required")?;
    let json = std::fs::read_to_string(proof_file)?;
    let proof = aevum::oracle::innocence::InnocenceProof::from_json(&json)?;
    let current_h = args.iter().position(|a| a == "--height").and_then(|i| args.get(i + 1)).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let sanctions_root = aevum::crypto::hash::Hash([1u8; 32]);
    let risk_root = aevum::crypto::hash::Hash([2u8; 32]);
    match proof.verify(&sanctions_root, &risk_root, current_h) {
        Ok(true) => println!("✅ Доказательство действительно"),
        Ok(false) => println!("❌ Доказательство недействительно"),
        Err(e) => println!("❌ Ошибка: {}", e),
    }
    Ok(())
}
fn cmd_prisma_config(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_hex_arg(args, "--address")?; let pk = validate_public_key(&addr, "адрес")?;
    let mut storage = Storage::open(db_path)?;
    let mut utxos = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let mut filter = utxos.get_prisma_policy(&pk).map(|p| PrismaFilter { policy: p.policy.clone(), ..PrismaFilter::default() }).unwrap_or_default();
    if args.iter().any(|a| a == "--show") { show_prisma_filter(&filter); return Ok(()); }
    if args.iter().any(|a| a == "--accept-all") { filter.policy = AcceptancePolicy::AcceptAll; }
    if args.iter().any(|a| a == "--reject-all") { filter.policy = AcceptancePolicy::RejectAll; }
    if let Some(codes) = parse_jurisdiction_list(args, "--accept") { filter.policy = AcceptancePolicy::Whitelist(codes.iter().map(|c| AcceptanceRule::Jurisdiction(*c)).collect()); }
    if let Some(codes) = parse_jurisdiction_list(args, "--block") { filter.policy = AcceptancePolicy::Blacklist(codes.iter().map(|c| AcceptanceRule::Jurisdiction(*c)).collect()); }
    if let Some(max_t) = parse_optional_u64(args, "--max-taint") { filter.max_taint_distance = max_t as u16; }
    if args.iter().any(|a| a == "--taint-decay-off") { filter.taint_decay_enabled = false; }
    if args.iter().any(|a| a == "--taint-decay-on") { filter.taint_decay_enabled = true; }
    if let Some(w) = parse_optional_u64(args, "--weight-sanctions") { filter.set_category_weight(0x010, w as u8); }
    if let Some(w) = parse_optional_u64(args, "--weight-darknet") { filter.set_category_weight(0x020, w as u8); }
    if let Some(w) = parse_optional_u64(args, "--weight-ransomware") { filter.set_category_weight(0x030, w as u8); }
    if let Some(w) = parse_optional_u64(args, "--weight-stolen") { filter.set_category_weight(0x040, w as u8); }
    if let Some(w) = parse_optional_u64(args, "--weight-scam") { filter.set_category_weight(0x050, w as u8); }
    if let Some(w) = parse_optional_u64(args, "--weight-mixer") { filter.set_category_weight(0x060, w as u8); }
    if let Some(t) = parse_optional_u64(args, "--threshold") { filter.category_threshold = t as u8; }
    if args.iter().any(|a| a == "--require-proof") { filter.require_proof_of_innocence = true; }
    if args.iter().any(|a| a == "--no-proof") { filter.require_proof_of_innocence = false; }
    let policy = Policy::new(filter.policy.clone());
    utxos.set_prisma_policy(&pk, policy);
    storage.save_utxo_set(&utxos)?;
    println!("✅ Prisma Filter обновлён");
    show_prisma_filter(&filter);
    Ok(())
}

fn show_prisma_filter(filter: &PrismaFilter) {
    println!("├─ Max Taint: {} | Decay: {} | Threshold: {}% | Proof: {}", filter.max_taint_distance, if filter.taint_decay_enabled {"on"} else {"off"}, filter.category_threshold, if filter.require_proof_of_innocence {"yes"} else {"no"});
    if !filter.category_weights.is_empty() { for (c,w) in &filter.category_weights { println!("│  ├─ 0x{:03X}: {}%", c, w); } }
}

fn cmd_create_address() -> Result<(), Box<dyn std::error::Error>> {
    let (w, m) = Wallet::new(); let kp = w.derive_keypair(0);
    println!("Мнемоника: {}", m.words.join(" ")); println!("Адрес: {}", kp.public.to_hex()); println!("Ключ: {}", hex::encode(kp.private.to_bytes())); Ok(())
}
fn cmd_export_key(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let ms = args.iter().position(|a| a == "--mnemonic").and_then(|i| args.get(i + 1)).ok_or("--mnemonic required")?;
    let words: Vec<String> = ms.split_whitespace().map(|s| s.to_string()).collect();
    if words.len()!=12 && words.len()!=24 { return Err("12 или 24 слова".into()); }
    let m = Mnemonic{words}; let seed = m.to_seed(""); let w = Wallet::from_seed(&seed); let kp = w.derive_keypair(0);
    println!("Ключ: {}", hex::encode(kp.private.to_bytes())); Ok(())
}
fn cmd_import(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let ms = args.iter().position(|a| a == "--mnemonic").and_then(|i| args.get(i + 1)).ok_or("--mnemonic required")?;
    let words: Vec<String> = ms.split_whitespace().map(|s| s.to_string()).collect();
    if words.len()!=12 && words.len()!=24 { return Err("12 или 24 слова".into()); }
    let m = Mnemonic{words}; let seed = m.to_seed(""); let w = Wallet::from_seed(&seed);
    println!("Адрес: {}", w.public_key().to_hex()); Ok(())
}
fn cmd_genesis_info(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::open(db_path)?;
    if let Some(b) = storage.load_block(0)? { println!("Genesis: height=0 hash={}", hex::encode(b.block_hash.as_bytes())); if let Some(tx)=b.transactions.first() { for (i,o) in tx.outputs.iter().enumerate() { println!("  Out {}: {:.8} AEV -> {}", i, o.amount as f64/100_000_000.0, hex::encode(o.owner.to_bytes())); } } }
    else { println!("Генезис не найден."); } Ok(())
}
fn cmd_compute_status(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let addr = parse_hex_arg(args, "--address")?; let pk = validate_public_key(&addr, "адрес")?;
    let storage = Storage::open(db_path)?; let utxos = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let h = storage.max_height()?.unwrap_or(0); let mut te:u64=0;
    for (_,u) in utxos.all() { if u.owner().to_bytes()==pk.to_bytes() { te+=u.amount(); } }
    println!("Compute:"); println!("├─ Заработано: {:.8} AEV", te as f64/100_000_000.0); println!("├─ Высота: {}", h); println!("└─ Статус: {}", if h>0 {"активна"} else {"ожидание"}); Ok(())
}
fn cmd_utxos(args: &[String], db_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::open(db_path)?;
    let utxos = storage.load_utxo_set().unwrap_or_else(|_| UtxoSet::new());
    let h = storage.max_height()?.unwrap_or(0); let mat = get_maturity(&storage);
    let lim = parse_optional_u64(args,"--limit").unwrap_or(u64::MAX) as usize;
    let off = parse_optional_u64(args,"--offset").unwrap_or(0) as usize;
    let fpk = args.iter().position(|a|a=="--address").and_then(|i|args.get(i+1)).map(|hs|->Result<PublicKey,String>{let b=hex::decode(hs).map_err(|_|"Hex")?;let mut a=[0u8;32];a.copy_from_slice(&b[..32]);validate_public_key(&a,"адрес")}).transpose()?;
    let mut sk=0usize; let mut sh=0usize;
    for (n,u) in utxos.all() {
        if let Some(ref p)=fpk { if u.owner().to_bytes()!=p.to_bytes() { continue; } }
        if sk<off { sk+=1; continue; } if sh>=lim { break; }
        let ms = if is_coinbase(u.restriction_level())&&!u.is_spendable(h,mat) { let r=mat.saturating_sub(h.saturating_sub(u.created_height())); format!(" (зреет {} бл.)",r) } else { String::new() };
        println!("  {} {} -> {:.8} AEV{} (h:{})", utxo_type_tag(u.restriction_level()), hex::encode(n.as_bytes()), u.amount() as f64/100_000_000.0, ms, u.created_height());
        sh+=1;
    }
    Ok(())
}
