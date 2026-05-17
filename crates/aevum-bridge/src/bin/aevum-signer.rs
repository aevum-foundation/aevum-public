use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 3 {
        eprintln!("Aevum Module Signer v1.0");
        eprintln!("Usage: {} <module.so> <private_key_hex>", args[0]);
        eprintln!("Example: {} libaevum_zk.so 0ffc...", args[0]);
        return Err("Not enough arguments".into());
    }

    let lib_path = PathBuf::from(&args[1]);
    let key_hex = &args[2];

    if !lib_path.exists() {
        return Err(format!("File not found: {}", lib_path.display()));
    }

    let data = std::fs::read(&lib_path).map_err(|e| format!("Read: {}", e))?;
    let key_bytes = hex::decode(key_hex).map_err(|e| format!("Hex: {}", e))?;
    
    if key_bytes.len() < 32 {
        return Err("Private key must be 32 bytes (64 hex chars)".into());
    }
    
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes[..32]);
    let signing_key = SigningKey::from_bytes(&key_arr);
    let signature = signing_key.sign(&data);
    
    let sig_path = lib_path.with_extension("sig");
    std::fs::write(&sig_path, signature.to_bytes()).map_err(|e| format!("Write: {}", e))?;
    
    println!("✅ Signed: {}", lib_path.display());
    println!("   Signature: {}", sig_path.display());
    println!("   Size: {} bytes", signature.to_bytes().len());
    
    Ok(())
}
