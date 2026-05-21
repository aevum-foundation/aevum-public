use std::collections::HashMap;
use reqwest;

/// Результат анализа адреса
#[derive(Clone, Debug)]
pub struct OnChainAnalysis {
    pub address: String,
    pub chain: u32,
    pub risk_level: u64,
    pub taint_distance: u16,
    pub taint_origin: String,
    pub interacted_addresses: Vec<String>,
    pub exchange_history: Vec<ExchangeRecord>,
}

#[derive(Clone, Debug)]
pub struct ExchangeRecord {
    pub exchange_name: String,
    pub kyc_level: KycLevel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KycLevel { None, Basic, Standard, Enhanced, Unknown }

#[derive(Clone, Debug)]
pub struct AddressRisk {
    pub risk_level: u64,
    pub taint_distance: u16,
    pub origin: String,
    pub exchange: Option<ExchangeRecord>,
}

/// База известных адресов
pub struct KnownAddressDB {
    pub exchanges: HashMap<String, ExchangeRecord>,
    pub mixers: Vec<String>,
    pub darknet_markets: Vec<String>,
    pub sanctioned: Vec<String>,
    pub scammers: Vec<String>,
    pub ransomware: Vec<String>,
}

impl KnownAddressDB {
    pub fn new() -> Self {
        KnownAddressDB {
            exchanges: HashMap::new(),
            mixers: Vec::new(),
            darknet_markets: Vec::new(),
            sanctioned: Vec::new(),
            scammers: Vec::new(),
            ransomware: Vec::new(),
        }
    }

    pub fn load_defaults(&mut self) {
        // Крупнейшие биржи
        self.exchanges.insert("1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s".into(),
            ExchangeRecord { exchange_name: "Binance".into(), kyc_level: KycLevel::Standard });
        self.exchanges.insert("3Kzh9qAqVWQhEsfQz7zEQL1EuSx5tyNLNS".into(),
            ExchangeRecord { exchange_name: "Coinbase".into(), kyc_level: KycLevel::Standard });
        self.exchanges.insert("bc1qgdjqv0av3q56jvd82tkdjpy7gd5jdlp5rj5q6v".into(),
            ExchangeRecord { exchange_name: "Kraken".into(), kyc_level: KycLevel::Enhanced });

        // Известные миксеры (по публичным отчётам)
        self.mixers = vec!["TornadoCash".into(), "Blender".into(), "Sinbad".into()];
        self.darknet_markets = vec!["Hydra".into(), "OMG".into(), "Blacksprut".into()];
    }

    pub fn check_address(&self, address: &str) -> AddressRisk {
        if self.sanctioned.iter().any(|a| a == address) {
            return AddressRisk {
                risk_level: crate::core::jt_utxo::CAT_RISK_TAG | crate::core::jt_utxo::RISK_SANCTIONS,
                taint_distance: 0,
                origin: "OFAC/EU Sanctions".into(),
                exchange: None,
            };
        }
        if self.darknet_markets.iter().any(|m| address.contains(m)) {
            return AddressRisk {
                risk_level: crate::core::jt_utxo::CAT_RISK_TAG | crate::core::jt_utxo::RISK_DARKNET,
                taint_distance: 1,
                origin: "Darknet market".into(),
                exchange: None,
            };
        }
        if self.mixers.iter().any(|m| address.contains(m)) {
            return AddressRisk {
                risk_level: crate::core::jt_utxo::CAT_RISK_TAG | crate::core::jt_utxo::RISK_MIXER,
                taint_distance: 1,
                origin: "Mixer".into(),
                exchange: None,
            };
        }
        if self.ransomware.iter().any(|a| a == address) {
            return AddressRisk {
                risk_level: crate::core::jt_utxo::CAT_RISK_TAG | crate::core::jt_utxo::RISK_RANSOMWARE,
                taint_distance: 0,
                origin: "Ransomware".into(),
                exchange: None,
            };
        }
        if let Some(record) = self.exchanges.get(address) {
            let risk = match record.kyc_level {
                KycLevel::None => crate::core::jt_utxo::RISK_NO_KYC_EXCHANGE,
                _ => 0,
            };
            return AddressRisk {
                risk_level: if risk > 0 { crate::core::jt_utxo::CAT_RISK_TAG | risk } else { crate::core::jt_utxo::CAT_GLOBAL },
                taint_distance: if risk > 0 { 2 } else { 0 },
                origin: format!("Exchange: {}", record.exchange_name),
                exchange: Some(record.clone()),
            };
        }
        AddressRisk {
            risk_level: crate::core::jt_utxo::CAT_GLOBAL,
            taint_distance: 0,
            origin: "Unknown".into(),
            exchange: None,
        }
    }
}

/// Анализатор адресов из внешних сетей
pub struct OnChainAnalyzer {
    pub known_db: KnownAddressDB,
    pub cache: HashMap<String, OnChainAnalysis>,
    client: reqwest::Client,
}

impl OnChainAnalyzer {
    pub fn new() -> Self {
        let mut db = KnownAddressDB::new();
        db.load_defaults();
        OnChainAnalyzer {
            known_db: db,
            cache: HashMap::new(),
            client: reqwest::Client::new(),
        }
    }

    /// Проанализировать адрес (сначала кеш, потом внешние API)
    pub async fn analyze(&mut self, chain: u32, address: &str) -> OnChainAnalysis {
        if let Some(cached) = self.cache.get(address) {
            return cached.clone();
        }

        // Сначала локальная проверка
        let risk = self.known_db.check_address(address);

        // Потом внешние API
        let mut interacted = Vec::new();
        match chain {
            0 => { // Bitcoin
                if let Some(txs) = self.fetch_btc_transactions(address).await {
                    interacted = txs;
                }
            }
            1 => { // Ethereum
                if let Some(txs) = self.fetch_eth_transactions(address).await {
                    interacted = txs;
                }
            }
            _ => {}
        }

        // Анализируем адреса взаимодействия
        let mut taint = risk.taint_distance;
        for addr in &interacted {
            let sub_risk = self.known_db.check_address(addr);
            if sub_risk.taint_distance + 1 > taint {
                taint = sub_risk.taint_distance + 1;
            }
        }

        let analysis = OnChainAnalysis {
            address: address.to_string(),
            chain,
            risk_level: risk.risk_level,
            taint_distance: taint,
            taint_origin: risk.origin,
            interacted_addresses: interacted,
            exchange_history: risk.exchange.map(|e| vec![e]).unwrap_or_default(),
        };

        self.cache.insert(address.to_string(), analysis.clone());
        analysis
    }

    /// Запросить транзакции BTC через Blockstream API (бесплатный, без ключа)
    async fn fetch_btc_transactions(&self, address: &str) -> Option<Vec<String>> {
        let url = format!("https://blockstream.info/api/address/{}/txs", address);
        match self.client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(txs) = resp.json::<Vec<serde_json::Value>>().await {
                    let mut addresses = Vec::new();
                    for tx in txs.iter().take(10) {
                        if let Some(vout) = tx.get("vout").and_then(|v| v.as_array()) {
                            for out in vout {
                                if let Some(addr) = out.get("scriptpubkey_address").and_then(|a| a.as_str()) {
                                    addresses.push(addr.to_string());
                                }
                            }
                        }
                    }
                    Some(addresses)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Запросить транзакции ETH через Etherscan API (бесплатный)
    async fn fetch_eth_transactions(&self, address: &str) -> Option<Vec<String>> {
        let url = format!(
            "https://api.etherscan.io/api?module=account&action=txlist&address={}&sort=desc&offset=10",
            address
        );
        match self.client.get(&url).send().await {
            Ok(resp) => {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if data.get("status").and_then(|s| s.as_str()) == Some("1") {
                        let mut addresses = Vec::new();
                        if let Some(txs) = data.get("result").and_then(|r| r.as_array()) {
                            for tx in txs.iter().take(10) {
                                if let Some(to) = tx.get("to").and_then(|t| t.as_str()) {
                                    if to != address { addresses.push(to.to_string()); }
                                }
                                if let Some(from) = tx.get("from").and_then(|f| f.as_str()) {
                                    if from != address { addresses.push(from.to_string()); }
                                }
                            }
                        }
                        Some(addresses)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}
