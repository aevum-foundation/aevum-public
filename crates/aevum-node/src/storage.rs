use aevum::core::block::Block;
use aevum::core::jt_utxo::JtUtxo;
use aevum::core::state::UtxoSet;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

#[derive(Debug)]
pub enum NonceStatus {
    Accepted,
    Rejected { last_nonce: u64 },
}

pub struct Storage {
    conn: Connection,
}

impl Storage {
    pub fn open(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blocks (
                height INTEGER PRIMARY KEY,
                block_hash BLOB NOT NULL,
                prev_hash BLOB NOT NULL,
                poh_tick_start INTEGER NOT NULL,
                poh_tick_end INTEGER NOT NULL,
                state_root BLOB NOT NULL,
                data BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash BLOB PRIMARY KEY,
                block_height INTEGER NOT NULL,
                poh_tick INTEGER NOT NULL,
                data BLOB NOT NULL,
                FOREIGN KEY (block_height) REFERENCES blocks(height)
            );
            CREATE TABLE IF NOT EXISTS utxos (
                nullifier BLOB PRIMARY KEY,
                data BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_height);
            CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(block_hash);",
        )?;
        Ok(Storage { conn })
    }

    pub fn save_block(&mut self, block: &Block) -> Result<(), Box<dyn std::error::Error>> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO blocks (height, block_hash, prev_hash, poh_tick_start, poh_tick_end, state_root, data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![block.height, block.block_hash.as_bytes(), block.prev_hash.as_bytes(), block.poh_tick_start, block.poh_tick_end, block.state_root.as_bytes(), bincode::serialize(block)?],
        )?;
        for t in &block.transactions {
            tx.execute(
                "INSERT OR REPLACE INTO transactions (tx_hash, block_height, poh_tick, data) VALUES (?1, ?2, ?3, ?4)",
                params![t.tx_hash.as_bytes(), block.height, t.poh_tick, bincode::serialize(t)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn save_utxo_set(&mut self, utxo_set: &UtxoSet) -> Result<(), Box<dyn std::error::Error>> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM utxos", [])?;
        for (nullifier, utxo) in utxo_set.all() {
            tx.execute(
                "INSERT INTO utxos (nullifier, data) VALUES (?1, ?2)",
                params![nullifier.as_bytes(), bincode::serialize(utxo)?],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn load_utxo_set(&self) -> Result<UtxoSet, Box<dyn std::error::Error>> {
        let mut utxo_set = UtxoSet::new();
        let mut stmt = self.conn.prepare("SELECT data FROM utxos")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        for row in rows {
            let utxo: JtUtxo = bincode::deserialize(&row?)?;
            utxo_set.add(utxo);
        }
        Ok(utxo_set)
    }

    /// Атомарно проверяет и обновляет nonce (требует &mut self как save_block)
    pub fn check_and_update_nonce(&mut self, key: &str, new_nonce: u64) -> Result<NonceStatus, Box<dyn std::error::Error>> {
        let tx = self.conn.transaction()?;

        let updated = tx.execute(
            "UPDATE metadata SET value = ?1 WHERE key = ?2 AND CAST(value AS INTEGER) < ?3",
            params![bincode::serialize(&new_nonce)?, key, new_nonce as i64],
        )?;

        if updated > 0 {
            tx.commit()?;
            return Ok(NonceStatus::Accepted);
        }

        let existing: Option<Vec<u8>> = tx.query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get(0),
        ).optional()?;

        match existing {
            None => {
                tx.execute(
                    "INSERT INTO metadata (key, value) VALUES (?1, ?2)",
                    params![key, bincode::serialize(&new_nonce)?],
                )?;
                tx.commit()?;
                Ok(NonceStatus::Accepted)
            }
            Some(bytes) => {
                let last_nonce: u64 = bincode::deserialize(&bytes).unwrap_or(0);
                Ok(NonceStatus::Rejected { last_nonce })
            }
        }
    }

    pub fn save_metadata(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn load_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare("SELECT value FROM metadata WHERE key = ?1")?;
        let value: Option<Vec<u8>> = stmt.query_row(params![key], |row| row.get(0)).optional()?;
        Ok(value)
    }

    pub fn load_block(&self, height: u64) -> Result<Option<Block>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare("SELECT data FROM blocks WHERE height = ?1")?;
        let result: Option<Vec<u8>> = stmt.query_row(params![height], |row| row.get(0)).optional()?;
        match result {
            Some(data) => Ok(Some(bincode::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    pub fn max_height(&self) -> Result<Option<u64>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare("SELECT COALESCE(MAX(height), 0) FROM blocks")?;
        let result: u64 = stmt.query_row([], |row| row.get(0))?;
        if result == 0 { Ok(None) } else { Ok(Some(result)) }
    }
}
