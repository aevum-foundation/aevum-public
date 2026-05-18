use aevum::core::state::UtxoSet;
use crate::storage::Storage;
use std::sync::{Arc, Mutex as StdMutex};

const SNAPSHOT_INTERVAL: u64 = 1000;
const SNAPSHOT_KEY_PREFIX: &str = "utxo_snapshot_";

pub struct SnapshotManager;

impl SnapshotManager {
    /// Сохранить снапшот если высота кратна интервалу
    pub fn save_if_needed(
        storage: &Arc<StdMutex<Storage>>,
        height: u64,
        utxo_set: &UtxoSet,
    ) -> Result<(), String> {
        if height % SNAPSHOT_INTERVAL != 0 {
            return Ok(());
        }

        let key = format!("{}{}", SNAPSHOT_KEY_PREFIX, height);
        let data = bincode::serialize(utxo_set).map_err(|e| format!("serialize: {}", e))?;

        let st = storage.lock().unwrap();
        st.save_metadata(&key, &data).map_err(|e| format!("save: {}", e))?;

        tracing::info!("💾 UTXO snapshot saved at height {}", height);
        Ok(())
    }

    /// Загрузить ближайший снапшот (не выше запрошенной высоты)
    pub fn load_nearest(
        storage: &Arc<StdMutex<Storage>>,
        max_height: u64,
    ) -> Result<Option<(u64, UtxoSet)>, String> {
        let start = (max_height / SNAPSHOT_INTERVAL) * SNAPSHOT_INTERVAL;

        let mut h = start;
        loop {
            let key = format!("{}{}", SNAPSHOT_KEY_PREFIX, h);
            let st = storage.lock().unwrap();
            if let Ok(Some(data)) = st.load_metadata(&key) {
                let utxo_set: UtxoSet = bincode::deserialize(&data).map_err(|e| format!("deserialize: {}", e))?;
                tracing::info!("📥 UTXO snapshot loaded from height {}", h);
                return Ok(Some((h, utxo_set)));
            }
            if h == 0 { break; }
            h = h.saturating_sub(SNAPSHOT_INTERVAL);
        }

        Ok(None)
    }

    /// Получить высоту ближайшего снапшота
    pub fn nearest_snapshot_height(height: u64) -> u64 {
        (height / SNAPSHOT_INTERVAL) * SNAPSHOT_INTERVAL
    }

    /// Очистить старые снапшоты (оставить только последний)
    pub fn cleanup(
        storage: &Arc<StdMutex<Storage>>,
        current_height: u64,
    ) -> Result<usize, String> {
        let keep_height = Self::nearest_snapshot_height(current_height);
        let mut removed = 0usize;
        let mut h: u64 = 0;

        while h < keep_height {
            let key = format!("{}{}", SNAPSHOT_KEY_PREFIX, h);
            let st = storage.lock().unwrap();
            if st.load_metadata(&key).ok().flatten().is_some() {
                (*st).delete_metadata(&key).map_err(|e| format!("delete: {}", e))?;
                removed += 1;
            }
            h += SNAPSHOT_INTERVAL;
        }

        if removed > 0 {
            tracing::info!("🧹 Cleaned up {} old UTXO snapshots", removed);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_height_calculation() {
        assert_eq!(SnapshotManager::nearest_snapshot_height(0), 0);
        assert_eq!(SnapshotManager::nearest_snapshot_height(999), 0);
        assert_eq!(SnapshotManager::nearest_snapshot_height(1000), 1000);
        assert_eq!(SnapshotManager::nearest_snapshot_height(1999), 1000);
        assert_eq!(SnapshotManager::nearest_snapshot_height(2000), 2000);
    }
}
