use aevum::consensus::validator::Validator;
use aevum::core::block::Block;
use crate::storage::Storage;
use std::sync::{Arc, Mutex as StdMutex};

#[derive(Debug, PartialEq)]
pub enum ForkDecision {
    OurChainWins,
    ForeignChainWins { from_height: u64, blocks: Vec<Block> },
    Tie,
}

pub struct ForkResolver;

impl ForkResolver {
    /// Разрешить форк: сравнить нашу цепь с чужой
    /// foreign_blocks — блоки чужой цепи, начиная с первого расходящегося
    pub fn resolve(
        validator: &Arc<StdMutex<Validator>>,
        storage: &Arc<StdMutex<Storage>>,
        foreign_blocks: &[Block],
    ) -> ForkDecision {
        if foreign_blocks.is_empty() {
            return ForkDecision::OurChainWins;
        }

        let val = validator.lock().unwrap();
        let our_height = val.last_block_height();
        let foreign_height = foreign_blocks.last().unwrap().height;
        let first_foreign = &foreign_blocks[0];

        if foreign_height <= our_height {
            return ForkDecision::OurChainWins;
        }

        let ancestor_height = match Self::find_common_ancestor(storage, our_height, first_foreign) {
            Some(h) => h,
            None => return ForkDecision::OurChainWins,
        };

        let our_ticks = Self::sum_ticks_from(storage, ancestor_height + 1, our_height);
        let foreign_ticks: u64 = foreign_blocks.iter()
            .map(|b| b.poh_tick_end.saturating_sub(b.poh_tick_start))
            .sum();

        tracing::info!("[Fork] ancestor={}, our_ticks={}, foreign_ticks={}, our_h={}, foreign_h={}",
            ancestor_height, our_ticks, foreign_ticks, our_height, foreign_height);

        if foreign_ticks > our_ticks {
            ForkDecision::ForeignChainWins { from_height: ancestor_height + 1, blocks: foreign_blocks.to_vec() }
        } else if our_ticks > foreign_ticks {
            ForkDecision::OurChainWins
        } else if foreign_height > our_height {
            ForkDecision::ForeignChainWins { from_height: ancestor_height + 1, blocks: foreign_blocks.to_vec() }
        } else {
            ForkDecision::Tie
        }
    }

    fn find_common_ancestor(storage: &Arc<StdMutex<Storage>>, our_height: u64, first_foreign: &Block) -> Option<u64> {
        let st = storage.lock().unwrap();
        let parent_height = first_foreign.height.saturating_sub(1);
        if let Ok(Some(parent_block)) = st.load_block(parent_height) {
            if parent_block.block_hash.0 == first_foreign.prev_hash.0 {
                return Some(parent_height);
            }
        }
        let start = if our_height > 1000 { our_height - 1000 } else { 0 };
        for h in (start..=our_height).rev() {
            if let Ok(Some(block)) = st.load_block(h) {
                if block.block_hash.0 == first_foreign.prev_hash.0 {
                    return Some(h);
                }
            }
        }
        Some(first_foreign.height.saturating_sub(1))
    }

    fn sum_ticks_from(storage: &Arc<StdMutex<Storage>>, from: u64, to: u64) -> u64 {
        let st = storage.lock().unwrap();
        let mut total = 0u64;
        for h in from..=to {
            if let Ok(Some(block)) = st.load_block(h) {
                total += block.poh_tick_end.saturating_sub(block.poh_tick_start);
            }
        }
        total
    }

    /// Применить чужую цепь (без отката — просто применяем поверх)
    pub fn apply_foreign_chain(
        validator: &Arc<StdMutex<Validator>>,
        storage: &Arc<StdMutex<Storage>>,
        blocks: Vec<Block>,
    ) -> Result<u64, String> {
        let mut val = validator.lock().unwrap();
        let mut st = storage.lock().unwrap();
        let mut applied = 0u64;

        for mut block in blocks {
            match val.validate_and_apply(&mut block) {
                Ok(_) => {
                    st.save_block(&block).map_err(|e| format!("save: {}", e))?;
                    st.save_utxo_set(val.utxo_set()).map_err(|e| format!("save_utxo: {}", e))?;
                    applied += 1;
                }
                Err(e) => {
                    tracing::warn!("[Fork] Failed to apply block {}: {}", block.height, e);
                    break;
                }
            }
        }
        Ok(applied)
    }
}
