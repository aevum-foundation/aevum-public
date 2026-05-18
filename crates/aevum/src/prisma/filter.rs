use crate::core::address::{AcceptancePolicy, AcceptanceRule};
use crate::core::jt_utxo::{JtUtxo, CATEGORY_MASK, CAT_RISK_TAG, SUBCATEGORY_MASK, decay_taint, is_risk_tag, get_risk_subcategory};
use crate::oracle::consensus::{OracleConsensus, ConsensusResult};
use std::collections::HashMap;

/// Результат проверки Prisma Filter
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterResult {
    Accepted,
    RejectedByPolicy,
    RejectedByCategory,
    RejectedByTaint,
    RejectedByJurisdiction,
    RejectedByOracleConsensus,
    RejectedMissingProof,
    NeedsManualReview,
}

impl FilterResult {
    pub fn is_accepted(&self) -> bool { matches!(self, FilterResult::Accepted) }
    pub fn is_rejected(&self) -> bool { !self.is_accepted() }
}

/// Расширенный Prisma Filter с матрицей весов и проверкой taint
#[derive(Clone, Debug)]
pub struct PrismaFilter {
    pub policy: AcceptancePolicy,
    pub category_weights: HashMap<u64, u8>,
    pub category_threshold: u8,
    pub max_taint_distance: u16,
    pub taint_decay_enabled: bool,
    pub allowed_jurisdictions: Vec<u8>,
    pub blocked_jurisdictions: Vec<u8>,
    pub require_proof_of_innocence: bool,
    pub min_oracle_confirmations: u8,
    pub appeal_enabled: bool,
    pub default_action: FilterAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterAction {
    Accept,
    Reject,
    ManualReview,
}

impl Default for PrismaFilter {
    fn default() -> Self {
        PrismaFilter {
            policy: AcceptancePolicy::AcceptAll,
            category_weights: HashMap::new(),
            category_threshold: 75,
            max_taint_distance: 3,
            taint_decay_enabled: true,
            allowed_jurisdictions: Vec::new(),
            blocked_jurisdictions: Vec::new(),
            require_proof_of_innocence: false,
            min_oracle_confirmations: 2,
            appeal_enabled: false,
            default_action: FilterAction::Accept,
        }
    }
}

impl PrismaFilter {
    /// Создать строгий AML фильтр
    pub fn strict() -> Self {
        let mut weights = HashMap::new();
        weights.insert(0x010, 100); // SANCTIONS — мгновенный блок
        weights.insert(0x020, 100); // DARKNET
        weights.insert(0x030, 100); // RANSOMWARE
        weights.insert(0x040, 90);  // STOLEN
        weights.insert(0x050, 80);  // SCAM
        weights.insert(0x060, 50);  // MIXER
        weights.insert(0x070, 20);  // GAMBLING
        weights.insert(0x080, 30);  // NO_KYC_EXCHANGE
        weights.insert(0x0A0, 100); // CHILD_ABUSE
        weights.insert(0x0B0, 100); // HUMAN_TRAFFICKING
        PrismaFilter {
            policy: AcceptancePolicy::RejectAll,
            category_weights: weights,
            category_threshold: 50,
            max_taint_distance: 2,
            taint_decay_enabled: true,
            require_proof_of_innocence: true,
            min_oracle_confirmations: 2,
            appeal_enabled: true,
            default_action: FilterAction::Reject,
            ..Default::default()
        }
    }

    /// Создать либеральный фильтр (принимать почти всё)
    pub fn permissive() -> Self {
        PrismaFilter {
            policy: AcceptancePolicy::AcceptAll,
            max_taint_distance: 10,
            default_action: FilterAction::Accept,
            ..Default::default()
        }
    }

    /// Главная функция проверки UTXO
    pub fn check_utxo(
        &self,
        utxo: &JtUtxo,
        current_height: u64,
        consensus: Option<&ConsensusResult>,
    ) -> FilterResult {
        let level = utxo.restriction_level();
        let category = level & CATEGORY_MASK;

        // 1. Проверка юрисдикции
        let jurisdiction_code = (level & 0x0F) as u8;
        if self.blocked_jurisdictions.contains(&jurisdiction_code) {
            return FilterResult::RejectedByJurisdiction;
        }
        if !self.allowed_jurisdictions.is_empty()
            && !self.allowed_jurisdictions.contains(&jurisdiction_code)
        {
            return FilterResult::RejectedByJurisdiction;
        }

        // 2. Проверка категории риска через матрицу весов
        if category == CAT_RISK_TAG {
            let subcategory = (level & SUBCATEGORY_MASK) >> 4;
            if let Some(&weight) = self.category_weights.get(&subcategory) {
                if weight >= self.category_threshold {
                    return FilterResult::RejectedByCategory;
                }
            } else if self.default_action == FilterAction::Reject {
                return FilterResult::RejectedByCategory;
            }
        }

        // 3. Проверка taint distance
        let effective_taint = if self.taint_decay_enabled {
            decay_taint(utxo.taint_distance, utxo.taint_timestamp, current_height)
        } else {
            utxo.taint_distance
        };
        if effective_taint > self.max_taint_distance {
            return FilterResult::RejectedByTaint;
        }

        // 4. Проверка консенсуса оракулов
        if let Some(consensus) = consensus {
            match consensus {
                ConsensusResult::Accepted { risk_level, voting_oracles, .. } => {
                    if is_risk_tag(*risk_level) {
                        return FilterResult::RejectedByOracleConsensus;
                    }
                    if *voting_oracles < self.min_oracle_confirmations {
                        return FilterResult::NeedsManualReview;
                    }
                }
                ConsensusResult::NeedsReview => {
                    return FilterResult::NeedsManualReview;
                }
                ConsensusResult::NoConsensus { .. } => {
                    if self.default_action == FilterAction::Reject {
                        return FilterResult::RejectedByOracleConsensus;
                    }
                }
                ConsensusResult::Unknown => {}
            }
        }

        // 5. ZK-доказательство невиновности
        if self.require_proof_of_innocence
            && effective_taint > 0
            && !utxo.zk_proof().is_valid()
        {
            return FilterResult::RejectedMissingProof;
        }

        // 6. Проверка политики
        if !self.policy.accepts_level(level) {
            return FilterResult::RejectedByPolicy;
        }

        FilterResult::Accepted
    }

    /// Установить вес для подкатегории риска
    pub fn set_category_weight(&mut self, subcategory: u64, weight: u8) {
        self.category_weights.insert(subcategory, weight);
    }

    /// Заблокировать юрисдикцию
    pub fn block_jurisdiction(&mut self, code: u8) {
        if !self.blocked_jurisdictions.contains(&code) {
            self.blocked_jurisdictions.push(code);
        }
    }

    /// Разрешить юрисдикцию
    pub fn allow_jurisdiction(&mut self, code: u8) {
        self.blocked_jurisdictions.retain(|c| *c != code);
        if !self.allowed_jurisdictions.contains(&code) {
            self.allowed_jurisdictions.push(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::jt_utxo::{RESTRICTION_GLOBAL_CLEAN, RISK_SANCTIONS_IRAN, CAT_GLOBAL};
    use crate::core::transaction::TxOutput;
    use crate::crypto::keys::PublicKey;
    use crate::crypto::hash::Hash;

    fn dummy_utxo(level: u64) -> JtUtxo {
        JtUtxo::new_global_clean(PublicKey::dummy(), 100, &[1u8; 32], &[1u8; 32], 1, 1, Hash::zero()).map(|mut u| { u.restriction_level = level; u }).expect("dummy")
    }

    #[test]
    fn global_always_accepted() {
        let filter = PrismaFilter::strict();
        let utxo = dummy_utxo(RESTRICTION_GLOBAL_CLEAN);
        assert!(filter.check_utxo(&utxo, 100, None).is_accepted());
    }

    #[test]
    fn sanctions_rejected_by_strict() {
        let filter = PrismaFilter::strict();
        let utxo = dummy_utxo(RISK_SANCTIONS_IRAN);
        assert!(!filter.check_utxo(&utxo, 100, None).is_accepted());
    }

    #[test]
    fn sanctions_accepted_by_permissive() {
        let filter = PrismaFilter::permissive();
        let utxo = dummy_utxo(RISK_SANCTIONS_IRAN);
        assert!(filter.check_utxo(&utxo, 100, None).is_accepted());
    }

    #[test]
    fn taint_rejected_if_too_deep() {
        let filter = PrismaFilter::strict();
        let utxo = dummy_utxo(RESTRICTION_GLOBAL_CLEAN);
        let mut tainted = utxo.clone();
        tainted.taint_distance = 5;
        assert!(!filter.check_utxo(&tainted, 100, None).is_accepted());
    }

    #[test]
    fn taint_decay_allows_old_taint() {
        let filter = PrismaFilter::strict();
        let mut utxo = dummy_utxo(RESTRICTION_GLOBAL_CLEAN);
        utxo.taint_distance = 5;
        utxo.taint_timestamp = 100;
        // Прошло 200 000 блоков = 2 decay
        assert!(filter.check_utxo(&utxo, 200_100, None).is_accepted());
    }

    #[test]
    fn missing_proof_rejected() {
        let mut filter = PrismaFilter::strict();
        filter.require_proof_of_innocence = true;
        let mut utxo = dummy_utxo(RESTRICTION_GLOBAL_CLEAN);
        utxo.taint_distance = 1;
        assert!(!filter.check_utxo(&utxo, 100, None).is_accepted());
    }
}
