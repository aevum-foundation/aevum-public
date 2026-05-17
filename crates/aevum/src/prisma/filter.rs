use crate::core::address::AcceptancePolicy;
use crate::core::address::AcceptanceRule;
use crate::core::jt_utxo::RestrictionLevel;

pub fn check_policy(
    policy: &AcceptancePolicy,
    level: &RestrictionLevel,
    specific_jurisdiction: Option<&[u8; 4]>,
) -> FilterResult {
    match policy {
        AcceptancePolicy::AcceptAll => FilterResult::Accepted,
        AcceptancePolicy::RejectAll => FilterResult::RejectedByPolicy,
        AcceptancePolicy::Whitelist(rules) => {
            if rules
                .iter()
                .any(|rule| rule.matches(level, specific_jurisdiction))
            {
                FilterResult::Accepted
            } else {
                FilterResult::RejectedByTag
            }
        }
        AcceptancePolicy::Blacklist(rules) => {
            if rules
                .iter()
                .any(|rule| rule.matches(level, specific_jurisdiction))
            {
                FilterResult::RejectedByPolicy
            } else {
                FilterResult::Accepted
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterResult {
    Accepted,
    RejectedByPolicy,
    RejectedByTag,
    RejectedByJurisdiction,
}

impl FilterResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, FilterResult::Accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_all_passes() {
        assert!(check_policy(
            &AcceptancePolicy::AcceptAll,
            &RestrictionLevel::ProvenanceNull,
            None
        )
        .is_accepted());
    }

    #[test]
    fn reject_all_blocks() {
        assert_eq!(
            check_policy(
                &AcceptancePolicy::RejectAll,
                &RestrictionLevel::GlobalClean,
                None
            ),
            FilterResult::RejectedByPolicy
        );
    }

    #[test]
    fn whitelist_accepts_matching_level() {
        let p =
            AcceptancePolicy::Whitelist(vec![AcceptanceRule::Level(RestrictionLevel::GlobalClean)]);
        assert_eq!(
            check_policy(&p, &RestrictionLevel::GlobalClean, None),
            FilterResult::Accepted
        );
    }

    #[test]
    fn whitelist_rejects_non_matching_level() {
        let p =
            AcceptancePolicy::Whitelist(vec![AcceptanceRule::Level(RestrictionLevel::GlobalClean)]);
        assert_eq!(
            check_policy(&p, &RestrictionLevel::ProvenanceNull, None),
            FilterResult::RejectedByTag
        );
    }

    #[test]
    fn blacklist_blocks_listed_level() {
        let p = AcceptancePolicy::Blacklist(vec![AcceptanceRule::Level(
            RestrictionLevel::ProvenanceNull,
        )]);
        assert_eq!(
            check_policy(&p, &RestrictionLevel::ProvenanceNull, None),
            FilterResult::RejectedByPolicy
        );
    }

    #[test]
    fn blacklist_passes_unlisted_level() {
        let p = AcceptancePolicy::Blacklist(vec![AcceptanceRule::Level(
            RestrictionLevel::ProvenanceNull,
        )]);
        assert_eq!(
            check_policy(&p, &RestrictionLevel::GlobalClean, None),
            FilterResult::Accepted
        );
    }

    #[test]
    fn jurisdiction_matches_restricted_utxo() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Jurisdiction(*b"NLOK")]);
        let l = RestrictionLevel::Restricted {
            allowed: vec![*b"NLOK", *b"DEOK"],
        };
        assert_eq!(check_policy(&p, &l, None), FilterResult::Accepted);
    }

    #[test]
    fn jurisdiction_rejects_non_matching() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Jurisdiction(*b"USOK")]);
        let l = RestrictionLevel::Restricted {
            allowed: vec![*b"NLOK"],
        };
        assert_eq!(check_policy(&p, &l, None), FilterResult::RejectedByTag);
    }

    #[test]
    fn specific_jurisdiction_matches_exact() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Jurisdiction(*b"NLOK")]);
        let l = RestrictionLevel::Restricted {
            allowed: vec![*b"NLOK", *b"DEOK"],
        };
        assert_eq!(check_policy(&p, &l, Some(b"NLOK")), FilterResult::Accepted);
    }

    #[test]
    fn specific_jurisdiction_rejects_wrong() {
        let p = AcceptancePolicy::Whitelist(vec![AcceptanceRule::Jurisdiction(*b"NLOK")]);
        let l = RestrictionLevel::Restricted {
            allowed: vec![*b"DEOK"],
        };
        assert_eq!(
            check_policy(&p, &l, Some(b"USOK")),
            FilterResult::RejectedByTag
        );
    }
}
