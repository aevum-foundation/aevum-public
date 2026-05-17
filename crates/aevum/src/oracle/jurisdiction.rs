use crate::core::jt_utxo::JurisdictionCode;
use crate::crypto::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalCode {
    pub country_code: [u8; 2],
    pub name: String,
    pub legal_categories: Vec<LegalCategory>,
    pub source_hash: Hash,
    pub version: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalCategory {
    pub tag: JurisdictionCode,
    pub description: String,
    pub legality: LegalityLevel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LegalityLevel {
    Prohibited = 0,
    Restricted = 1,
    Allowed = 2,
    Unregulated = 3,
}

impl LegalCode {
    pub fn from_json(_json: &str) -> Result<Self, &'static str> {
        Err("JSON import not implemented in v0.1")
    }

    pub fn to_json(&self) -> String {
        String::from("{}")
    }

    pub fn conflicts_with(&self, other: &LegalCode) -> Vec<JurisdictionCode> {
        let mut conflicts = Vec::new();
        for cat in &self.legal_categories {
            if let Some(other_cat) = other.legal_categories.iter().find(|c| c.tag == cat.tag) {
                if cat.legality >= LegalityLevel::Allowed
                    && other_cat.legality <= LegalityLevel::Restricted
                {
                    conflicts.push(cat.tag);
                }
                if other_cat.legality >= LegalityLevel::Allowed
                    && cat.legality <= LegalityLevel::Restricted
                {
                    if !conflicts.contains(&cat.tag) {
                        conflicts.push(cat.tag);
                    }
                }
            }
        }
        conflicts
    }

    pub fn is_allowed(&self, tag: &JurisdictionCode) -> Option<bool> {
        self.legal_categories
            .iter()
            .find(|c| c.tag == *tag)
            .map(|c| c.legality >= LegalityLevel::Allowed)
    }

    pub fn is_prohibited(&self, tag: &JurisdictionCode) -> Option<bool> {
        self.legal_categories
            .iter()
            .find(|c| c.tag == *tag)
            .map(|c| c.legality == LegalityLevel::Prohibited)
    }

    pub fn len(&self) -> usize {
        self.legal_categories.len()
    }
    pub fn is_empty(&self) -> bool {
        self.legal_categories.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nl_legal_code() -> LegalCode {
        LegalCode {
            country_code: *b"NL",
            name: "Netherlands".to_string(),
            legal_categories: vec![
                LegalCategory {
                    tag: *b"NLOK",
                    description: "Cannabis (licensed)".to_string(),
                    legality: LegalityLevel::Allowed,
                },
                LegalCategory {
                    tag: *b"ALCH",
                    description: "Alcohol".to_string(),
                    legality: LegalityLevel::Unregulated,
                },
            ],
            source_hash: Hash::zero(),
            version: 1,
        }
    }

    fn us_legal_code() -> LegalCode {
        LegalCode {
            country_code: *b"US",
            name: "United States".to_string(),
            legal_categories: vec![
                LegalCategory {
                    tag: *b"NLOK",
                    description: "Cannabis".to_string(),
                    legality: LegalityLevel::Prohibited,
                },
                LegalCategory {
                    tag: *b"ALCH",
                    description: "Alcohol".to_string(),
                    legality: LegalityLevel::Allowed,
                },
            ],
            source_hash: Hash::zero(),
            version: 1,
        }
    }

    #[test]
    fn is_allowed_returns_true() {
        assert_eq!(nl_legal_code().is_allowed(b"NLOK"), Some(true));
    }

    #[test]
    fn is_prohibited_returns_true() {
        assert_eq!(us_legal_code().is_prohibited(b"NLOK"), Some(true));
    }

    #[test]
    fn unknown_tag_returns_none() {
        assert_eq!(nl_legal_code().is_allowed(b"XXXX"), None);
    }

    #[test]
    fn conflicts_detects_nlok() {
        let conflicts = nl_legal_code().conflicts_with(&us_legal_code());
        assert!(conflicts.contains(b"NLOK"));
    }

    #[test]
    fn no_conflicts_same() {
        assert!(nl_legal_code().conflicts_with(&nl_legal_code()).is_empty());
    }

    #[test]
    fn legality_ordering() {
        assert!(LegalityLevel::Allowed > LegalityLevel::Restricted);
        assert!(LegalityLevel::Unregulated > LegalityLevel::Allowed);
        assert!(LegalityLevel::Prohibited < LegalityLevel::Restricted);
    }

    #[test]
    fn json_stubs() {
        let nl = nl_legal_code();
        assert_eq!(nl.to_json(), "{}");
        assert!(LegalCode::from_json("{}").is_err());
    }
}
