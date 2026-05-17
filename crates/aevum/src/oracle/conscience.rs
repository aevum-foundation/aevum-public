use crate::core::jt_utxo::JurisdictionCode;
use crate::crypto::hash::Hash;

#[derive(Clone, Debug)]
pub struct ConscienceOracle {
    jurisdictions: Vec<Jurisdiction>,
    state_hash: Hash,
    version: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jurisdiction {
    pub country_code: [u8; 2],
    pub name: String,
    pub allowed_tags: Vec<JurisdictionCode>,
    pub forbidden_tags: Vec<JurisdictionCode>,
}

impl ConscienceOracle {
    const DOMAIN_SEPARATOR: &[u8] = b"AEVUM_ORACLE_V1";
    const CURRENT_VERSION: u8 = 0x01;

    pub fn new() -> Self {
        ConscienceOracle {
            jurisdictions: Vec::new(),
            state_hash: Hash::zero(),
            version: Self::CURRENT_VERSION,
        }
    }

    pub fn add_jurisdiction(&mut self, jurisdiction: Jurisdiction) -> Result<(), &'static str> {
        if self
            .jurisdictions
            .iter()
            .any(|j| j.country_code == jurisdiction.country_code)
        {
            return Err("Jurisdiction already exists");
        }
        self.jurisdictions.push(jurisdiction);
        self.recompute_hash();
        Ok(())
    }

    pub fn add_tag_to_jurisdiction(
        &mut self,
        country_code: &[u8; 2],
        tag: &JurisdictionCode,
    ) -> Result<(), &str> {
        if let Some(jur) = self
            .jurisdictions
            .iter_mut()
            .find(|j| j.country_code == *country_code)
        {
            if !jur.allowed_tags.contains(tag) {
                jur.allowed_tags.push(*tag);
                jur.forbidden_tags.retain(|t| t != tag);
                self.recompute_hash();
            }
            Ok(())
        } else {
            Err("Jurisdiction not found")
        }
    }

    pub fn remove_tag_from_jurisdiction(
        &mut self,
        country_code: &[u8; 2],
        tag: &JurisdictionCode,
    ) -> Result<(), &str> {
        if let Some(jur) = self
            .jurisdictions
            .iter_mut()
            .find(|j| j.country_code == *country_code)
        {
            if !jur.forbidden_tags.contains(tag) {
                jur.forbidden_tags.push(*tag);
                jur.allowed_tags.retain(|t| t != tag);
                self.recompute_hash();
            }
            Ok(())
        } else {
            Err("Jurisdiction not found")
        }
    }

    pub fn is_tag_allowed(&self, country_code: &[u8; 2], tag: &JurisdictionCode) -> Option<bool> {
        let jurisdiction = self
            .jurisdictions
            .iter()
            .find(|j| j.country_code == *country_code)?;
        if jurisdiction.forbidden_tags.contains(tag) {
            return Some(false);
        }
        if jurisdiction.allowed_tags.contains(tag) {
            return Some(true);
        }
        Some(false)
    }

    pub fn state_hash(&self) -> Hash {
        self.state_hash
    }
    pub fn len(&self) -> usize {
        self.jurisdictions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.jurisdictions.is_empty()
    }

    fn recompute_hash(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(Self::DOMAIN_SEPARATOR);
        hasher.update(&[self.version]);
        let mut sorted: Vec<&Jurisdiction> = self.jurisdictions.iter().collect();
        sorted.sort_by(|a, b| a.country_code.cmp(&b.country_code));
        for j in sorted {
            hasher.update(&j.country_code);
            hasher.update(j.name.as_bytes());
            let mut allowed = j.allowed_tags.clone();
            allowed.sort();
            for tag in allowed {
                hasher.update(&tag);
            }
            let mut forbidden = j.forbidden_tags.clone();
            forbidden.sort();
            for tag in forbidden {
                hasher.update(&tag);
            }
        }
        self.state_hash = Hash(hasher.finalize().into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nl() -> Jurisdiction {
        Jurisdiction {
            country_code: *b"NL",
            name: "Netherlands".to_string(),
            allowed_tags: vec![*b"DEOK"],
            forbidden_tags: vec![],
        }
    }

    #[test]
    fn add_tag_works() {
        let mut oracle = ConscienceOracle::new();
        oracle.add_jurisdiction(nl()).unwrap();
        oracle.add_tag_to_jurisdiction(b"NL", b"NLOK").unwrap();
        assert_eq!(oracle.is_tag_allowed(b"NL", b"NLOK"), Some(true));
    }

    #[test]
    fn remove_tag_works() {
        let mut oracle = ConscienceOracle::new();
        oracle.add_jurisdiction(nl()).unwrap();
        oracle.remove_tag_from_jurisdiction(b"NL", b"DEOK").unwrap();
        assert_eq!(oracle.is_tag_allowed(b"NL", b"DEOK"), Some(false));
    }
}
