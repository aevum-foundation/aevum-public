use crate::oracle::conscience::ConscienceOracle;
use crate::core::jt_utxo::JurisdictionCode;
use crate::crypto::hash::Hash;
use crate::crypto::keys::PublicKey;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug)]
pub struct Proposal {
    pub id: Hash,
    pub proposer: PublicKey,
    pub country_code: [u8; 2],
    pub tag: JurisdictionCode,
    pub action: ProposalAction,
    pub start_height: u64,
    pub end_height: u64,
    pub votes_for_hashrate: u64,
    pub votes_against_hashrate: u64,
    pub voters: HashSet<[u8; 32]>,
    pub finalized: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalAction { Add, Remove }

pub struct Governance {
    proposals: HashMap<Hash, Proposal>,
    finalized_proposals: HashMap<Hash, Proposal>,
    oracle: ConscienceOracle,
    voting_period: u64,
    voting_delay: u64,
    threshold_percent: u8,
    miner_hashrate: HashMap<[u8; 32], (u64, u64)>,
    total_hashrate: u64,
    min_proposal_hashrate: u64,
    hashrate_expiry_blocks: u64,
}

impl Governance {
    pub fn new(oracle: ConscienceOracle) -> Self {
        Governance {
            proposals: HashMap::new(),
            finalized_proposals: HashMap::new(),
            oracle,
            voting_period: 1000,
            voting_delay: 100,
            threshold_percent: 51,
            miner_hashrate: HashMap::new(),
            total_hashrate: 0,
            min_proposal_hashrate: 10,
            hashrate_expiry_blocks: 5000,
        }
    }

    pub fn update_hashrate(&mut self, miner: &PublicKey, hashrate: u64, current_height: u64) {
        let key = miner.to_bytes();
        let old = self.miner_hashrate.get(&key).map(|(h, _)| *h).unwrap_or(0);
        self.miner_hashrate.insert(key, (hashrate, current_height));
        self.total_hashrate = self.total_hashrate.saturating_sub(old).saturating_add(hashrate);
    }

    pub fn expire_stale_hashrate(&mut self, current_height: u64) {
        let expiry_threshold = current_height.saturating_sub(self.hashrate_expiry_blocks);
        let stale_keys: Vec<[u8; 32]> = self.miner_hashrate
            .iter()
            .filter(|(_, (_, last_updated))| *last_updated < expiry_threshold)
            .map(|(k, _)| *k)
            .collect();
        for key in stale_keys {
            if let Some((hashrate, _)) = self.miner_hashrate.remove(&key) {
                self.total_hashrate = self.total_hashrate.saturating_sub(hashrate);
            }
        }
    }

    pub fn vote_weight(&self, miner: &PublicKey) -> u64 {
        let key = miner.to_bytes();
        self.miner_hashrate.get(&key).map(|(h, _)| *h).unwrap_or(0)
    }

    pub fn propose(&mut self, proposer: PublicKey, country_code: [u8; 2], tag: JurisdictionCode, action: ProposalAction, current_height: u64) -> Result<Hash, &'static str> {
        let proposer_weight = self.vote_weight(&proposer);
        if proposer_weight < self.min_proposal_hashrate {
            return Err("Insufficient hashrate to propose");
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"AEVUM_PROPOSAL_V4");
        hasher.update(proposer.as_bytes());
        hasher.update(&country_code);
        hasher.update(&tag);
        hasher.update(&action.to_bytes()[..]);
        hasher.update(&current_height.to_le_bytes());
        let id = Hash(hasher.finalize().into());
        self.proposals.insert(id, Proposal {
            id, proposer, country_code, tag, action,
            start_height: current_height + self.voting_delay,
            end_height: current_height + self.voting_delay + self.voting_period,
            votes_for_hashrate: 0, votes_against_hashrate: 0,
            voters: HashSet::new(), finalized: false,
        });
        Ok(id)
    }

    pub fn vote(&mut self, proposal_id: &Hash, vote_for: bool, voter: PublicKey, signature: &[u8; 64], current_height: u64) -> Result<(), &'static str> {
        let hashrate = self.vote_weight(&voter);
        if hashrate == 0 { return Err("Vote rejected"); }
        let proposal = self.proposals.get_mut(proposal_id).ok_or("Vote rejected")?;
        let mut message = Vec::with_capacity(32 + 1 + 8);
        message.extend_from_slice(proposal_id.as_bytes());
        message.push(vote_for as u8);
        message.extend_from_slice(&current_height.to_le_bytes());
        if !voter.verify(&message, signature) { return Err("Vote rejected"); }
        if current_height < proposal.start_height { return Err("Vote rejected"); }
        if current_height > proposal.end_height { return Err("Vote rejected"); }
        let voter_bytes = voter.to_bytes();
        if proposal.voters.contains(&voter_bytes) { return Err("Vote rejected"); }
        proposal.voters.insert(voter_bytes);
        if vote_for {
            proposal.votes_for_hashrate = proposal.votes_for_hashrate.saturating_add(hashrate);
        } else {
            proposal.votes_against_hashrate = proposal.votes_against_hashrate.saturating_add(hashrate);
        }
        Ok(())
    }

    pub fn finalize(&mut self, proposal_id: &Hash, current_height: u64) -> Result<bool, &'static str> {
        self.expire_stale_hashrate(current_height);
        let for_percent;
        let passed;
        let action;
        let country_code;
        let tag;
        {
            let proposal = self.proposals.get(proposal_id).ok_or("Proposal rejected")?;
            if proposal.finalized { return Err("Proposal rejected"); }
            if current_height < proposal.end_height { return Err("Proposal rejected"); }
            let total_voted = proposal.votes_for_hashrate + proposal.votes_against_hashrate;
            if total_voted == 0 || self.total_hashrate == 0 {
                let mut p = self.proposals.remove(proposal_id).unwrap();
                p.finalized = true;
                self.finalized_proposals.insert(p.id, p);
                return Ok(false);
            }
            for_percent = (proposal.votes_for_hashrate * 100) / self.total_hashrate;
            passed = for_percent >= self.threshold_percent as u64;
            action = proposal.action.clone();
            country_code = proposal.country_code;
            tag = proposal.tag;
        }
        if passed {
            match action {
                ProposalAction::Add => { self.oracle.add_tag_to_jurisdiction(&country_code, &tag).ok(); }
                ProposalAction::Remove => { self.oracle.remove_tag_from_jurisdiction(&country_code, &tag).ok(); }
            }
        }
        let mut p = self.proposals.remove(proposal_id).unwrap();
        p.finalized = true;
        self.finalized_proposals.insert(p.id, p);
        Ok(passed)
    }

    pub fn oracle(&self) -> &ConscienceOracle { &self.oracle }
    pub fn active_proposals(&self) -> Vec<&Proposal> { self.proposals.values().filter(|p| !p.finalized).collect() }
    pub fn finalized_proposals(&self) -> Vec<&Proposal> { self.finalized_proposals.values().collect() }
    pub fn get_proposal(&self, id: &Hash) -> Option<&Proposal> { self.proposals.get(id).or_else(|| self.finalized_proposals.get(id)) }
    pub fn total_hashrate(&self) -> u64 { self.total_hashrate }
}

impl ProposalAction {
    fn to_bytes(&self) -> [u8; 1] {
        match self { ProposalAction::Add => [0], ProposalAction::Remove => [1] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{PrivateKey, Keypair};

    fn random_keypair() -> (PublicKey, PrivateKey) { let kp = Keypair::generate(); (kp.public, kp.private) }

    fn sign_vote(proposal_id: &Hash, vote_for: bool, height: u64, private: &PrivateKey) -> [u8; 64] {
        let mut message = Vec::with_capacity(32 + 1 + 8);
        message.extend_from_slice(proposal_id.as_bytes());
        message.push(vote_for as u8);
        message.extend_from_slice(&height.to_le_bytes());
        private.sign(&message)
    }

    #[test]
    fn hashrate_weighted_voting() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m1, _) = random_keypair(); let (m2, _) = random_keypair();
        gov.update_hashrate(&m1, 1000, 100); gov.update_hashrate(&m2, 100, 100);
        assert!(gov.vote_weight(&m1) > gov.vote_weight(&m2));
    }

    #[test]
    fn proposal_with_weighted_votes() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m1, sk1) = random_keypair(); let (m2, sk2) = random_keypair();
        gov.update_hashrate(&m1, 900, 100); gov.update_hashrate(&m2, 100, 100);
        let id = gov.propose(m1.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        gov.vote(&id, true, m1, &sign_vote(&id, true, 300, &sk1), 300).unwrap();
        gov.vote(&id, false, m2, &sign_vote(&id, false, 301, &sk2), 301).unwrap();
        assert!(gov.finalize(&id, 2000).unwrap());
    }

    #[test]
    fn cannot_reuse_signature_with_different_vote() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, sk) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        let id = gov.propose(m.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        let sig = sign_vote(&id, true, 300, &sk);
        assert!(gov.vote(&id, false, m, &sig, 300).is_err());
    }

    #[test]
    fn cannot_reuse_signature_at_different_height() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, sk) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        let id = gov.propose(m.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        let sig = sign_vote(&id, true, 300, &sk);
        assert!(gov.vote(&id, true, m, &sig, 400).is_err());
    }

    #[test]
    fn cannot_vote_without_signature() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, _) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        let id = gov.propose(m.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        assert!(gov.vote(&id, true, m, &[0u8; 64], 300).is_err());
    }

    #[test]
    fn cannot_vote_before_start() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, sk) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        let id = gov.propose(m.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        assert!(gov.vote(&id, true, m, &sign_vote(&id, true, 250, &sk), 250).is_err());
    }

    #[test]
    fn cannot_vote_after_period() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, sk) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        let id = gov.propose(m.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        assert!(gov.vote(&id, true, m, &sign_vote(&id, true, 2000, &sk), 2000).is_err());
    }

    #[test]
    fn cannot_finalize_twice() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, sk) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        let id = gov.propose(m.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        gov.vote(&id, true, m, &sign_vote(&id, true, 300, &sk), 300).unwrap();
        assert!(gov.finalize(&id, 2000).unwrap());
        assert!(gov.finalize(&id, 2000).is_err());
    }

    #[test]
    fn proposer_needs_minimum_hashrate() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, _) = random_keypair();
        assert!(gov.propose(m, *b"NL", *b"NLOK", ProposalAction::Add, 200).is_err());
    }

    #[test]
    fn stale_hashrate_expires() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, _) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        assert_eq!(gov.vote_weight(&m), 100);
        gov.expire_stale_hashrate(100 + 5000 + 1);
        assert_eq!(gov.vote_weight(&m), 0);
    }

    #[test]
    fn finalized_proposals_are_archived() {
        let mut gov = Governance::new(ConscienceOracle::new());
        let (m, sk) = random_keypair(); gov.update_hashrate(&m, 100, 100);
        let id = gov.propose(m.clone(), *b"NL", *b"NLOK", ProposalAction::Add, 200).unwrap();
        gov.vote(&id, true, m, &sign_vote(&id, true, 300, &sk), 300).unwrap();
        gov.finalize(&id, 2000).unwrap();
        assert!(gov.active_proposals().is_empty());
        assert_eq!(gov.finalized_proposals().len(), 1);
        assert!(gov.get_proposal(&id).is_some());
    }
}
