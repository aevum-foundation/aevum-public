//! DNA Range Tree v4 — Asset Provenance Layer
//!
//! Production lineage tracking for L1 -> L2.
//!
//! Properties:
//! - No per-satoshi storage
//! - Range based ownership tracking
//! - Genesis / Epoch / Remainder immutable origin
//! - Full lineage back to genesis
//! - Supply conservation checks
//! - Bridge provenance support
//! - L2 compatible

use crate::crypto::hash::Hash;
use serde::{Deserialize, Serialize};
use blake3;

const DOMAIN: &[u8] = b"AEVUM_DNA_RANGE_V4";

pub const SATOSHIS_PER_AEV: u64 = 100_000_000;
pub const GENESIS_SUPPLY: u64 = 21_000_000 * SATOSHIS_PER_AEV;
pub const MAX_SUPPLY: u64 = 371_000_000 * SATOSHIS_PER_AEV;


// ─────────────────────────────────────────────
// Origin
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnaOrigin {

    Genesis,

    EpochMining {
        epoch: u64,
        event_id: Hash,
    },

    EpochRemainder {
        epoch: u64,
        event_id: Hash,
    },
}

impl DnaOrigin {

    pub fn bytes(&self) -> Vec<u8> {
        match self {

            Self::Genesis => vec![0],

            Self::EpochMining { epoch, event_id } => {
                let mut v = vec![1];
                v.extend_from_slice(&epoch.to_le_bytes());
                v.extend_from_slice(event_id.as_bytes());
                v
            }

            Self::EpochRemainder { epoch, event_id } => {
                let mut v = vec![2];
                v.extend_from_slice(&epoch.to_le_bytes());
                v.extend_from_slice(event_id.as_bytes());
                v
            }
        }
    }

    pub fn epoch(&self) -> Option<u64> {
        match self {
            Self::Genesis => None,
            Self::EpochMining {epoch,..} => Some(*epoch),
            Self::EpochRemainder {epoch,..} => Some(*epoch),
        }
    }
}


// ─────────────────────────────────────────────
// Layer
// ─────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnaLayer {
    L1,
    L2,
}


// ─────────────────────────────────────────────
// DNA Range
// ─────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnaRange {

    pub range_id: Hash,

    /// Original emission root
    pub root_id: Hash,

    pub origin: DnaOrigin,

    /// Global satoshi interval
    pub start: u64,
    pub end: u64,


    pub layer: DnaLayer,


    pub birth_epoch: u64,
    pub birth_height: u64,
    pub birth_timestamp: u64,


    pub miner: [u8;32],


    /// Previous DNA state
    pub parent_range_id: Option<Hash>,


    /// L1 burn -> L2 bridge reference
    pub bridge_tx: Option<Hash>,


    /// Transaction creating current split
    pub creation_tx: Option<Hash>,


    pub owner: [u8;32],


    pub transfer_count: u32,

    pub last_transfer_block: u64,


    pub proof: Hash,
}



impl DnaRange {


    pub fn new_genesis(
        root_id: Hash,
        owner: [u8;32],
        height:u64,
        timestamp:u64,
    )->Self {

        let mut r = Self {

            range_id:Hash::zero(),
            root_id,
            origin:DnaOrigin::Genesis,

            start:0,
            end:GENESIS_SUPPLY-1,

            layer:DnaLayer::L1,

            birth_epoch:0,
            birth_height:height,
            birth_timestamp:timestamp,

            miner:[0u8;32],

            parent_range_id:None,

            bridge_tx:None,
            creation_tx:None,

            owner,

            transfer_count:0,
            last_transfer_block:height,

            proof:Hash::zero(),
        };


        r.range_id=r.id();
        r.proof=r.hash();

        r
    }



    pub fn new_epoch(
        root_id:Hash,
        origin:DnaOrigin,
        start:u64,
        end:u64,
        epoch:u64,
        height:u64,
        timestamp:u64,
        miner:[u8;32],
        owner:[u8;32],

    )->Self {


        let mut r=Self {

            range_id:Hash::zero(),

            root_id,

            origin,

            start,
            end,

            layer:DnaLayer::L1,

            birth_epoch:epoch,
            birth_height:height,
            birth_timestamp:timestamp,

            miner,

            parent_range_id:None,

            bridge_tx:None,
            creation_tx:None,

            owner,

            transfer_count:0,
            last_transfer_block:height,

            proof:Hash::zero(),
        };


        r.range_id=r.id();
        r.proof=r.hash();

        r
    }



    pub fn split(
        &self,
        point:u64,
        left:[u8;32],
        right:[u8;32],
        tx:Hash,
        block:u64,

    )->Result<(Self,Self), &'static str>{


        if point<=self.start || point>self.end {
            return Err("invalid split");
        }


        let a=self.child(
            self.start,
            point-1,
            left,
            tx,
            block
        );


        let b=self.child(
            point,
            self.end,
            right,
            tx,
            block
        );


        if !Self::verify_split(self,&a,&b){
            return Err("supply violation");
        }


        Ok((a,b))
    }



    fn child(
        &self,
        start:u64,
        end:u64,
        owner:[u8;32],
        tx:Hash,
        block:u64,

    )->Self {


        let mut r=Self {

            range_id:Hash::zero(),

            root_id:self.root_id,

            origin:self.origin.clone(),

            start,
            end,

            layer:self.layer,

            birth_epoch:self.birth_epoch,
            birth_height:self.birth_height,
            birth_timestamp:self.birth_timestamp,

            miner:self.miner,


            parent_range_id:Some(self.range_id),


            bridge_tx:self.bridge_tx,

            creation_tx:Some(tx),


            owner,

            transfer_count:self.transfer_count+1,

            last_transfer_block:block,


            proof:Hash::zero(),
        };


        r.range_id=r.id();
        r.proof=r.hash();

        r
    }



    pub fn bridge_to_l2(
        &mut self,
        bridge:Hash
    ){

        self.layer=DnaLayer::L2;
        self.bridge_tx=Some(bridge);

        self.range_id=self.id();
        self.proof=self.hash();

    }



    pub fn verify_split(
        parent:&Self,
        a:&Self,
        b:&Self

    )->bool {


        a.start==parent.start
        &&
        b.end==parent.end
        &&
        a.end+1==b.start
        &&
        parent.amount()==a.amount()+b.amount()
    }



    pub fn verify(&self)->bool {

        self.range_id==self.id()
        &&
        self.proof==self.hash()
        &&
        self.start<=self.end

    }



    pub fn verify_lineage(
        parent:&Self,
        child:&Self
    )->bool {

        child.parent_range_id==Some(parent.range_id)
        &&
        child.root_id==parent.root_id

    }



    pub fn amount(&self)->u64 {

        self.end-self.start+1

    }



    pub fn id(&self)->Hash {

        let mut h=blake3::Hasher::new();

        h.update(DOMAIN);
        h.update(b"ID");

        h.update(self.root_id.as_bytes());

        if let Some(p)=self.parent_range_id {
            h.update(p.as_bytes());
        }

        h.update(&self.start.to_le_bytes());
        h.update(&self.end.to_le_bytes());


        Hash(h.finalize().into())

    }



    pub fn hash(&self)->Hash {


        let mut h=blake3::Hasher::new();

        h.update(DOMAIN);
        h.update(b"PROOF");

        h.update(&self.origin.bytes());

        h.update(self.root_id.as_bytes());

        h.update(&self.start.to_le_bytes());
        h.update(&self.end.to_le_bytes());


        h.update(&self.birth_epoch.to_le_bytes());
        h.update(&self.birth_height.to_le_bytes());


        if let Some(p)=self.parent_range_id {
            h.update(p.as_bytes());
        }


        if let Some(b)=self.bridge_tx {
            h.update(b.as_bytes());
        }


        h.update(&self.owner);


        Hash(h.finalize().into())

    }



    pub fn contains(&self,s:u64)->bool{

        s>=self.start && s<=self.end

    }

}


pub fn emission_event(
    epoch:u64,
    height:u64,
    reward:u64,
    participants:u64

)->Hash {


    let mut h=blake3::Hasher::new();

    h.update(b"AEVUM_EMISSION_V4");

    h.update(&epoch.to_le_bytes());
    h.update(&height.to_le_bytes());
    h.update(&reward.to_le_bytes());
    h.update(&participants.to_le_bytes());


    Hash(h.finalize().into())

}


pub const fn aev_to_satoshi(v:u64)->u64{

    v*SATOSHIS_PER_AEV

}
