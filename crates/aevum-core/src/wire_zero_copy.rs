//! Wire Zero-Copy v3 — Cursor-Based Decoder Aligned with Canonical Wire Format.
//!
//! ## Design
//! - Cursor abstraction: safe, bounds-checked, no unwraps
//! - True zero-copy: all Views store only references to the original buffer
//! - Compatible with canonical wire.rs format (WIRE_VERSION = 5)
//! - Version validation: incompatible format → None
//! - BlockTxIter: lazy iteration over block transactions
//! - TxView.parsed_len: exact size of one transaction
//!
//! ## Wire Format (BlockWire)
//! [version:2][block_hash:32][prev_hash:32][height:8][poh_start:8][poh_end:8]
//! [tx_root:32][tx_count:4][transactions...][state_root:32][total_supply:8]
//! [is_presence:1][block_size:8]
//!
//! ## Performance
//! - Block header: 0 allocations
//! - Tx parse: 0 allocations, exact parsed_len
//! - Tx iteration: lazy, no double-parse
//! - Memory: ~80 bytes per BlockView, ~64 bytes per TxView

use crate::crypto::hash::Hash;

pub const EXPECTED_WIRE_VERSION: u16 = 5;
const BLOCK_HEADER_SIZE: usize = 2 + 32 + 32 + 8 + 8 + 8 + 32 + 4;

/// Safe cursor for sequential reading from a buffer.
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    #[inline]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    #[inline]
    pub fn position(&self) -> usize { self.pos }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    #[inline]
    fn read<const N: usize>(&mut self) -> Option<&'a [u8; N]> {
        let end = self.pos + N;
        if end > self.data.len() { return None; }
        let chunk = &self.data[self.pos..end];
        self.pos = end;
        Some(chunk.try_into().ok()?)
    }

    #[inline]
    pub fn u8(&mut self) -> Option<u8> {
        let bytes = self.read::<1>()?;
        Some(bytes[0])
    }

    #[inline]
    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(*self.read()?))
    }

    #[inline]
    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(*self.read()?))
    }

    #[inline]
    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(*self.read()?))
    }

    #[inline]
    pub fn hash(&mut self) -> Option<Hash> {
        let bytes = self.read::<32>()?;
        Some(Hash::from_bytes(bytes))
    }

    #[inline]
    pub fn slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos + len;
        if end > self.data.len() { return None; }
        let out = &self.data[self.pos..end];
        self.pos = end;
        Some(out)
    }

    #[inline]
    pub fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos + n;
        if end > self.data.len() { return None; }
        self.pos = end;
        Some(())
    }

    /// Skip TxInput: variable-length signature
    pub fn skip_inputs(&mut self, count: u32) -> Option<()> {
        for _ in 0..count {
            self.skip(32 + 4 + 32)?;
            let sig_len = self.u32()? as usize;
            self.skip(sig_len)?;
            self.skip(32 + 32 + 8)?;
        }
        Some(())
    }

    /// Skip TxOutput: variable-length zk_proof
    pub fn skip_outputs(&mut self, count: u32) -> Option<()> {
        for _ in 0..count {
            self.skip(8)?;   // amount
            self.skip(32)?;  // owner
            self.skip(32)?;  // amount_commitment
            self.skip(32)?;  // tag_commitment
            self.skip(32)?;  // nullifier
            self.skip(8)?;   // serial
            let zk_len = self.u32()? as usize;
            self.skip(zk_len)?;
            self.skip(32)?;  // tx_hash
            self.skip(32)?;  // view_key_public
            self.skip(8)?;   // encrypted_amount
            self.skip(8)?;   // auth_tag
            self.skip(8)?;   // restriction_level
            self.skip(4)?;   // output_index
        }
        Some(())
    }

    /// Skip heartbeat witnesses
    pub fn skip_witnesses(&mut self) -> Option<()> {
        let count = self.u32()? as usize;
        for _ in 0..count {
            let len = self.u32()? as usize;
            self.skip(len)?;
        }
        Some(())
    }
}

/// Zero-copy block header (header fields only, no transactions).
#[derive(Debug, Clone)]
pub struct BlockView<'a> {
    pub height: u64,
    pub poh_start: u64,
    pub poh_end: u64,
    pub prev_hash: Hash,
    pub block_hash: Hash,
    pub tx_count: u32,
    /// Reference to the original buffer (zero-copy)
    pub raw: &'a [u8],
}

impl<'a> BlockView<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);

        let version = c.u16()?;
        if version != EXPECTED_WIRE_VERSION { return None; }

        let block_hash = c.hash()?;
        let prev_hash = c.hash()?;
        let height = c.u64()?;
        let poh_start = c.u64()?;
        let poh_end = c.u64()?;
        let _tx_root = c.hash()?;
        let tx_count = c.u32()?;

        Some(Self { height, poh_start, poh_end, prev_hash, block_hash, tx_count, raw: data })
    }

    #[inline] pub fn has_transactions(&self) -> bool { self.tx_count > 0 }
    #[inline] pub fn is_genesis(&self) -> bool { self.height == 0 }
}

/// Zero-copy transaction with exact size.
#[derive(Debug, Clone)]
pub struct TxView<'a> {
    pub tx_hash: Hash,
    pub fee: u64,
    pub poh_tick: u64,
    pub locktime: u64,
    pub tx_type: u8,
    pub input_count: u32,
    pub output_count: u32,
    /// Exact number of bytes read from the buffer
    pub parsed_len: usize,
    /// Reference ONLY to the bytes of this transaction
    pub raw: &'a [u8],
}

impl<'a> TxView<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut c = Cursor::new(data);

        let version = c.u16()?;
        if version != EXPECTED_WIRE_VERSION { return None; }

        let _tx_version = c.u32()?;
        let _chain_id = c.u32()?;
        let tx_type = c.u8()?;

        let input_count = c.u32()?;
        c.skip_inputs(input_count)?;

        let output_count = c.u32()?;
        c.skip_outputs(output_count)?;

        let fee = c.u64()?;
        let tx_hash = c.hash()?;
        let poh_tick = c.u64()?;
        let locktime = c.u64()?;
        c.skip_witnesses()?;

        let parsed_len = c.position();
        let raw = &data[..parsed_len];

        Some(Self { tx_hash, fee, poh_tick, locktime, tx_type, input_count, output_count, parsed_len, raw })
    }

    #[inline] pub fn has_inputs(&self) -> bool { self.input_count > 0 }
    #[inline] pub fn has_outputs(&self) -> bool { self.output_count > 0 }
    #[inline] pub fn size(&self) -> usize { self.parsed_len }
    #[inline] pub fn is_coinbase(&self) -> bool { self.input_count == 0 && self.output_count > 0 }
    #[inline] pub fn is_heartbeat(&self) -> bool { self.tx_type == 2 }
}

/// Lazy iterator over block transactions.
pub struct BlockTxIter<'a> {
    cursor: Cursor<'a>,
    remaining: u32,
}

impl<'a> BlockTxIter<'a> {
    pub fn new(data: &'a [u8], offset: usize, tx_count: u32) -> Option<Self> {
        if offset > data.len() { return None; }
        let cursor = Cursor::new(&data[offset..]);
        Some(Self { cursor, remaining: tx_count })
    }
}

impl<'a> Iterator for BlockTxIter<'a> {
    type Item = TxView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 { return None; }

        let start = self.cursor.position();
        let remaining_data = self.cursor.data.get(start..)?;

        let tx = TxView::parse(remaining_data)?;
        self.cursor.skip(tx.parsed_len)?;
        self.remaining -= 1;

        Some(tx)
    }
}

/// Fast checks without full parsing.
pub struct FastValidator;

impl FastValidator {
    #[inline]
    pub fn check_block_size(data: &[u8], max: usize) -> bool {
        data.len() <= max
    }

    pub fn check_min_fee(data: &[u8], min_fee: u64) -> bool {
        let mut c = Cursor::new(data);

        let result = (|| {
            let v = c.u16()?;
            if v != EXPECTED_WIRE_VERSION { return None; }
            c.u32()?; c.u32()?; c.skip(1)?;
            let ic = c.u32()?; c.skip_inputs(ic)?;
            let oc = c.u32()?; c.skip_outputs(oc)?;
            c.u64()
        })();

        match result {
            Some(fee) => fee >= min_fee,
            None => false,
        }
    }

    #[inline]
    pub fn check_tx_size(data: &[u8], max: usize) -> bool {
        data.len() <= max
    }

    #[inline]
    pub fn check_not_empty(data: &[u8]) -> bool {
        data.len() > BLOCK_HEADER_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block_wire(height: u64, tx_count: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&EXPECTED_WIRE_VERSION.to_le_bytes());
        data.extend_from_slice(&[height as u8; 32]);
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(&(height * 100).to_le_bytes());
        data.extend_from_slice(&(height * 100 + 50).to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);
        data.extend_from_slice(&tx_count.to_le_bytes());
        data
    }

    fn make_tx_wire(fee: u64, poh_tick: u64, inputs: u32, outputs: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&EXPECTED_WIRE_VERSION.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.push(0u8);

        data.extend_from_slice(&inputs.to_le_bytes());
        for _ in 0..inputs {
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&0u64.to_le_bytes());
        }

        data.extend_from_slice(&outputs.to_le_bytes());
        for _ in 0..outputs {
            data.extend_from_slice(&0u64.to_le_bytes());
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&0u64.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 32]);
            data.extend_from_slice(&[0u8; 8]);
            data.extend_from_slice(&[0u8; 8]);
            data.extend_from_slice(&0u64.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
        }

        data.extend_from_slice(&fee.to_le_bytes());
        data.extend_from_slice(&[fee as u8; 32]);
        data.extend_from_slice(&poh_tick.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    #[test]
    fn parse_block_header() {
        let data = make_block_wire(42, 7);
        let view = BlockView::parse(&data).unwrap();
        assert_eq!(view.height, 42);
        assert_eq!(view.tx_count, 7);
        assert!(view.has_transactions());
    }

    #[test]
    fn parse_tx_view() {
        let data = make_tx_wire(500, 1000, 2, 1);
        let view = TxView::parse(&data).unwrap();
        assert_eq!(view.fee, 500);
        assert_eq!(view.poh_tick, 1000);
        assert_eq!(view.input_count, 2);
        assert_eq!(view.output_count, 1);
        assert!(!view.is_coinbase());
        assert!(!view.is_heartbeat());
    }

    #[test]
    fn parse_coinbase_tx() {
        let data = make_tx_wire(0, 100, 0, 1);
        let view = TxView::parse(&data).unwrap();
        assert!(view.is_coinbase());
        assert_eq!(view.input_count, 0);
    }

    #[test]
    fn parsed_len_is_exact() {
        let data = make_tx_wire(100, 0, 1, 1);
        let view = TxView::parse(&data).unwrap();
        assert_eq!(view.parsed_len, data.len());
        assert_eq!(view.raw.len(), data.len());
    }

    #[test]
    fn fast_check_min_fee_works() {
        let data = make_tx_wire(100, 0, 1, 1);
        assert!(FastValidator::check_min_fee(&data, 50));
        assert!(!FastValidator::check_min_fee(&data, 200));
    }

    #[test]
    fn fast_check_min_fee_short_data() {
        assert!(!FastValidator::check_min_fee(&[0u8; 10], 50));
    }

    #[test]
    fn version_mismatch_rejected() {
        let mut data = make_block_wire(1, 1);
        data[0] = 99;
        assert!(BlockView::parse(&data).is_none());
    }

    #[test]
    fn short_data_rejected() {
        assert!(BlockView::parse(&[0u8; 10]).is_none());
        assert!(TxView::parse(&[0u8; 10]).is_none());
    }

    #[test]
    fn block_tx_iter_multiple() {
        let mut data = make_block_wire(1, 3);
        // Add 3 transactions
        for i in 0..3 {
            let tx = make_tx_wire(100 + i as u64 * 10, i as u64 * 100, 1, 1);
            data.extend_from_slice(&tx);
        }

        let view = BlockView::parse(&data).unwrap();
        assert_eq!(view.tx_count, 3);

        let iter = BlockTxIter::new(&data, BLOCK_HEADER_SIZE, 3).unwrap();
        let txs: Vec<TxView> = iter.collect();
        assert_eq!(txs.len(), 3);
        assert_eq!(txs[0].fee, 100);
        assert_eq!(txs[1].fee, 110);
        assert_eq!(txs[2].fee, 120);
    }

    #[test]
    fn zero_copy_no_allocation() {
        let data = make_tx_wire(100, 0, 1, 1);
        let data_ptr = data.as_ptr();
        let view = TxView::parse(&data).unwrap();
        assert_eq!(view.raw.as_ptr(), data_ptr);
    }
}
