use crate::crypto::hash::Hash;

pub struct MerkleTree;

impl MerkleTree {
    pub fn root(leaves: &[Hash]) -> Hash {
        if leaves.is_empty() {
            return Hash::zero();
        }
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mut nodes: Vec<Hash> = leaves.to_vec();
        let mut level: u8 = 0;
        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in nodes.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"AEVUM_MERKLE_V1");
                hasher.update(&[level]);
                hasher.update(left.as_bytes());
                hasher.update(right.as_bytes());
                next_level.push(Hash(hasher.finalize().into()));
            }
            nodes = next_level;
            level += 1;
        }
        nodes[0]
    }

    pub fn proof(leaves: &[Hash], index: usize) -> Vec<(Hash, bool)> {
        if index >= leaves.len() {
            return vec![];
        }
        let mut proof = Vec::new();
        let mut nodes: Vec<Hash> = leaves.to_vec();
        let mut current_index = index;
        let mut level: u8 = 0;
        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for (i, chunk) in nodes.chunks(2).enumerate() {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                if i * 2 == current_index || i * 2 + 1 == current_index {
                    if current_index % 2 == 0 {
                        proof.push((right, true));
                    } else {
                        proof.push((left, false));
                    }
                }
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"AEVUM_MERKLE_V1");
                hasher.update(&[level]);
                hasher.update(left.as_bytes());
                hasher.update(right.as_bytes());
                next_level.push(Hash(hasher.finalize().into()));
            }
            nodes = next_level;
            current_index /= 2;
            level += 1;
        }
        proof
    }

    pub fn verify_proof(root: &Hash, leaf: &Hash, proof: &[(Hash, bool)], index: usize) -> bool {
        let mut current = *leaf;
        let mut current_index = index;
        let mut level: u8 = 0;
        for (sibling, is_right) in proof {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"AEVUM_MERKLE_V1");
            hasher.update(&[level]);
            if *is_right {
                hasher.update(current.as_bytes());
                hasher.update(sibling.as_bytes());
            } else {
                hasher.update(sibling.as_bytes());
                hasher.update(current.as_bytes());
            }
            current = Hash(hasher.finalize().into());
            current_index /= 2;
            level += 1;
        }
        current == *root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree() {
        assert_eq!(MerkleTree::root(&[]), Hash::zero());
    }
    #[test]
    fn single_leaf() {
        assert_eq!(MerkleTree::root(&[Hash([1u8; 32])]), Hash([1u8; 32]));
    }
    #[test]
    fn two_leaves() {
        assert_ne!(
            MerkleTree::root(&[Hash([1u8; 32]), Hash([2u8; 32])]),
            Hash([1u8; 32])
        );
    }
    #[test]
    fn proof_verification() {
        let leaves: Vec<Hash> = (0..8).map(|i| Hash([i as u8; 32])).collect();
        let root = MerkleTree::root(&leaves);
        for i in 0..8 {
            assert!(MerkleTree::verify_proof(
                &root,
                &leaves[i],
                &MerkleTree::proof(&leaves, i),
                i
            ));
        }
    }
    #[test]
    fn proof_rejects_wrong_leaf() {
        let leaves: Vec<Hash> = (0..4).map(|i| Hash([i as u8; 32])).collect();
        let root = MerkleTree::root(&leaves);
        assert!(!MerkleTree::verify_proof(
            &root,
            &Hash([99u8; 32]),
            &MerkleTree::proof(&leaves, 0),
            0
        ));
    }
    #[test]
    fn odd_leaves() {
        let leaves: Vec<Hash> = (0..5).map(|i| Hash([i as u8; 32])).collect();
        let root = MerkleTree::root(&leaves);
        for i in 0..5 {
            assert!(MerkleTree::verify_proof(
                &root,
                &leaves[i],
                &MerkleTree::proof(&leaves, i),
                i
            ));
        }
    }
}
