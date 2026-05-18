use crate::crypto::hash::Hash;

/// Тип zk-доказательства
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofType {
    /// Доказательство принадлежности тега юрисдикции
    JurisdictionTag,
    /// Доказательство знания blinding'а для коммитмента
    CommitmentBlinding,
    /// Доказательство корректности перевода (сумма входов = сумма выходов)
    TransactionBalance,
    /// Доказательство решения полезной задачи
    UsefulSolution,
}

/// Zk-доказательство (v0.2 — заглушка, v1.0 — Halo2)
#[derive(Clone, Debug)]
pub struct ZkProof {
    /// Тип доказательства
    pub proof_type: ZkProofType,
    /// Публичные входы (доступны всем)
    pub public_inputs: Vec<Hash>,
    /// Данные доказательства (Halo2 proof bytes)
    pub proof_data: Vec<u8>,
}

impl ZkProof {
    /// Создать новое доказательство (v0.2 — заглушка)
    pub fn new(proof_type: ZkProofType, public_inputs: Vec<Hash>) -> Self {
        ZkProof {
            proof_type,
            public_inputs,
            proof_data: Vec::new(),
        }
    }

    /// Проверить доказательство (v0.2 — простая проверка)
    pub fn verify(&self) -> bool {
        // v0.2: проверяем что публичные входы не пусты и соответствуют типу
        if self.public_inputs.is_empty() {
            return false;
        }
        match self.proof_type {
            ZkProofType::TransactionBalance => self.public_inputs.len() >= 2,
            ZkProofType::JurisdictionTag => self.public_inputs.len() >= 1,
            ZkProofType::CommitmentBlinding => self.public_inputs.len() >= 2,
            ZkProofType::UsefulSolution => self.public_inputs.len() >= 1,
        }
    }

    /// Сериализовать в байты для хранения
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(self.proof_type.clone() as u8);
        for input in &self.public_inputs {
            data.extend_from_slice(input.as_bytes());
        }
        data.extend_from_slice(&self.proof_data);
        data
    }

    /// Десериализовать из байт
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 33 {
            return None;
        }
        let proof_type = match data[0] {
            0 => ZkProofType::JurisdictionTag,
            1 => ZkProofType::CommitmentBlinding,
            2 => ZkProofType::TransactionBalance,
            3 => ZkProofType::UsefulSolution,
            _ => return None,
        };
        let count = match proof_type {
            ZkProofType::TransactionBalance | ZkProofType::CommitmentBlinding => 2,
            ZkProofType::JurisdictionTag | ZkProofType::UsefulSolution => 1,
        };
        if data.len() < 1 + count * 32 {
            return None;
        }
        let mut public_inputs = Vec::new();
        for i in 0..count {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[1 + i * 32..1 + (i + 1) * 32]);
            public_inputs.push(Hash(hash));
        }
        let proof_data = data[1 + count * 32..].to_vec();
        Some(ZkProof {
            proof_type,
            public_inputs,
            proof_data,
        })
    }
}

/// Генератор zk-доказательств (v0.2 — заглушка)
pub struct ZkProver;

impl ZkProver {
    /// Создать доказательство принадлежности тега юрисдикции
    pub fn prove_jurisdiction_tag(tag_hash: Hash, jurisdiction_hash: Hash) -> ZkProof {
        ZkProof::new(ZkProofType::JurisdictionTag, vec![tag_hash])
    }

    /// Создать доказательство знания blinding
    pub fn prove_blinding(commitment: Hash, blinding: Hash) -> ZkProof {
        ZkProof::new(ZkProofType::CommitmentBlinding, vec![commitment, blinding])
    }

    /// Создать доказательство баланса
    pub fn prove_balance(input_sum: Hash, output_sum: Hash) -> ZkProof {
        ZkProof::new(ZkProofType::TransactionBalance, vec![input_sum, output_sum])
    }

    /// Создать доказательство решения задачи
    pub fn prove_useful_solution(output_hash: Hash) -> ZkProof {
        ZkProof::new(ZkProofType::UsefulSolution, vec![output_hash])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_creation_and_verification() {
        let proof = ZkProver::prove_jurisdiction_tag(Hash([1u8; 32]), Hash([2u8; 32]));
        assert!(proof.verify());
    }

    #[test]
    fn balance_proof_requires_two_inputs() {
        let proof = ZkProver::prove_balance(Hash([1u8; 32]), Hash([2u8; 32]));
        assert!(proof.verify());
    }

    #[test]
    fn serialization_roundtrip() {
        let proof = ZkProver::prove_blinding(Hash([3u8; 32]), Hash([4u8; 32]));
        let bytes = proof.to_bytes();
        let restored = ZkProof::from_bytes(&bytes).unwrap();
        assert!(restored.verify());
        assert_eq!(restored.proof_type, proof.proof_type);
    }
}
