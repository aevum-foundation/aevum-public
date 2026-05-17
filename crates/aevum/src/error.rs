use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum AevumError {
    // Криптография
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    VerificationFailed,

    // Транзакции
    TxNotFound,
    TxInvalid,
    TxDoubleSpend,
    TxBalanceMismatch,
    TxSignatureMissing,

    // Блоки
    BlockNotFound,
    BlockInvalid,
    BlockPrevHashMismatch,
    BlockHeightMismatch,
    BlockPoHOverlap,
    BlockPoHFuture,
    BlockEmpty,
    BlockGenesisAlreadyApplied,
    BlockGenesisNotApplied,

    // UTXO
    UtxoNotFound,
    UtxoAlreadySpent,

    // Мемпул
    MempoolFull,
    MempoolTxTooOld,

    // Оракул
    JurisdictionNotFound,
    JurisdictionAlreadyExists,
    TagNotFound,

    // Governance
    ProposalNotFound,
    ProposalVotingPeriodNotEnded,
    AlreadyVoted,

    // Модели
    ModelNotFound,
    ModelAlreadyRegistered,

    // Общее
    IoError(String),
    SerializationError(String),
    InternalError(String),
}

impl fmt::Display for AevumError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AevumError::InvalidPublicKey => write!(f, "Invalid public key"),
            AevumError::InvalidPrivateKey => write!(f, "Invalid private key"),
            AevumError::InvalidSignature => write!(f, "Invalid signature"),
            AevumError::VerificationFailed => write!(f, "Verification failed"),
            AevumError::TxNotFound => write!(f, "Transaction not found"),
            AevumError::TxInvalid => write!(f, "Transaction invalid"),
            AevumError::TxDoubleSpend => write!(f, "Double spend detected"),
            AevumError::TxBalanceMismatch => write!(f, "Transaction balance mismatch"),
            AevumError::TxSignatureMissing => write!(f, "Transaction signature missing"),
            AevumError::BlockNotFound => write!(f, "Block not found"),
            AevumError::BlockInvalid => write!(f, "Block invalid"),
            AevumError::BlockPrevHashMismatch => write!(f, "Block prev_hash mismatch"),
            AevumError::BlockHeightMismatch => write!(f, "Block height mismatch"),
            AevumError::BlockPoHOverlap => write!(f, "PoH tick overlap"),
            AevumError::BlockPoHFuture => write!(f, "Block PoH start in future"),
            AevumError::BlockEmpty => write!(f, "Block has no transactions"),
            AevumError::BlockGenesisAlreadyApplied => write!(f, "Genesis already applied"),
            AevumError::BlockGenesisNotApplied => write!(f, "Genesis not applied yet"),
            AevumError::UtxoNotFound => write!(f, "UTXO not found"),
            AevumError::UtxoAlreadySpent => write!(f, "UTXO already spent"),
            AevumError::MempoolFull => write!(f, "Mempool full"),
            AevumError::MempoolTxTooOld => write!(f, "Transaction too old"),
            AevumError::JurisdictionNotFound => write!(f, "Jurisdiction not found"),
            AevumError::JurisdictionAlreadyExists => write!(f, "Jurisdiction already exists"),
            AevumError::TagNotFound => write!(f, "Tag not found"),
            AevumError::ProposalNotFound => write!(f, "Proposal not found"),
            AevumError::ProposalVotingPeriodNotEnded => write!(f, "Voting period not ended"),
            AevumError::AlreadyVoted => write!(f, "Already voted"),
            AevumError::ModelNotFound => write!(f, "Model not found"),
            AevumError::ModelAlreadyRegistered => write!(f, "Model already registered"),
            AevumError::IoError(e) => write!(f, "IO error: {}", e),
            AevumError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            AevumError::InternalError(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl std::error::Error for AevumError {}

impl From<std::io::Error> for AevumError {
    fn from(e: std::io::Error) -> Self {
        AevumError::IoError(e.to_string())
    }
}

impl From<serde_json::Error> for AevumError {
    fn from(e: serde_json::Error) -> Self {
        AevumError::SerializationError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        assert_eq!(AevumError::BlockNotFound.to_string(), "Block not found");
        assert_eq!(
            AevumError::TxDoubleSpend.to_string(),
            "Double spend detected"
        );
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let aevum_err: AevumError = io_err.into();
        assert_eq!(aevum_err.to_string(), "IO error: file missing");
    }
}
