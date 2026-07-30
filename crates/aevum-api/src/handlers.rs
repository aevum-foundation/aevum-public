use crate::*;

/// Health endpoint (node status aggregation)
pub fn health(
    block_height: u64,
    peer_count: u64,
    uptime_secs: u64,
    sync_lag: u64,
) -> HealthResponse {
    let status = if sync_lag > 100 {
        NodeStatus::Syncing
    } else if peer_count == 0 {
        NodeStatus::Degraded
    } else {
        NodeStatus::Healthy
    };

    HealthResponse {
        status,
        version: crate::API_VERSION,
        block_height,
        peer_count,
        uptime_secs,
        is_sealed: false,
        chain_finality: block_height,
    }
}

/// Metrics endpoint (Prometheus bridge-ready)
pub fn metrics(
    block_height: u64,
    mempool_size: u64,
    tps: u64,
    errors_total: u64,
    fraud_alerts: u64,
) -> MetricsResponse {
    MetricsResponse {
        block_height,
        mempool_size,
        tps,
        errors_total,
        fraud_alerts,
        zk_proofs_verified: 0,
        dao_proposals: 0,
        dna_nodes: 0,
        finality_index: block_height,
    }
}

/// Transaction submission response
pub fn submit_tx(tx_hash: [u8; 32], accepted: bool) -> TxResponse {
    TxResponse {
        tx_hash: blake3::hash(&tx_hash).to_hex().to_string(),
        status: if accepted {
            TxStatus::Accepted
        } else {
            TxStatus::Rejected
        },
        finality_height: None,
        dna_verified: false,
    }
}

/// Standard error builder (Stripe-style API errors)
pub fn error(msg: &str, kind: ApiErrorType, code: u16) -> ApiError {
    ApiError {
        error: kind,
        message: msg.to_string(),
        code,
        request_id: None,
    }
}
