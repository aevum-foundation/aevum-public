use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, BlockHeader, SyncContext};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

const MAX_BLOCKS_PER_REQUEST: u64 = 500;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RETRIES: u32 = 3;

#[derive(Debug, Clone, PartialEq)]
pub enum SyncState {
    Idle,
    FetchingHeaders,
    ValidatingChain,
    FetchingBlocks,
    Synced,
    Failed(String),
}

struct PendingRequest {
    since: Instant,
    request_id: u64,
}

pub struct SyncEngine {
    pub state: SyncState,
    pub peer_id: [u8; 20],
    pub peer_height: u64,
    pub headers: Vec<BlockHeader>,
    pub blocks_received: u64,
    pub retry_count: u32,
    pending_since: Option<Instant>,
    pending_request_id: Option<u64>,
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
}

impl SyncEngine {
    pub fn new(peer_id: [u8; 20], peers: Arc<PeersManager>, ctx: Arc<SyncContext>) -> Self {
        Self {
            state: SyncState::Idle, peer_id, peer_height: 0,
            headers: Vec::new(), blocks_received: 0, retry_count: 0,
            pending_since: None, pending_request_id: None,
            peers, ctx,
        }
    }

    pub fn start(&mut self, peer_height: u64) {
        self.peer_height = peer_height;
        let our_height = self.get_our_height();

        if peer_height <= our_height {
            self.state = SyncState::Synced;
            return;
        }

        tracing::info!("[Sync] Start: our={}, peer={}, need {} blocks", our_height, peer_height, peer_height - our_height);
        self.request_headers();
    }

    pub fn update_peer_height(&mut self, peer_height: u64) {
        if peer_height > self.peer_height {
            self.peer_height = peer_height;
        }
    }

    fn get_our_height(&self) -> u64 {
        self.ctx.validator.lock().unwrap().last_block_height()
    }

    fn request_headers(&mut self) {
        let our_height = self.get_our_height();
        self.state = SyncState::FetchingHeaders;
        self.pending_since = Some(Instant::now());

        let req = AtpMessage::HeaderRequest { from: our_height + 1, to: self.peer_height };
        if let Ok(data) = bincode::serialize(&req) {
            self.peers.send_to(&self.peer_id, data);
        }
    }

    pub fn on_headers(&mut self, headers: Vec<BlockHeader>) {
        self.pending_since = None;

        if headers.is_empty() {
            self.retry_or_fail("Empty headers");
            return;
        }

        self.headers = headers;
        self.state = SyncState::ValidatingChain;

        if !self.validate_chain() {
            self.retry_or_fail("Chain validation failed");
            return;
        }

        self.request_blocks();
    }

    fn validate_chain(&self) -> bool {
        let our_height = self.get_our_height();
        let st = self.ctx.storage.lock().unwrap();

        // Пустая БД — принимаем заголовки без проверки prev_hash
        if our_height == 0 {
            return true;
        }

        match st.load_block(our_height) {
            Ok(Some(last_block)) => {
                if self.headers[0].prev_hash != last_block.block_hash.0 {
                    return false;
                }
            }
            _ => {
                // Блок не найден — пробуем синхронизацию
            }
        }

        for i in 1..self.headers.len() {
            let prev = &self.headers[i - 1];
            let curr = &self.headers[i];
            if curr.prev_hash != prev.block_hash { return false; }
            if curr.poh_tick_start != prev.poh_tick_end { return false; }
        }
        true
    }

    fn request_blocks(&mut self) {
        if self.headers.is_empty() { return; }
        let our_height = self.get_our_height();
        let from = our_height + 1;
        let to = (from + MAX_BLOCKS_PER_REQUEST - 1).min(self.peer_height);
        let request_id = rand::random();

        self.state = SyncState::FetchingBlocks;
        self.pending_since = Some(Instant::now());
        self.pending_request_id = Some(request_id);
        let req = AtpMessage::BlockRequest { request_id, from, to };
        if let Ok(data) = bincode::serialize(&req) {
            self.peers.send_to(&self.peer_id, data);
        }
    }

    pub fn on_blocks(&mut self, blocks: Vec<(u64, Vec<u8>)>, request_id: u64) {
        if let Some(expected_id) = self.pending_request_id {
            if expected_id != request_id { return; }
        } else {
            return;
        }

        self.pending_since = None;
        self.pending_request_id = None;
        self.blocks_received += blocks.len() as u64;
        let our_height = self.get_our_height();

        if our_height >= self.peer_height {
            self.state = SyncState::Synced;
            return;
        }

        let from = our_height + 1;
        let to = (from + MAX_BLOCKS_PER_REQUEST - 1).min(self.peer_height);
        let request_id = rand::random();

        self.state = SyncState::FetchingBlocks;
        self.pending_since = Some(Instant::now());
        self.pending_request_id = Some(request_id);

        let req = AtpMessage::BlockRequest { request_id, from, to };
        if let Ok(data) = bincode::serialize(&req) {
            self.peers.send_to(&self.peer_id, data);
        }
    }

    fn retry_or_fail(&mut self, reason: &str) {
        self.retry_count += 1;
        if self.retry_count >= MAX_RETRIES {
            self.state = SyncState::Failed(format!("{} after {} retries", reason, MAX_RETRIES));
            return;
        }
        self.request_headers();
    }

    pub fn check_timeouts(&mut self) {
        if let Some(since) = self.pending_since {
            if since.elapsed() > REQUEST_TIMEOUT {
                self.pending_since = None;
                self.pending_request_id = None;
                self.retry_or_fail("Request timeout");
            }
        }
    }

    pub fn handle_message(&mut self, msg: &AtpMessage) -> bool {
        if let AtpMessage::Status { height, .. } = msg {
            self.update_peer_height(*height);
        }

        match msg {
            AtpMessage::HeaderResponse { headers } => {
                if matches!(self.state, SyncState::FetchingHeaders | SyncState::Idle) {
                    self.on_headers(headers.clone());
                    return true;
                }
            }
            AtpMessage::BlockResponse { request_id, blocks } => {
                if matches!(self.state, SyncState::FetchingBlocks) {
                    self.on_blocks(blocks.clone(), *request_id);
                    return true;
                }
            }
            _ => {}
        }
        false
    }

    pub fn is_synced(&self) -> bool { self.state == SyncState::Synced }

    pub fn progress(&self) -> f64 {
        let our_height = self.get_our_height();
        if self.peer_height <= our_height { return 100.0; }
        let total = self.peer_height - our_height;
        if total == 0 { return 100.0; }
        (self.blocks_received as f64 / total as f64 * 100.0).min(99.9)
    }
}
