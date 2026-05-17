use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, create_status, handle_atp_message};
use crate::p2p::noise::AtpCipher;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex as TokioMutex};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState {
    Handshaking,
    Active,
    Dead,
}

#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub connected_at: Option<Instant>,
    pub last_message: Option<Instant>,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub score: i32,
}

pub struct AtpConnection {
    pub peer_id: [u8; 20],
    pub addr: SocketAddr,
    pub state: ConnState,
    pub stats: PeerStats,
    is_server: bool,
    stream: Arc<TokioMutex<TcpStream>>,
    send_cipher: Arc<StdMutex<AtpCipher>>,
    recv_cipher: Arc<StdMutex<AtpCipher>>,
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
}

impl AtpConnection {
    pub fn new(
        stream: TcpStream, cipher: AtpCipher, peer_id: [u8; 20],
        addr: SocketAddr, peers: Arc<PeersManager>, ctx: Arc<SyncContext>, is_server: bool,
    ) -> Self {
        let send_cipher = Arc::new(StdMutex::new(cipher));
        let recv_secret = send_cipher.lock().unwrap().shared_secret_bytes();
        let recv_cipher = Arc::new(StdMutex::new(AtpCipher::new(&recv_secret)));
        Self {
            peer_id, addr, is_server, peers, ctx,
            state: ConnState::Handshaking,
            stats: PeerStats { connected_at: Some(Instant::now()), ..Default::default() },
            stream: Arc::new(TokioMutex::new(stream)),
            send_cipher, recv_cipher,
        }
    }

    /// Главный жизненный цикл
    pub async fn run(mut self) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        self.peers.register_peer(self.peer_id, self.addr, tx.clone());

        if !self.do_handshake().await {
            self.peers.remove_peer(&self.peer_id);
            return;
        }

        self.state = ConnState::Active;
        self.run_active_loop(tx, &mut rx).await;

        self.peers.remove_peer(&self.peer_id);
        tracing::info!("❌ Disconnected from {}", hex::encode(&self.peer_id));
    }

    /// Фаза 1: Handshake
    async fn do_handshake(&mut self) -> bool {
        let mut stream = self.stream.lock().await;

        if self.is_server {
            match Self::read_message(&mut *stream).await {
                Ok(encrypted) => {
                    if let Some(p) = self.recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                            tracing::info!("📊 Peer status received from {}", hex::encode(&self.peer_id));
                            self.stats.messages_received += 1;
                            self.stats.bytes_received += encrypted.len() as u64;
                            self.stats.last_message = Some(Instant::now());
                            let ctx = self.ctx.clone(); let peers = self.peers.clone(); let pid = self.peer_id;
                            tokio::spawn(async move { handle_atp_message(msg, &ctx, &pid, &peers); });
                        }
                    }
                }
                Err(e) => { tracing::warn!("Handshake read error: {}", e); return false; }
            }
        } else {
            if !self.send_status(&mut *stream).await { return false; }
        }

        if self.is_server {
            if !self.send_status(&mut *stream).await { return false; }
        } else {
            match Self::read_message(&mut *stream).await {
                Ok(encrypted) => {
                    if let Some(p) = self.recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                            tracing::info!("📊 Peer status received from {}", hex::encode(&self.peer_id));
                            self.stats.messages_received += 1;
                            self.stats.bytes_received += encrypted.len() as u64;
                            self.stats.last_message = Some(Instant::now());
                            let ctx = self.ctx.clone(); let peers = self.peers.clone(); let pid = self.peer_id;
                            tokio::spawn(async move { handle_atp_message(msg, &ctx, &pid, &peers); });
                        }
                    }
                }
                Err(e) => { tracing::warn!("Handshake read error: {}", e); return false; }
            }
        }
        drop(stream);
        true
    }

    async fn send_status(&mut self, stream: &mut TcpStream) -> bool {
        let ctx2 = self.ctx.clone();
        let my_status = tokio::task::spawn_blocking(move || create_status(&ctx2)).await.unwrap();
        if let Ok(data) = bincode::serialize(&my_status) {
            let encrypted = self.send_cipher.lock().unwrap().encrypt(&data);
            let len = (encrypted.len() as u32).to_be_bytes();
            let mut packet = Vec::with_capacity(4 + encrypted.len());
            packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
            if tokio::io::AsyncWriteExt::write_all(stream, &packet).await.is_ok() {
                tracing::info!("📤 Status sent to {}", hex::encode(&self.peer_id));
                self.stats.messages_sent += 1;
                self.stats.bytes_sent += packet.len() as u64;
                self.stats.last_message = Some(Instant::now());
                return true;
            }
        }
        false
    }

    /// Фаза 3: Активный обмен
    async fn run_active_loop(&mut self, tx: mpsc::Sender<Vec<u8>>, rx: &mut mpsc::Receiver<Vec<u8>>) {
        let stream_send = self.stream.clone();
        let stream_recv = self.stream.clone();
        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;

        // Канал для статистики из отправки
        let (stats_tx, mut stats_rx) = mpsc::unbounded_channel();

        let send_handle = tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                let encrypted = send_cipher.lock().unwrap().encrypt(&data);
                let len = (encrypted.len() as u32).to_be_bytes();
                let mut packet = Vec::with_capacity(4 + encrypted.len());
                packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
                let mut s = stream_send.lock().await;
                if tokio::io::AsyncWriteExt::write_all(&mut *s, &packet).await.is_err() { break; }
                let _ = stats_tx.send((1u64, packet.len() as u64));
            }
        });

        let recv_handle = tokio::spawn(async move {
            let mut len_buf = [0u8; 4];
            let mut msgs = 0u64;
            let mut bytes = 0u64;
            loop {
                let mut s = stream_recv.lock().await;
                if tokio::io::AsyncReadExt::read_exact(&mut *s, &mut len_buf).await.is_err() { break; }
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > 10 * 1024 * 1024 { break; }
                let mut encrypted = vec![0u8; len];
                if tokio::io::AsyncReadExt::read_exact(&mut *s, &mut encrypted).await.is_err() { break; }
                drop(s);
                msgs += 1;
                bytes += len as u64;
                if let Some(plaintext) = recv_cipher.lock().unwrap().decrypt(&encrypted) {
                    if let Ok(msg) = bincode::deserialize::<AtpMessage>(&plaintext) {
                        handle_atp_message(msg, &ctx, &peer_id, &peers);
                    }
                }
            }
            // Отправляем финальную статистику
            let _ = stats_tx.send((msgs, bytes));
        });

        // Обновляем статистику из канала
        while let Some((msgs, bytes)) = stats_rx.recv().await {
            self.stats.messages_sent += msgs;
            self.stats.bytes_sent += bytes;
            self.stats.last_message = Some(Instant::now());
        }

        let _ = tokio::join!(send_handle, recv_handle);
    }

    async fn read_message(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
        let mut len_buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(stream, &mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 10 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too large"));
        }
        let mut encrypted = vec![0u8; len];
        tokio::io::AsyncReadExt::read_exact(stream, &mut encrypted).await?;
        Ok(encrypted)
    }
}
