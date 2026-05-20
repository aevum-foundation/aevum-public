use crate::p2p::peers::PeersManager;
use crate::p2p::sync::{AtpMessage, SyncContext, create_status, handle_atp_message};
use crate::p2p::noise::AtpCipher;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum ConnState { Handshaking, Active, Dead }

#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub connected_at: Option<Instant>,
    pub messages_sent: u64, pub messages_received: u64,
    pub bytes_sent: u64, pub bytes_received: u64,
    pub score: i32,
}

pub struct AtpConnection {
    pub peer_id: [u8; 20], pub addr: SocketAddr,
    pub state: ConnState, pub stats: PeerStats,
    is_server: bool,
    send_cipher: Arc<StdMutex<AtpCipher>>,
    recv_cipher: Arc<StdMutex<AtpCipher>>,
    peers: Arc<PeersManager>,
    ctx: Arc<SyncContext>,
    peer_ready: bool,
    we_sent_ready: bool,
    pending_outgoing: Vec<Vec<u8>>,
    outgoing_tx: Option<mpsc::Sender<Vec<u8>>>,
}

impl AtpConnection {
    pub fn new(
        cipher: AtpCipher, peer_id: [u8; 20],
        addr: SocketAddr, peers: Arc<PeersManager>, ctx: Arc<SyncContext>, is_server: bool,
    ) -> Self {
        let send_cipher = Arc::new(StdMutex::new(cipher));
        let recv_secret = send_cipher.lock().unwrap().shared_secret_bytes();
        let recv_cipher = Arc::new(StdMutex::new(AtpCipher::new(&recv_secret)));
        Self {
            peer_id, addr, is_server, peers, ctx,
            state: ConnState::Handshaking,
            stats: PeerStats { connected_at: Some(Instant::now()), ..Default::default() },
            send_cipher, recv_cipher,
            peer_ready: false, we_sent_ready: false,
            pending_outgoing: Vec::new(), outgoing_tx: None,
        }
    }

    pub fn send_or_buffer(&mut self, data: Vec<u8>) {
        if self.peer_ready && self.we_sent_ready {
            if let Some(ref tx) = self.outgoing_tx {
                let _ = tx.try_send(data);
                return;
            }
        }
        self.pending_outgoing.push(data);
    }

    pub fn on_peer_ready(&mut self) {
        self.peer_ready = true;
        // Запускаем синхронизацию: запрашиваем блоки у пира
        let our_height = self.ctx.validator.lock().unwrap().last_block_height();
        let status = create_status(&self.ctx);
        let data = bincode::serialize(&status).unwrap_or_default();
        self.pending_outgoing.push(data);
        tracing::info!("[ATP] Sync initiated after handshake: our_height={}", our_height);
        self.flush_buffer();
    }

    fn flush_buffer(&mut self) {
        if self.peer_ready && self.we_sent_ready {
            if let Some(ref tx) = self.outgoing_tx {
                for data in self.pending_outgoing.drain(..) {
                    let _ = tx.try_send(data);
                }
            }
        }
    }

    pub async fn run(mut self, mut reader: ReadHalf<TcpStream>, mut writer: WriteHalf<TcpStream>) {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
        self.outgoing_tx = Some(tx);
        self.peers.register_peer(self.peer_id, self.addr, self.outgoing_tx.as_ref().unwrap().clone());

        let send_cipher = self.send_cipher.clone();
        let recv_cipher = self.recv_cipher.clone();
        let peers = self.peers.clone();
        let ctx = self.ctx.clone();
        let peer_id = self.peer_id;

        // HANDSHAKE
        if self.is_server {
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    if let Some(p) = recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                            let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                            tokio::spawn(async move { handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                            // Если это ReadySignal — обрабатываем
                            if let Ok(AtpMessage::ReadySignal) = bincode::deserialize::<AtpMessage>(&p) {
                                self.on_peer_ready();
                            }
                        }
                    }
                }
                Err(e) => { tracing::warn!("[ATP] Handshake read failed: {}", e); return; }
            }
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
            // Send ReadySignal
            Self::send_ready(&send_cipher, &mut writer).await;
            self.we_sent_ready = true;
            self.flush_buffer();
        } else {
            Self::send_status(&send_cipher, &ctx, &mut writer, &peer_id).await;
            Self::send_ready(&send_cipher, &mut writer).await;
            self.we_sent_ready = true;
            self.flush_buffer();
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    if let Some(p) = recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        if let Ok(msg) = bincode::deserialize::<AtpMessage>(&p) {
                            let ctx_h = ctx.clone(); let peers_h = peers.clone(); let pid = peer_id;
                            tokio::spawn(async move { handle_atp_message(msg, &ctx_h, &pid, &peers_h); });
                            if let Ok(AtpMessage::ReadySignal) = bincode::deserialize::<AtpMessage>(&p) {
                                self.on_peer_ready();
                            }
                        }
                    }
                }
                Err(e) => { tracing::warn!("[ATP] Handshake read failed: {}", e); return; }
            }
        }

        // Wait for peer ReadySignal if not received yet
        if !self.peer_ready {
            match Self::read_msg(&mut reader).await {
                Ok(encrypted) => {
                    if let Some(p) = recv_cipher.lock().unwrap().decrypt(&encrypted) {
                        if let Ok(AtpMessage::ReadySignal) = bincode::deserialize(&p) {
                            self.on_peer_ready();
                        }
                    }
                }
                Err(e) => { tracing::warn!("[ATP] ReadySignal wait failed: {}", e); return; }
            }
        }

        self.state = ConnState::Active;
        tracing::info!("[ATP] Active loop started: peer_id={}", hex::encode(&peer_id));

        // ACTIVE LOOP
        loop {
            tokio::select! {
                data = rx.recv() => {
                    match data {
                        Some(d) => {
                            let encrypted = send_cipher.lock().unwrap().encrypt(&d);
                            let len = (encrypted.len() as u32).to_be_bytes();
                            let mut packet = Vec::with_capacity(4 + encrypted.len());
                            packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
                            if writer.write_all(&packet).await.is_err() { break; }
                            let _ = writer.flush().await;
                        }
                        None => break,
                    }
                }
                result = Self::read_msg(&mut reader) => {
                    match result {
                        Ok(encrypted) => {
                            if let Some(plaintext) = recv_cipher.lock().unwrap().decrypt(&encrypted) {
                                if let Ok(msg) = bincode::deserialize::<AtpMessage>(&plaintext) {
                                    handle_atp_message(msg, &ctx, &peer_id, &peers);
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        self.peers.remove_peer(&peer_id);
        tracing::info!("[ATP] Disconnected: {}", hex::encode(&peer_id));
    }

    async fn send_status(
        send_cipher: &Arc<StdMutex<AtpCipher>>, ctx: &Arc<SyncContext>,
        writer: &mut WriteHalf<TcpStream>, peer_id: &[u8; 20],
    ) {
        let ctx2 = ctx.clone();
        let my_status = tokio::task::spawn_blocking(move || create_status(&ctx2)).await.unwrap();
        let data = bincode::serialize(&my_status).unwrap_or_default();
        let encrypted = send_cipher.lock().unwrap().encrypt(&data);
        let len = (encrypted.len() as u32).to_be_bytes();
        let mut packet = Vec::with_capacity(4 + encrypted.len());
        packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
        let _ = writer.write_all(&packet).await;
        let _ = writer.flush().await;
    }

    async fn send_ready(send_cipher: &Arc<StdMutex<AtpCipher>>, writer: &mut WriteHalf<TcpStream>) {
        let ready_data = bincode::serialize(&AtpMessage::ReadySignal).unwrap_or_default();
        let encrypted = send_cipher.lock().unwrap().encrypt(&ready_data);
        let len = (encrypted.len() as u32).to_be_bytes();
        let mut packet = Vec::with_capacity(4 + encrypted.len());
        packet.extend_from_slice(&len); packet.extend_from_slice(&encrypted);
        let _ = writer.write_all(&packet).await;
        let _ = writer.flush().await;
    }

    async fn read_msg(reader: &mut ReadHalf<TcpStream>) -> Result<Vec<u8>, std::io::Error> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 10 * 1024 * 1024 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "too large")); }
        let mut encrypted = vec![0u8; len];
        reader.read_exact(&mut encrypted).await?;
        Ok(encrypted)
    }
}
