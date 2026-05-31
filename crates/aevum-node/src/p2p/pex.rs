use crate::p2p::peers::PeersManager;
use crate::p2p::sync::AtpMessage;
use std::sync::Arc;
use std::net::{SocketAddr, IpAddr};

pub type PeerAddr = ([u8; 16], u16);

pub struct PeerExchange;

impl PeerExchange {
    /// Создать список пиров заданного размера (случайная выборка)
    pub fn create_peer_list(peers: &Arc<PeersManager>, count: usize) -> AtpMessage {
        let addrs: Vec<PeerAddr> = peers.random_peers(count).iter()
            .filter_map(|pid| peers.peer_ips.get(pid).map(|e| socket_to_bytes(e.value())))
            .collect();
        AtpMessage::PeerList { addrs }
    }

    /// Создать список для конкретного пира (исключая его самого)
    pub fn create_peer_list_for(peers: &Arc<PeersManager>, exclude_addr: &SocketAddr) -> AtpMessage {
        let addrs: Vec<PeerAddr> = peers.peer_ips.iter()
            .filter(|e| *e.value() != *exclude_addr)
            .map(|e| socket_to_bytes(e.value()))
            .collect();
        AtpMessage::PeerList { addrs }
    }

    /// Обработать полученный список пиров — сохранить все адреса
    pub fn process_peer_list(addrs: &[PeerAddr], peers: &Arc<PeersManager>, now: u64) -> usize {
        let mut added = 0;
        for (ip_bytes, port) in addrs {
            if let Some(addr) = bytes_to_socket(*ip_bytes, *port) {
                if peers.can_accept(&addr) {
                    peers.add_known_address(addr);
                    added += 1;
                }
            }
        }
        if added > 0 { tracing::info!("[PEX] added {} new peer addresses", added); }
        added
    }

    /// Запросить список пиров у соседа
    pub fn request_peers(peers: &Arc<PeersManager>, peer_id: &[u8; 20]) {
        let req = AtpMessage::GetPeers { count: 16 };
        if let Ok(data) = bincode::serialize(&req) { peers.send_to(peer_id, data); }
    }

    /// Разослать адрес нового пира всем остальным
    pub fn gossip_new_peer(peers: &Arc<PeersManager>, new_addr: &SocketAddr, exclude_peer: Option<&[u8; 20]>) {
        let addr_bytes = socket_to_bytes(new_addr);
        let msg = AtpMessage::PeerList { addrs: vec![addr_bytes] };
        if let Ok(data) = bincode::serialize(&msg) {
            for e in &peers.peers {
                if let Some(exclude) = exclude_peer {
                    if *e.key() == *exclude { continue; }
                }
                let _ = e.value().tx.try_send(data.clone());
            }
        }
    }
}

pub fn socket_to_bytes(addr: &SocketAddr) -> PeerAddr {
    match addr.ip() {
        IpAddr::V4(v4) => {
            let mut ip = [0u8; 16];
            ip[..4].copy_from_slice(&v4.octets());
            (ip, addr.port())
        }
        IpAddr::V6(v6) => (v6.octets(), addr.port()),
    }
}

pub fn bytes_to_socket(ip: [u8; 16], port: u16) -> Option<SocketAddr> {
    if ip[..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] || ip[..12].iter().all(|&b| b == 0) {
        Some(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])), port))
    } else {
        Some(SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::from(ip)), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_roundtrip() {
        let addr: SocketAddr = "192.168.1.1:9733".parse().unwrap();
        let bytes = socket_to_bytes(&addr);
        let restored = bytes_to_socket(bytes.0, bytes.1).unwrap();
        assert_eq!(addr, restored);
    }

    #[test]
    fn test_ipv6_roundtrip() {
        let addr: SocketAddr = "[::1]:9733".parse().unwrap();
        let bytes = socket_to_bytes(&addr);
        let restored = bytes_to_socket(bytes.0, bytes.1).unwrap();
        assert_eq!(addr, restored);
    }
}
