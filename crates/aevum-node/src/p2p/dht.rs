use std::net::SocketAddr;
pub struct Dht;
impl Dht {
    pub fn new(_id: [u8; 32]) -> Self { Dht }
    pub fn find_closest(&self, _target: &[u8; 32], _count: usize) -> Vec<DhtNode> { vec![] }
}
pub struct DhtNode { pub node_id: [u8; 32], pub addr: SocketAddr }
