use crate::protocols::{proto_ipv4, proto_ipv6};
use std::net::IpAddr;
pub trait ProtocolHandler {
    fn handle(&self, addr: IpAddr, length: u32);
}
pub struct ProtocolManager {
    handlers: Vec<Box<dyn ProtocolHandler>>,
}

impl ProtocolManager {
    pub fn new() -> Self {
        Self {
            handlers: vec![
                Box::new(proto_ipv4::Ipv4Handler),
                Box::new(proto_ipv6::Ipv6Handler),
            ],
        }
    }

    pub fn route_packets(&self, addr: IpAddr, length: u32) {
        match addr {
            IpAddr::V4(_) => {
                if let Some(handler) = self.handlers.get(0) {
                    handler.handle(addr, length);
                }
            }
            IpAddr::V6(_) => {
                if let Some(handler) = self.handlers.get(1) {
                    handler.handle(addr, length);
                }
            }
        }
    }
}
