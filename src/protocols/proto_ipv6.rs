use super::ProtocolHandler;
use log::info;
use std::net::IpAddr;

pub struct Ipv6Handler;

impl ProtocolHandler for Ipv6Handler {
    fn handle(&self, addr: IpAddr, length: u32) {
        if let IpAddr::V6(v6_addr) = addr {
            info!("IPv6 Packet: {} of {} bytes", v6_addr, length);
        }
    }
}
