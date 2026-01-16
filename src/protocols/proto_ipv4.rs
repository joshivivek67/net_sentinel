use super::ProtocolHandler;
use log::info;
use std::net::IpAddr;

pub struct Ipv4Handler;

impl ProtocolHandler for Ipv4Handler {
    fn handle(&self, addr: IpAddr, length: u32) {
        if let IpAddr::V4(v4_addr) = addr {
            info!("IPv4 Packet: {} of {} bytes", v4_addr, length);
        }
    }
}
