use etherparse::SlicedPacket;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Serialize)]
pub struct PacketFiled {
    pub len: u32,
    #[serde(skip)]
    pub score: f64,
    pub protocol: u8,
    pub iat: f64,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}
impl PacketFiled {
    pub fn from_packet(packet: &pcap::Packet, iat: f64) -> Option<Self> {
        let value = SlicedPacket::from_ethernet(&packet.data).ok()?;

        let (protocol_byte, src_ip, dst_ip) = match value.ip {
            Some(etherparse::InternetSlice::Ipv4(header, _)) => {
                let src = IpAddr::V4(Ipv4Addr::from(header.source()));
                let dst = IpAddr::V4(Ipv4Addr::from(header.destination()));
                (header.protocol(), src, dst)
            }
            Some(etherparse::InternetSlice::Ipv6(header, _)) => {
                let src = IpAddr::V6(Ipv6Addr::from(header.source()));
                let dst = IpAddr::V6(Ipv6Addr::from(header.destination()));
                (header.next_header(), src, dst)
            }
            _ => (
                0u8,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            ),
        };
        let (src_port, dst_port) = match value.transport {
            Some(etherparse::TransportSlice::Tcp(header)) => {
                (header.source_port(), header.destination_port())
            }
            Some(etherparse::TransportSlice::Udp(header)) => {
                (header.source_port(), header.destination_port())
            }
            _ => (0u16, 0u16),
        };
        Some(Self {
            len: packet.header.len,
            score: 0.0,
            protocol: protocol_byte,
            iat,
            src_port,
            dst_port,
            src_ip,
            dst_ip,
        })
    }
}
