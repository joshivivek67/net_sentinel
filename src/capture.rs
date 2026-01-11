use crate::ml;
use etherparse::SlicedPacket;
use extended_isolation_forest::Forest;
use pcap::{Capture, Device};
use serde::Serialize;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;
//Find the main network interface

pub struct CaptureState {
    last_packet_time: Option<Instant>,
}

impl CaptureState {
    pub fn new() -> Self {
        Self {
            last_packet_time: None,
        }
    }
    pub fn update_and_get_iat(&mut self) -> f64 {
        let now = Instant::now();
        let iat = match self.last_packet_time {
            Some(prev) => now.duration_since(prev).as_secs_f64(),
            None => 0.0,
        };
        self.last_packet_time = Some(now);
        iat
    }
}

pub fn get_device_default_interface() -> Result<Device, Box<dyn Error>> {
    let device_interface = Device::lookup()?.expect("Failed to find default interface");
    println!("Default interface: {}", device_interface.name);
    Ok(device_interface)
}
#[derive(Serialize)]
pub struct PacketFiled {
    len: u32,
    protocol: u8,
    iat: f64,
    src_port: u16,
    dst_port: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
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
            _ => (0, 0),
        };
        Some(Self {
            len: packet.header.len,
            protocol: protocol_byte,
            iat,
            src_port,
            dst_port,
            src_ip,
            dst_ip,
        })
    }
}

//Open the Main Interface to capture packets

pub fn start_capture(device: Device) -> Result<(), Box<dyn Error>> {
    let mut state = CaptureState::new();

    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(1000)
        .open()?;

    println!("Capture started on press ctrl +c to Stop");
    // Loop through the packets provide by the capture
    let mut file_writer = csv::Writer::from_path("training.data.csv")?;
    while let Ok(packet) = capture.next_packet() {
        let iat = state.update_and_get_iat();
        println!("Captured packet: {} byte | IAT: {}", packet.header.len, iat);

        // Just one line to parse everything!
        if let Some(packet_file) = PacketFiled::from_packet(&packet, iat) {
            // In start_capture:
            file_writer.serialize(&packet_file)?;

            let protocol_name = match packet_file.protocol {
                6 => "TCP",
                17 => "UDP",
                1 => "ICMP",
                41 => "IPv6",
                _ => "Other",
            };
            println!(
                "Captured packet: {} byte | Proto {}: ",
                packet.header.len, protocol_name
            );
        }
    }
    Ok(())
}
// The Detection Loop
pub fn start_guard(device: Device, model: &Forest<f64, 7>) -> Result<(), Box<dyn Error>> {
    let mut state = CaptureState::new();
    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(1000)
        .open()?;
    println!("🛡️ GUARD ACTIVE. Monitoring traffic...");
    while let Ok(packet) = capture.next_packet() {
        let iat = state.update_and_get_iat();
        if let Some(pf) = PacketFiled::from_packet(&packet, iat) {
            let src_ip_num = match pf.src_ip {
                IpAddr::V4(v4) => u32::from(v4) as f64,
                IpAddr::V6(_) => 0.0,
            };

            let dst_ip_num = match pf.dst_ip {
                IpAddr::V4(v4) => u32::from(v4) as f64,
                IpAddr::V6(_) => 0.0,
            };
            if ml::is_anomaly(
                model,
                pf.len as f64,
                pf.protocol as f64,
                iat,
                pf.src_port as f64,
                pf.dst_port as f64,
                src_ip_num,
                dst_ip_num,
            ) {
                println!(
                    "🚨 ANOMALY DETECTED! Len: {}, Proto: {}, IAT: {}, Src Port: {}, Dst Port: {}, Src IP: {}, Dst IP: {}",
                    pf.len, pf.protocol, iat, pf.src_port, pf.dst_port, src_ip_num, dst_ip_num
                );
            }
        }
    }
    Ok(())
}
