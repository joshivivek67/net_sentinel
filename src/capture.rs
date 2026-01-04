use crate::ml;
use etherparse::SlicedPacket;
use extended_isolation_forest::Forest;
use pcap::{Capture, Device};
use serde::Serialize;
use std::error::Error;
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

        match SlicedPacket::from_ethernet(&packet.data) {
            Ok(value) => {
                let protocol_byte = match value.ip {
                    Some(etherparse::InternetSlice::Ipv4(header, _)) => header.protocol(),
                    Some(etherparse::InternetSlice::Ipv6(header, _)) => header.next_header(),
                    None => continue,
                };
                let packet_file = PacketFiled {
                    len: packet.header.len,
                    protocol: protocol_byte,
                    iat,
                };
                file_writer.serialize(&packet_file)?;
                let protocol_name = match protocol_byte {
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
            Err(e) => {
                println!("Error parsing packet: {}", e);
            }
        }
    }
    Ok(())
}
// The Detection Loop
pub fn start_guard(device: Device, model: &Forest<f64, 3>) -> Result<(), Box<dyn Error>> {
    let mut state = CaptureState::new();
    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(1000)
        .open()?;
    println!("🛡️ GUARD ACTIVE. Monitoring traffic...");
    while let Ok(packet) = capture.next_packet() {
        let iat = state.update_and_get_iat();
        match SlicedPacket::from_ethernet(&packet.data) {
            Ok(value) => {
                let protocol_byte = match value.ip {
                    Some(etherparse::InternetSlice::Ipv4(header, _)) => header.protocol(),
                    Some(etherparse::InternetSlice::Ipv6(header, _)) => header.next_header(),
                    None => continue,
                };
                // FEATURE EXTRACTION
                let len = packet.header.len as f64;
                let proto = protocol_byte as f64;
                // ASK THE BRAIN
                if ml::is_anomaly(model, len, proto, iat) {
                    println!("🚨 ANOMALY DETECTED! Len: {}, Proto: {}", len, proto);
                }
            }
            Err(_) => {}
        }
    }
    Ok(())
}
