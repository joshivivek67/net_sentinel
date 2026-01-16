use super::types::PacketFiled;
use crate::{capture, ml};
use crossbeam_channel::Sender;
use etherparse::SlicedPacket;
use extended_isolation_forest::Forest;
use pcap::{Capture, Device};
use serde::Serialize;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

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
    let device_interface = Device::lookup()?.ok_or("Failed to find default interface")?;
    println!("Default interface: {}", device_interface.name);
    Ok(device_interface)
}
pub fn start_training_capture(device: Device) -> Result<(), Box<dyn Error>> {
    let mut state = CaptureState::new();

    let mut capture = Capture::from_device(device)?.promisc(true).open()?;

    println!("Capture started on press ctrl +c to Stop");
    // Loop through the packets provide by the capture
    let mut file_writer = csv::Writer::from_path("training.data.csv")?;
    while let Ok(packet) = capture.next_packet() {
        let iat = state.update_and_get_iat();
        println!("Captured packet: {} byte | IAT: {}", packet.header.len, iat);

        // Just one line to parse everything!
        if let Some(pf) = PacketFiled::from_packet(&packet, iat) {
            // In start_capture:
            file_writer.serialize(&pf)?;
            file_writer.flush()?;

            println!("Captured packet: {} byte ", packet.header.len);
        }
    }
    Ok(())
}

// Startbackground capture
pub fn start_background_capture(
    device: Device,
    model: Forest<f64, 5>,
    tx: Sender<PacketFiled>,
) -> Result<(), Box<dyn Error>> {
    let mut state = CaptureState::new();

    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(1000)
        .open()?;
    while let Ok(packet) = capture.next_packet() {
        let iat = state.update_and_get_iat();
        if let Some(mut pf) = PacketFiled::from_packet(&packet, iat) {
            let score = model.score(&[
                pf.len as f64,
                pf.protocol as f64,
                iat,
                pf.src_port as f64,
                pf.dst_port as f64,
            ]);
            pf.score = score;

            let _ = tx.send(pf);
        }
    }
    Ok(())
}

// The Detection Loop
pub fn start_guard(device: Device, model: &Forest<f64, 5>) -> Result<(), Box<dyn Error>> {
    let mut state = CaptureState::new();
    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(1000)
        .open()?;
    println!("🛡️ GUARD ACTIVE. Monitoring traffic...");
    while let Ok(packet) = capture.next_packet() {
        let iat = state.update_and_get_iat();
        if let Some(pf) = PacketFiled::from_packet(&packet, iat) {
            if ml::is_anomaly(
                model,
                pf.len as f64,
                pf.protocol as f64,
                iat,
                pf.src_port as f64,
                pf.dst_port as f64,
            ) {
                println!(
                    "🚨 ANOMALY DETECTED! Len: {}, Proto: {}, IAT: {}, Src Port: {}, Dst Port: {}",
                    pf.len, pf.protocol, iat, pf.src_port, pf.dst_port
                );
            }
        }
    }
    Ok(())
}
