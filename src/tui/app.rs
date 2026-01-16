use crate::capture::PacketFiled;

pub struct App {
    pub recent_packets: Vec<PacketFiled>,
    pub total_packets: u64,
    pub total_anomalies: u64,
    pub pps: u64,
    pub should_quit: bool,
}

impl App {
    pub fn new() -> Self {
        Self {
            recent_packets: Vec::new(),
            total_packets: 0,
            total_anomalies: 0,
            pps: 0,
            should_quit: false,
        }
    }
    pub fn on_tick(&mut self, packet: PacketFiled) {
        self.total_packets += 1;
        if packet.score > 0.6 {
            self.total_anomalies += 1;
        }
        self.recent_packets.push(packet);
        if self.recent_packets.len() > 20 {
            self.recent_packets.remove(0);
        }
    }
}
