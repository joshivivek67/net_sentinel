use crate::tui::App;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(frame.size());
    let header = Paragraph::new(" 🛡️ NET SENTINEL - Real-Time Dashboard ")
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(header, chunks[0]);

    let bodychunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(chunks[1]);
    let stats = Paragraph::new(format!(
        "Total: {}\nAnomalies: {}",
        app.total_packets, app.total_anomalies
    ))
    .block(Block::default().title("Statistics").borders(Borders::ALL));
    frame.render_widget(stats, bodychunks[1]);

    let packet_items: Vec<ListItem> = app
        .recent_packets
        .iter()
        .rev() // Show newest at the top
        .map(|packet| {
            let color = if packet.score > 0.6 {
                Color::Red
            } else {
                Color::Green
            };
            ListItem::new(format!(
                "[{}] {} -> {}: {} bytes Score: {:.3}",
                packet.protocol, packet.src_ip, packet.dst_ip, packet.len, packet.score
            ))
            .style(Style::default().fg(color))
        })
        .collect();
    // 2. Create the List Widget
    let packet_list = List::new(packet_items).block(
        Block::default()
            .title(" LIVE TRAFFIC ")
            .borders(Borders::ALL),
    );
    // 3. Render it into the LARGE section (swap bodychunks if you like!)
    frame.render_widget(packet_list, bodychunks[0]);

    let footer = Paragraph::new("Press 'q' to quit").block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, chunks[2]);
}
