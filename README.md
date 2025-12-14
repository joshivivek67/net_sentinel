# 🛡️ Net Sentinel

**Net Sentinel** is a lightweight, Rust-based Network Intrusion Detection System (NIDS) that uses **Machine Learning** (Extended Isolation Forest) to detect anomalies in improved network traffic patterns in real-time.

> 🚀 **Status**: Prototype / Active Development

## ✨ Features
- **Packet Capture**: High-performance packet sniffing using `libpcap`.
- **Anomaly Detection**: Uses an Unsupervised Learning model (Isolation Forest) to learn "normal" traffic patterns.
- **Guard Mode**: Real-time traffic analysis and anomaly alerting.
- **Lightweight**: Written in Rust for speed and safety.

## 🛠️ Prerequisites
- **Rust** (Latest Stable)
- **libpcap-dev** (Linux/Debian)
  ```bash
  sudo apt install libpcap-dev
  ```

## 📦 Installation
```bash
git clone https://github.com/YOUR_USERNAME/net_sentinel.git
cd net_sentinel
cargo build --release
```

## 🧠 Usage

Net Sentinel operates in three modes: **Default (Capture)**, **Train**, and **Guard**.

### 1. Capture (Data Collection)
Capture normal traffic to create a training dataset (`training.data.csv`).
```bash
sudo ./target/release/net_sentinel
# Press Ctrl+C to stop after collecting enough packets (e.g., ~10k)
```

### 2. Train (Machine Learning)
Train the Isolation Forest model using the captured CSV data. This creates `model_isolation_forest.json`.
```bash
./target/release/net_sentinel -- train
```

### 3. Guard (Active Protection)
Monitor live traffic and flag anomalies based on the trained model.
```bash
sudo ./target/release/net_sentinel -- guard
```
*Note: You will see `🚨 ANOMALY` logs for traffic that deviates from the learned baseline.*

## 🗺️ Roadmap
- [ ] Add Source/Dest Port features
- [ ] Real-time Alerting (Webhooks)
- [ ] TUI Dashboard
