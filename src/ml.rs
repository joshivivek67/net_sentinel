use extended_isolation_forest::{Forest, ForestOptions};
use log::info;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
// Define our data type: A list of rows, where each row is a list of numbers
pub type Dataset = Vec<[f64; 7]>;

pub fn load_training_data() -> Result<Dataset, Box<dyn Error>> {
    let mut reader = csv::Reader::from_path("training.data.csv")?;
    let mut data = Vec::new();

    for result in reader.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue, // Skip bad CSV lines
        };

        // SAFETY CHECK: Ensure we actually have 2 columns and they aren't empty
        if record.len() < 3
            || record[0].is_empty()
            || record[1].is_empty()
            || record[2].is_empty()
            || record[3].is_empty()
            || record[4].is_empty()
            || record[5].is_empty()
            || record[6].is_empty()
        {
            continue;
        }

        // Parse safely. If it's not a number, skip this row.
        let len: f64 = match record[0].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let proto: f64 = match record[1].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let iat: f64 = match record[2].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let src_port: f64 = match record[3].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let dst_port: f64 = match record[4].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let src_ip_num: f64 = record[5]
            .parse::<IpAddr>()
            .map(|ip| match ip {
                IpAddr::V4(v4) => u32::from(v4) as f64,
                IpAddr::V6(_) => 0.0,
            })
            .unwrap_or(0.0);
        let dst_ip_num: f64 = record[6]
            .parse::<IpAddr>()
            .map(|ip| match ip {
                IpAddr::V4(v4) => u32::from(v4) as f64,
                IpAddr::V6(_) => 0.0,
            })
            .unwrap_or(0.0);

        data.push([len, proto, iat, src_port, dst_port, src_ip_num, dst_ip_num]);
    }
    Ok(data)
}

pub fn train_model(data: &Dataset) -> Result<Forest<f64, 7>, Box<dyn Error>> {
    info!(
        "Training Extended Isolation Forest on {} packets...",
        data.len()
    );

    //Setting
    let options = ForestOptions {
        n_trees: 100,
        sample_size: 256,
        max_tree_depth: None,
        extension_level: 0,
    };
    // 0 = Normal Isolation Forest. 1 = Extended (Diagonal cuts)

    // Train the Forest
    // Note: We map the error to string because the library uses a custom Error type
    let forest = Forest::from_slice(data, &options).map_err(|e| e.to_string())?;
    info!("Model Trained Successfully! tree {}", options.n_trees);
    Ok(forest)
}

pub fn save_model(model: &Forest<f64, 7>) -> Result<(), Box<dyn Error>> {
    let mut file = File::create("model_isolation_forest.json")?;
    let serialized = serde_json::to_string_pretty(model)?;
    file.write_all(serialized.as_bytes())?;
    info!("Model saved successfully!");
    Ok(())
}
pub fn load_model(path: &str) -> Result<Forest<f64, 7>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    // Deserialize the JSON string back into a Forest
    let model: Forest<f64, 7> = serde_json::from_str(&content)?;
    Ok(model)
}

pub fn is_anomaly(
    model: &Forest<f64, 7>,
    len: f64,
    proto: f64,
    iat: f64,
    src_port: f64,
    dst_port: f64,
    src_ip_num: f64,
    dst_ip_num: f64,
) -> bool {
    let point = [len, proto, iat, src_port, dst_port, src_ip_num, dst_ip_num];
    let score = model.score(&point);

    // DEBUG: Print EVERY score so we can see what is happening!
    //info!(
    //    "Packet Score: {:.4} (Len: {}, Proto: {}, IAT: {} ,Src Port: {}, Dst Port: {}, Src IP: {}, Dst IP: {})",
    //    score, len, proto, iat, src_port, dst_port, src_ip_num, dst_ip_num
    //);

    if score > 0.6 {
        info!(
            "🚨 ANOMALY! Score: {:.4} (Len: {}, Proto: {}, IAT: {} ,Src Port: {}, Dst Port: {}, Src IP: {}, Dst IP: {})",
            score, len, proto, iat, src_port, dst_port, src_ip_num, dst_ip_num
        );
        return true;
    }

    false
}
