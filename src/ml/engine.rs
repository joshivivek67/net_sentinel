use extended_isolation_forest::{Forest, ForestOptions};
use log::info;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
pub type Dataset = Vec<[f64; 5]>;

pub fn train_model(data: &Dataset) -> Result<Forest<f64, 5>, Box<dyn Error>> {
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

pub fn is_anomaly(
    model: &Forest<f64, 5>,
    len: f64,
    proto: f64,
    iat: f64,
    src_port: f64,
    dst_port: f64,
) -> bool {
    let point = [len, proto, iat, src_port, dst_port];
    let score = model.score(&point);

    // DEBUG: Print EVERY score so we can see what is happening!
    //info!(
    //    "Packet Score: {:.4} (Len: {}, Proto: {}, IAT: {} ,Src Port: {}, Dst Port: {}, Src IP: {}, Dst IP: {})",
    //    score, len, proto, iat, src_port, dst_port, src_ip_num, dst_ip_num
    //);

    if score > 0.6 {
        info!(
            "🚨 ANOMALY! Score: {:.4} (Len: {}, Proto: {}, IAT: {} ,Src Port: {}, Dst Port: {})",
            score, len, proto, iat, src_port, dst_port
        );
        return true;
    }

    false
}
