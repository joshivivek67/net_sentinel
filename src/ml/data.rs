use extended_isolation_forest::{Forest, ForestOptions};
use log::info;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
pub type Dataset = Vec<[f64; 5]>;

pub fn load_training_data() -> Result<Dataset, Box<dyn Error>> {
    let mut reader = csv::Reader::from_path("training.data.csv")?;
    let mut data = Vec::new();

    for result in reader.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue, // Skip bad CSV lines
        };

        // SAFETY CHECK: Ensure we actually have 2 columns and they aren't empty
        if record.len() < 5
            || record[0].is_empty()
            || record[1].is_empty()
            || record[2].is_empty()
            || record[3].is_empty()
            || record[4].is_empty()
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

        data.push([len, proto, iat, src_port, dst_port]);
    }
    Ok(data)
}
pub fn save_model(model: &Forest<f64, 5>) -> Result<(), Box<dyn Error>> {
    let mut file = File::create("model_isolation_forest.json")?;
    let serialized = serde_json::to_string_pretty(model)?;
    file.write_all(serialized.as_bytes())?;
    info!("Model saved successfully!");
    Ok(())
}
pub fn load_model(path: &str) -> Result<Forest<f64, 5>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    // Deserialize the JSON string back into a Forest
    let model: Forest<f64, 5> = serde_json::from_str(&content)?;
    Ok(model)
}
