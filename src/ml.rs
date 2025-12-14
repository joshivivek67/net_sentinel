use extended_isolation_forest::{Forest, ForestOptions};
use log::info;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
// Define our data type: A list of rows, where each row is a list of numbers
pub type Dataset = Vec<[f64; 2]>;

pub fn load_training_data() -> Result<Dataset, Box<dyn Error>> {
    let mut reader = csv::Reader::from_path("training.data.csv")?;
    let mut data = Vec::new();

    for result in reader.records() {
        let record = match result {
            Ok(r) => r,
            Err(_) => continue, // Skip bad CSV lines
        };

        // SAFETY CHECK: Ensure we actually have 2 columns and they aren't empty
        if record.len() < 2 || record[0].is_empty() || record[1].is_empty() {
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

        data.push([len, proto]);
    }
    Ok(data)
}

pub fn train_model(data: &Dataset) -> Result<Forest<f64, 2>, Box<dyn Error>> {
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

pub fn save_model(model: &Forest<f64, 2>) -> Result<(), Box<dyn Error>> {
    let mut file = File::create("model_isolation_forest.json")?;
    let serialized = serde_json::to_string(model)?;
    file.write_all(serialized.as_bytes())?;
    info!("Model saved successfully!");
    Ok(())
}
pub fn load_model(path: &str) -> Result<Forest<f64, 2>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    // Deserialize the JSON string back into a Forest
    let model: Forest<f64, 2> = serde_json::from_str(&content)?;
    Ok(model)
}

pub fn is_anomaly(model: &Forest<f64, 2>, len: f64, proto: f64) -> bool {
    let point = [len, proto];
    let score = model.score(&point);

    // DEBUG: Print EVERY score so we can see what is happening!
    info!(
        "Packet Score: {:.4} (Len: {}, Proto: {})",
        score, len, proto
    );

    if score > 0.6 {
        info!(
            "🚨 ANOMALY! Score: {:.4} (Len: {}, Proto: {})",
            score, len, proto
        );
        return true;
    }

    false
}
