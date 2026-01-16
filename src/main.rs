use crossbeam_channel::bounded;
use crossterm::event::Event;
use log::info;
use std::env;
use std::process;
use std::time::Duration;
mod capture;
mod ml;
pub mod tui;
mod utils;

use tui::App;
use tui::terminal::TuiManager;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("RUST_LOG").is_err() {
        unsafe {
            env::set_var("RUST_LOG", "info");
        }
    }
    env_logger::init();
    // 1. Get args into a Vector
    // 1. Get args into a Vector
    let args: Vec<String> = env::args().collect();

    // Find the first argument that isn't the binary path (index 0) and isn't "--"
    let mode = args
        .iter()
        .skip(1)
        .find(|&arg| arg != "--")
        .map(|s| s.as_str())
        .unwrap_or("capture");
    info!("NetSentinal starting in [{}] mode ...", mode);

    if mode == "train" {
        // ---- Brain Mode ----
        info!("Loading Data...");
        let dataset = ml::load_training_data().unwrap();
        let model = ml::train_model(&dataset).unwrap();
        info!("Model Trained Successfully!");
        ml::save_model(&model).unwrap();
        info!("Model Saved Successfully!");
    } else if mode == "capture" {
        let device = match capture::get_device_default_interface() {
            Ok(d) => d,
            Err(e) => {
                info!("Error finding device: {}", e);
                process::exit(1);
            }
        };
        capture::start_training_capture(device).unwrap();
    } else if mode == "guard" {
        // --- GUARD MODE --- 🛡️
        info!("Loading Brain...");

        let (tx, rx) = bounded::<capture::PacketFiled>(100);
        let mut app = App::new();
        // 1. Load the model from disk (We need to write this helper
        let model = ml::load_model("model_isolation_forest.json").unwrap();

        // 1. WE NEED TO FIND THE DEVICE HERE TOO! (Copy-paste this logic)
        let device = match capture::get_device_default_interface() {
            Ok(d) => d,
            Err(e) => {
                info!("Error finding device: {}", e);
                process::exit(1);
            }
        };

        // 2. Start capturing WITH the model
        // We will need to create a new function in capture.rs called 'start_guard'
        std::thread::spawn(move || {
            capture::start_background_capture(device, model, tx).unwrap();
        });

        info!("Guard active.");
        let mut tui = TuiManager::new()?;
        loop {
            tui.terminal.draw(|frame| {
                tui::ui::render(frame, &app);
            })?;
            if crossterm::event::poll(Duration::from_millis(100))? {
                if let Event::Key(key_event) = crossterm::event::read()? {
                    if key_event.code == crossterm::event::KeyCode::Char('q')
                        || key_event.code == crossterm::event::KeyCode::Esc
                    {
                        break;
                    }
                }
            }
            while let Ok(pf) = rx.try_recv() {
                app.on_tick(pf);
            }
        }
    } else {
        let device = match capture::get_device_default_interface() {
            Ok(device) => device,
            Err(e) => {
                info!("Failed to get default interface: {}", e);
                process::exit(1);
            }
        };
    }
    Ok(())
}
