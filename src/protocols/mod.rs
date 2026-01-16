pub mod handler;
pub mod proto_ipv4;
pub mod proto_ipv6;
pub use handler::*;
use log::info;

pub fn init_stack() {
    info!("Initializing protocol stack");
}
