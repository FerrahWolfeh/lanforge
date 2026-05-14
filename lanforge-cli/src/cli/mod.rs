pub mod client;
pub mod commands;
pub mod vendor;

use std::future::Future;

pub use client::{ClientOptions, LanforgeClient};
use color_eyre::eyre::Result;

pub trait Execute {
    fn execute(self, client: &LanforgeClient) -> impl Future<Output = Result<()>> + Send;
}
