pub mod client;
pub mod commands;
pub mod vendor;
pub mod wizard;

use std::future::Future;

pub use client::LanforgeClient;
use color_eyre::eyre::Result;

pub trait Execute {
    fn execute(self, client: &LanforgeClient) -> impl Future<Output = Result<()>> + Send;
}
