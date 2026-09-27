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

#[macro_export]
macro_rules! render_output {
    ($client:expr, $resp:expr, $render_fn:expr) => {{
        let resp = $resp;
        if $client.json {
            println!("{}", serde_json::to_string_pretty(&resp)?);
            return Ok(());
        }
        $render_fn(&resp, $client.ascii);
        Ok(())
    }};
}
