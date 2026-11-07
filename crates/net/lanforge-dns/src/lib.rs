//! Lanforge DNS Server
//!
//! A high-performance, modular DNS server for local network orchestration.
//! Features zero-allocation wire parsing, ad-blocking, and recursive forwarding.

#[cfg(test)]
use rcgen as _;

// rustls needs a crypto provider: without one, building a TLS config panics at runtime.
#[cfg(all(
    any(
        feature = "dot",
        feature = "doq",
        feature = "doh-upstream",
        feature = "adblock"
    ),
    not(any(feature = "ring", feature = "aws-lc"))
))]
compile_error!(
    "lanforge-dns: `dot`, `doq`, `doh-upstream` and `adblock` need a TLS crypto provider; \
     enable `ring` or `aws-lc`"
);

pub mod config;
pub mod error;
pub mod pipeline;
pub mod resolver;
pub mod server;
pub mod telemetry;
pub mod utils;

#[cfg(test)]
pub mod test_utils;
