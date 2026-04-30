//! # Lanforge API
//!
//! This crate provides the management and control interface for the `lanforge` daemon.
//! It allows CLI tools and local interfaces to query status and control
//! the daemon using JSON-encoded commands over a local Unix Domain Socket (UDS).
//!
//! ## Architecture Overview
//!
//! The API follows a request-response pattern where the client connects to a UDS socket,
//! sends a JSON command followed by a newline, and receives a JSON response.
//!
//! ```mermaid
//! sequenceDiagram
//!     participant Client
//!     participant Server as Lanforge API Service
//!     participant Bus as Event Bus
//!
//!     Client->>Server: Connect (UDS)
//!     Client->>Server: JSON Command\n(e.g., {"command":"status"})
//!     Server->>Bus: Request Data / Action
//!     Bus-->>Server: Data / Confirmation
//!     Server-->>Client: JSON Response\n(e.g., {"uptime_secs": 120, ...})
//!     Note over Client,Server: Connection remains open for more commands
//! ```
//!
//! ## Examples
//!
//! ### Serializing a Command
//!
//! ```rust
//! use lanforge_api::api::{Command, CommandAction};
//!
//! // Create a status command
//! let cmd = Command::new(CommandAction::Status);
//!
//! // Serialize to JSON string
//! let json = serde_json::to_string(&cmd).unwrap();
//! assert_eq!(json, r#"{"command":"status"}"#);
//! ```
//!
//! ### Common Usage Pattern
//!
//! Most clients will use a JSON-RPC-like approach:
//! 1. Open `/run/lanforge/control.sock` (or configured path).
//! 2. Write `{"command": "status"}\n`.
//! 3. Read the response line and parse it as a `Response` enum.

pub mod api;
#[cfg(feature = "http")]
pub mod auth;
pub mod config;
#[cfg(feature = "dot")]
pub mod dot;
pub mod error;
pub mod handlers;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub mod metrics;
pub mod server;
#[cfg(test)]
pub mod tests;
#[cfg(any(feature = "https", feature = "tls"))]
pub mod tls;
