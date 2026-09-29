//! Cryptographic primitives, password hashing, and security helpers for Lanforge.
//!
//! Serves as a foundational L1 crate isolating cryptographic algorithms
//! (e.g. Argon2id password hashing, and future TLS / DoT / DoQ primitives)
//! from the central daemon orchestration crate (`lanforge-core`).

pub mod password;

pub use password::{hash_password, verify_password};
