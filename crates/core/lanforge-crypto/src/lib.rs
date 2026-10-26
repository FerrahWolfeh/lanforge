//! Cryptographic primitives, password hashing, and security helpers for Lanforge.
//!
//! Serves as a foundational L1 crate isolating cryptographic algorithms
//! (e.g. Argon2id password hashing, and future TLS / DoT / DoQ primitives)
//! and deterministic content hashing from higher-level orchestration crates.

pub mod hash;
pub mod password;

pub use hash::{
    content_hash_hex, content_hash_short_hex, content_hash64, content_hash128, slugify,
    stable_id_or_hash,
};
pub use password::{hash_password, verify_password};
