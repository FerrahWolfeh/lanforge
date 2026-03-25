//! Persistência `SQLite` para a `DeviceTable`.
//!
//! ## Arquitetura
//!
//! O módulo tem duas camadas:
//!
//! - **`LeaseDb`** (engine) — motor `SQLite` síncrono (rusqlite). Responsável pelo
//!   schema, serialização e desserialização. Não sabe nada de async.
//!
//! - **`db_worker`** (worker) — task async que escuta `LanforgeEvent::DeviceTableDirty`
//!   no `EventBus` e persiste o estado com debounce, protegendo o SD card
//!   de escritas excessivas durante boot storms ou rajadas de leases.

pub mod engine;
#[cfg(test)]
pub mod tests;
pub mod worker;

pub use engine::LeaseDb;
pub use worker::db_worker;
