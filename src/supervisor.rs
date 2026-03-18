//! Supervisor de tasks — loop de reinício com backoff exponencial.
//!
//! **Status: STUB** — será implementado na Fase 1.

#![allow(dead_code)]

use std::time::Duration;
use tokio::task::JoinHandle;

/// Especificação de um serviço supervisionado.
pub struct ServiceSpec {
    /// Nome legível do serviço (usado em logs).
    pub name: &'static str,
    /// Se true e falhar definitivamente, mata o processo inteiro.
    pub critical: bool,
    /// Número máximo de tentativas de reinício.
    pub max_retries: u32,
    /// Backoff inicial entre tentativas.
    pub base_backoff: Duration,
    /// Backoff máximo (cap do exponencial).
    pub max_backoff: Duration,
    /// Factory que cria a task supervisionada.
    pub factory: Box<dyn Fn() -> JoinHandle<anyhow::Result<()>> + Send>,
}

/// Executa os serviços especificados com supervisão e restart automático.
///
/// **Ainda não implementado** — placeholder para a Fase 1.
pub async fn run_supervised(_services: Vec<ServiceSpec>) -> ! {
    todo!("Implementar loop de supervisão com backoff")
}
