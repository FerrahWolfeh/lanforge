//! Supervisor de tasks — Monitoramento e resiliência com backoff exponencial.
//!
//! Este módulo provê a infraestrutura para garantir que as tasks de protocolo
//! (DHCP, DNS, RA) continuem rodando mesmo após falhas críticas, aplicando
//! uma estratégia de reinício com espera progressiva.
//!
//! ## Fluxo de Supervisão
//!
//! ```text
//!    [ Factory ] ──► [ Future ] ──► [ Execução ]
//!          ▲                            │
//!          │                            ▼
//!          │                    ┌───────────────┐
//!          │                    │  Sucesso?     │──► Ok(())
//!          │                    └──────┬────────┘
//!          │       [ Backoff ]         │ Não
//!          └───────────────────────────┘
//! ```

use std::time::Duration;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// Executa uma task supervisionada com reinício automático e backoff exponencial.
///
/// - `name`: nome legível para logs
/// - `critical`: se `true` e o serviço esgotar as tentativas, o processo termina
/// - `max_retries`: máximo de reinícios consecutivos (0 = infinito)
/// - `base_backoff`: intervalo inicial entre reinícios
/// - `max_backoff`: teto do backoff exponencial
/// - `factory`: closure que retorna o Future da task a cada tentativa
///
/// Cada execução bem-sucedida (retorno `Ok(())`) reseta o contador de falhas.
/// Um retorno `Err` incrementa o contador e aplica backoff.
pub async fn supervise_task<F, Fut>(
    name: &'static str,
    critical: bool,
    max_retries: u32,
    base_backoff: Duration,
    max_backoff: Duration,
    cancel: CancellationToken,
    factory: F,
) where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<()>>,
{
    let mut consecutive_failures: u32 = 0;

    loop {
        info!("Starting service '{name}'");

        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Supervisor '{name}' received shutdown signal, stopping");
                return;
            }
            res = factory() => {
                match res {
                    Ok(()) => {
                        // Task terminou normalmente — verifica se foi por shutdown
                        if cancel.is_cancelled() {
                            info!("Supervisor '{name}' shutting down after clean service exit");
                            return;
                        }
                        info!("Service '{name}' exited cleanly, restarting");
                        consecutive_failures = 0;
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        error!("Service '{name}' failed ({consecutive_failures}x): {e:#}");

                        if max_retries > 0 && consecutive_failures >= max_retries {
                            if critical {
                                error!(
                                    "Critical service '{name}' exhausted {max_retries} retries — aborting process"
                                );
                                std::process::exit(1);
                            } else {
                                warn!(
                                    "Non-critical service '{name}' exhausted {max_retries} retries — giving up"
                                );
                                return;
                            }
                        }

                        // Backoff exponencial com jitter: base * 2^(failures-1), capped
                        let exp = base_backoff.saturating_mul(1 << (consecutive_failures - 1).min(16));
                        let backoff = exp.min(max_backoff);

                        warn!(
                            "Restarting '{name}' in {:.1}s (attempt {}/{})",
                            backoff.as_secs_f64(),
                            consecutive_failures + 1,
                            if max_retries == 0 {
                                "∞".to_string()
                            } else {
                                max_retries.to_string()
                            }
                        );

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                info!("Supervisor '{name}' received shutdown signal during backoff, stopping");
                                return;
                            }
                            _ = sleep(backoff) => {}
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn gives_up_after_max_retries_non_critical() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        supervise_task(
            "test-service",
            false, // non-critical
            3,     // max 3 retries
            Duration::from_millis(1),
            Duration::from_millis(10),
            CancellationToken::new(),
            move || {
                let a = attempts_clone.clone();
                async move {
                    a.fetch_add(1, Ordering::Relaxed);
                    anyhow::bail!("always fails")
                }
            },
        )
        .await;

        assert_eq!(
            attempts.load(Ordering::Relaxed),
            3,
            "Supervisor deveria tentar exatamente max_retries vezes"
        );
    }

    #[tokio::test]
    async fn resets_failure_counter_on_success() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        supervise_task(
            "test-reset",
            false,
            3,
            Duration::from_millis(1),
            Duration::from_millis(10),
            CancellationToken::new(),
            move || {
                let a = attempts_clone.clone();
                async move {
                    let n = a.fetch_add(1, Ordering::Relaxed);
                    if n == 0 {
                        // Primeira chamada é um sucesso
                        Ok(())
                    } else if n < 4 {
                        // Próximas chamadas falham
                        anyhow::bail!("fails after success")
                    } else {
                        Ok(())
                    }
                }
            },
        )
        .await;

        // O supervisor executou 1x (sucesso) -> O contador de falha zerou.
        // Depois falhou 3x seguidas até desistir (atingiu o max_retries = 3).
        // Total de tentativas de loop = 4.
        assert_eq!(attempts.load(Ordering::Relaxed), 4);
    }
}
