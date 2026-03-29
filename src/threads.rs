//! Infraestrutura para serviços como OS threads nomeadas com runtime próprio.

use std::{
    thread::{Builder, JoinHandle},
    time::Instant,
};

/// Spawna um serviço como OS thread nomeada com um runtime `current_thread` isolado.
///
/// Cada thread aparece com o nome dado no `htop`, `ps -T` e em `/proc/<pid>/task/`.
/// O `stack_kb` controla o tamanho da stack (padrão Linux = 8 MB por thread).
pub fn spawn_service_thread<F, Fut>(name: &'static str, stack_kb: usize, f: F) -> JoinHandle<()>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    Builder::new()
        .name(name.into())
        .stack_size(stack_kb * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| panic!("thread '{name}': failed to build runtime: {e}"))
                .block_on(f())
        })
        .unwrap_or_else(|e| panic!("failed to spawn thread '{name}': {e}"))
}

/// Aguarda que todas as threads de serviço terminem, com timeout de parede.
///
/// Usa um canal `mpsc` para receber sinais de conclusão sem bloquear indefinidamente.
/// Threads que não respondem dentro de `timeout` são abandonadas (o processo sai logo
/// após, então o OS limpa tudo).
pub fn wait_for_service_threads(
    handles: Vec<(&'static str, JoinHandle<()>)>,
    timeout: std::time::Duration,
) {
    use std::sync::mpsc;
    use tracing::{info, warn};

    let (tx, rx) = mpsc::channel::<&'static str>();
    let expected = handles.len();

    // Spawna uma thread de monitor por serviço — apenas notifica quando termina.
    for (name, handle) in handles {
        let tx = tx.clone();
        std::thread::Builder::new()
            .name(format!("{name}-monitor"))
            .spawn(move || {
                let _ = handle.join();
                let _ = tx.send(name);
            })
            .expect("failed to spawn monitor thread");
    }
    drop(tx); // para o canal fechar quando todos os monitores saírem

    let deadline = Instant::now() + timeout;
    let mut finished = 0;

    while finished < expected {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            warn!(
                "⚠️  Shutdown timeout atingido ({}/{} serviços finalizados)",
                finished, expected
            );
            return;
        }
        match rx.recv_timeout(remaining) {
            Ok(name) => {
                info!("  ✓ Thread '{name}' finalizada");
                finished += 1;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                warn!("⚠️  Shutdown timeout — forçando saída");
                return;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if finished == expected {
        info!("✅ Todas as threads finalizadas graciosamente.");
    }
}
