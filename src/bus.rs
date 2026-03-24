//! `EventBus` — barramento de eventos interno do lanforge.
//!
//! Usa `tokio::sync::broadcast` para comunicação entre tasks.
//!
//! ## Modelo de eventos
//!
//! O barramento é **device-centric**: os eventos descrevem mudanças na
//! identidade e estado dos devices, não ações de protocolo. Os serviços
//! (`DHCPv4`, `DHCPv6`, Netlink) não publicam eventos diretamente — eles emitem
//! `DeviceUpdate` para o `DeviceTable`, e o Manager publica no barramento
//! caso o estado tenha efetivamente mudado.
//!
//! ```text
//! Protocolos ──► DeviceUpdate ──► DeviceTable (Manager)
//!                                       │
//!                                       │ se mudou
//!                                       ▼
//!                                   EventBus
//!                                       │
//!                          ┌────────────┼────────────┐
//!                          ▼            ▼             ▼
//!                         DNS          DB           CLI
//! ```
//!
//! ## Grupos de eventos
//!
//! - **Device**: ciclo de vida de identidades na rede.
//! - **Infra**: mudanças na infraestrutura de rede (prefixo GUA, etc.).
//! - **Control**: sinais internos de operação do daemon.

use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::sync::broadcast;

use crate::state::MacAddr;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// DeviceChange — o que mudou num device
// ---------------------------------------------------------------------------

/// Detalha qual aspecto de um `Device` foi alterado.
/// Publicado dentro de `LanforgeEvent::DeviceUpdated`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DeviceChange {
    /// Um endereço IPv4 foi atribuído ou renovado.
    V4Assigned { ip: Ipv4Addr },

    /// O lease IPv4 expirou e foi removido.
    V4Expired,

    /// Um endereço IPv6 (`DHCPv6`) foi atribuído ou renovado.
    V6Assigned { ip: Ipv6Addr },

    /// O lease IPv6 expirou e foi removido.
    V6Expired,

    /// Um prefixo IPv6 foi delegado via IA_PD.
    V6PrefixAssigned { prefix: Ipv6Addr, len: u8 },

    /// Um endereço SLAAC foi observado via NDP.
    SlaacObserved { addr: Ipv6Addr },

    /// O hostname do device foi atualizado.
    HostnameChanged { hostname: String },

    /// Uma reserva IPv4 estática foi definida ou removida via CLI.
    V4StaticChanged { ip: Option<Ipv4Addr> },

    /// Um sufixo IPv6 estático foi definido ou removido via CLI.
    V6SuffixChanged { suffix: Option<String> },

    /// Um DUID foi associado ao device.
    DuidAssociated,
}

// ---------------------------------------------------------------------------
// LanforgeEvent
// ---------------------------------------------------------------------------

/// Eventos que circulam pelo barramento.
///
/// Todos os consumers (DNS, DB, CLI) devem reagir apenas a esses eventos —
/// nunca a detalhes internos de protocolo.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LanforgeEvent {
    // -- Device lifecycle --
    /// Um device desconhecido foi visto pela primeira vez.
    /// O Manager já criou a entrada — consumers devem inicializar recursos
    /// para esta identidade (ex: DB insert, DNS pre-load).
    DeviceDiscovered { mac: MacAddr },

    /// Um device conhecido teve seu estado atualizado.
    DeviceUpdated { mac: MacAddr, change: DeviceChange },

    /// Um device dinâmico ficou inativo e foi removido da tabela.
    /// Consumers devem liberar recursos associados (ex: remover entrada DNS).
    DeviceExpired { mac: MacAddr },

    // -- Infra --
    /// O prefixo GUA do uplink mudou (ex: reboot do modem, nova delegação).
    /// Consumers como o RA e o DNS devem recalcular endereços derivados.
    PrefixChanged {
        gua: Option<Ipv6Addr>,
        preferred: u32,
        valid: u32,
    },

    // -- Control --
    /// Sinaliza que o `DeviceTable` foi modificado e deve ser persistido.
    /// Publicado pelo Manager; consumido pelo worker do DB com debounce.
    DeviceTableDirty,

    /// Solicita recarga do arquivo de configuração TOML.
    ReloadConfig,

    /// Solicita vacuum do banco de dados SQLite.
    DbVacuum,

    /// Solicita a liberação forçada de um lease.
    LeaseRelease { mac: MacAddr },

    /// Solicita a renovação (forcerenew) de um de um lease.
    LeaseRenew { mac: MacAddr },

    /// O daemon está encerrando — consumers devem finalizar graciosamente.
    Shutdown,
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

const BUS_CAPACITY: usize = 256;

/// Barramento de eventos compartilhado entre todas as tasks.
///
/// Distribuído via `Arc<EventBus>` no startup. Cada task chama
/// `bus.subscribe()` para receber eventos e `bus.publish()` para emitir.
///
/// Apenas o `DeviceTable` (Manager) deve publicar eventos de device.
/// Tasks de protocolo só publicam eventos de infra e controle.
pub struct EventBus {
    tx: broadcast::Sender<LanforgeEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }

    /// Cria um novo receiver. Chame no startup de cada task consumidora.
    pub fn subscribe(&self) -> broadcast::Receiver<LanforgeEvent> {
        self.tx.subscribe()
    }

    /// Publica um evento no barramento.
    /// Retorna o número de receivers que receberam o evento.
    /// Silencia o erro se não há receivers (normal durante startup).
    pub fn publish(&self, event: LanforgeEvent) -> usize {
        self.tx.send(event).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// ManagedTable — wrapper que conecta DeviceTable ao EventBus
// ---------------------------------------------------------------------------

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::state::{DeviceTable, DeviceUpdate};

/// Wrapper em torno do `DeviceTable` que automaticamente publica eventos
/// no `EventBus` após cada `apply_update`.
///
/// É este tipo que deve ser distribuído via `Arc<ManagedTable>` para as tasks
/// de protocolo — não o `DeviceTable` diretamente.
///
/// ## Uso
///
/// ```ignore
/// let table = Arc::new(ManagedTable::new(bus.clone()));
///
/// // Em qualquer task de protocolo:
/// table.update(DeviceUpdate::V4LeaseGranted { mac, ip, expires }).await;
/// ```
pub struct ManagedTable {
    inner: RwLock<DeviceTable>,
    bus: Arc<EventBus>,
}

impl ManagedTable {
    pub fn new(bus: Arc<EventBus>) -> Self {
        Self {
            inner: RwLock::new(DeviceTable::new()),
            bus,
        }
    }

    /// Aplica um update ao `DeviceTable` e publica os eventos correspondentes.
    ///
    /// Internamente:
    /// 1. Verifica se o device já existe antes do update.
    /// 2. Chama `apply_update` — autoridade de merging.
    /// 3. Se houve mudança:
    ///    - Publica `DeviceDiscovered` se o device é novo.
    ///    - Publica `DeviceUpdated` com o `DeviceChange` correspondente.
    ///    - Publica `DeviceTableDirty` para o worker de DB.
    pub async fn update(&self, update: DeviceUpdate) {
        let mut table = self.inner.write().await;

        let opt_mac = mac_of(&update);
        let is_new = if let Some(mac) = opt_mac {
            !table.devices.contains_key(&mac)
        } else {
            false
        };

        let change = device_change_of(&update);
        let changed = table.apply_update(update);

        drop(table);

        if !changed {
            return;
        }

        // Se não temos MAC (lease órfão), não publicamos eventos no bus que é device-centric.
        // O IP será "descoberto" depois via NdpSeen, que disparará a promoção e aí sim gera o evento.
        if let Some(mac) = opt_mac {
            if is_new {
                self.bus.publish(LanforgeEvent::DeviceDiscovered { mac });
            }

            if let Some(change) = change {
                self.bus
                    .publish(LanforgeEvent::DeviceUpdated { mac, change });
            }
        }

        self.bus.publish(LanforgeEvent::DeviceTableDirty);
    }

    /// Leitura do estado interno. Usar para DNS, CLI, DB snapshot.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, DeviceTable> {
        self.inner.read().await
    }

    /// Acesso de escrita direto — usar apenas para operações de manutenção
    /// como `expire_stale` e `load_static_devices`.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, DeviceTable> {
        self.inner.write().await
    }

    /// Retorna uma referência ao barramento de eventos.
    pub fn bus(&self) -> Arc<EventBus> {
        self.bus.clone()
    }
}

// ---------------------------------------------------------------------------
// Helpers internos
// ---------------------------------------------------------------------------

/// Extrai o MAC de qualquer variante de `DeviceUpdate`, se houver.
const fn mac_of(update: &DeviceUpdate) -> Option<MacAddr> {
    match update {
        DeviceUpdate::V4LeaseGranted { mac, .. } => Some(*mac),
        DeviceUpdate::V6LeaseGranted { mac, .. } => *mac,
        DeviceUpdate::V6PrefixAssigned { mac, .. } => *mac,
        DeviceUpdate::SlaacObserved { mac, .. } => Some(*mac),
        DeviceUpdate::NdpSeen { mac, .. } => Some(*mac),
        DeviceUpdate::ArpSeen { mac, .. } => Some(*mac),
        DeviceUpdate::HostnameHint { mac, .. } => Some(*mac),
        DeviceUpdate::DuidAssociated { mac, .. } => *mac,
        DeviceUpdate::CliHostUpdated { mac, .. } => Some(*mac),
        DeviceUpdate::SlaacCleared { mac } => Some(*mac),
        DeviceUpdate::LeaseReleased { mac } => Some(*mac),
        DeviceUpdate::IpDeleted { .. } => None,
    }
}

/// Converte um `DeviceUpdate` no `DeviceChange` correspondente para o bus.
/// Retorna `None` para updates que não geram evento de mudança (ex: `NdpSeen`).
fn device_change_of(update: &DeviceUpdate) -> Option<DeviceChange> {
    match update {
        DeviceUpdate::V4LeaseGranted { ip, .. } => Some(DeviceChange::V4Assigned { ip: *ip }),
        DeviceUpdate::V6LeaseGranted { ip, .. } => Some(DeviceChange::V6Assigned { ip: *ip }),
        DeviceUpdate::V6PrefixAssigned { prefix, len, .. } => {
            Some(DeviceChange::V6PrefixAssigned {
                prefix: *prefix,
                len: *len,
            })
        }
        DeviceUpdate::SlaacObserved { addr, .. } => {
            Some(DeviceChange::SlaacObserved { addr: *addr })
        }
        DeviceUpdate::HostnameHint { hostname, .. } => Some(DeviceChange::HostnameChanged {
            hostname: hostname.clone(),
        }),
        DeviceUpdate::DuidAssociated { .. } => Some(DeviceChange::DuidAssociated),
        DeviceUpdate::NdpSeen { .. }
        | DeviceUpdate::ArpSeen { .. }
        | DeviceUpdate::SlaacCleared { .. }
        | DeviceUpdate::LeaseReleased { .. } => None,

        DeviceUpdate::CliHostUpdated {
            hostname,
            v4_static,
            v6_suffix,
            ..
        } => {
            // CLI updates can change multiple things. We pick the most "urgent" change
            // to emit as a DeviceUpdated event. The Manager will also emit DeviceTableDirty
            // ensuring persistence regardless.
            if let Some(Some(hn)) = hostname {
                return Some(DeviceChange::HostnameChanged {
                    hostname: hn.clone(),
                });
            }
            if let Some(v4) = v4_static {
                return Some(DeviceChange::V4StaticChanged { ip: *v4 });
            }
            if let Some(v6) = v6_suffix {
                return Some(DeviceChange::V6SuffixChanged { suffix: v6.clone() });
            }
            None
        }
        DeviceUpdate::IpDeleted { .. } => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::SystemTime;

    fn make_bus() -> Arc<EventBus> {
        Arc::new(EventBus::new())
    }

    #[tokio::test]
    async fn new_device_publishes_discovered_and_updated() {
        let bus = make_bus();
        let mut rx = bus.subscribe();
        let table = ManagedTable::new(bus.clone());

        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let ip: Ipv4Addr = "192.168.0.10".parse().unwrap();
        let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

        table
            .update(DeviceUpdate::V4LeaseGranted { mac, ip, expires })
            .await;

        // Deve receber DeviceDiscovered, DeviceUpdated, DeviceTableDirty
        let mut events = vec![];
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }

        assert!(
            events
                .iter()
                .any(|e| matches!(e, LanforgeEvent::DeviceDiscovered { .. })),
            "Deve publicar DeviceDiscovered para device novo"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, LanforgeEvent::DeviceUpdated { .. })),
            "Deve publicar DeviceUpdated"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, LanforgeEvent::DeviceTableDirty)),
            "Deve publicar DeviceTableDirty"
        );
    }

    #[tokio::test]
    async fn known_device_does_not_publish_discovered() {
        let bus = make_bus();
        let table = ManagedTable::new(bus.clone());
        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let expires = SystemTime::now() + std::time::Duration::from_secs(3600);

        // Primeiro update — descobre o device
        table
            .update(DeviceUpdate::V4LeaseGranted {
                mac,
                ip: "192.168.0.10".parse().unwrap(),
                expires,
            })
            .await;

        let mut rx = bus.subscribe();

        // Segundo update com IP diferente — não deve ser Discovered
        table
            .update(DeviceUpdate::V4LeaseGranted {
                mac,
                ip: "192.168.0.11".parse().unwrap(),
                expires,
            })
            .await;

        let mut events = vec![];
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }

        assert!(
            !events
                .iter()
                .any(|e| matches!(e, LanforgeEvent::DeviceDiscovered { .. })),
            "Device já conhecido não deve gerar DeviceDiscovered"
        );
    }

    #[tokio::test]
    async fn ndp_seen_publishes_nothing() {
        let bus = make_bus();
        let table = ManagedTable::new(bus.clone());
        let mut rx = bus.subscribe();

        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
        let ip: std::net::Ipv6Addr = "fe80::1".parse().unwrap();

        table.update(DeviceUpdate::NdpSeen { mac, ip }).await;

        // NdpSeen não gera eventos no barramento (só bump de last_seen)
        let count = {
            let mut n = 0;
            while rx.try_recv().is_ok() {
                n += 1;
            }
            n
        };
        assert_eq!(count, 0, "NdpSeen não deve publicar eventos");
    }

    #[tokio::test]
    async fn cli_host_update_publishes_events() {
        let bus = make_bus();
        let table = ManagedTable::new(bus.clone());
        let mut rx = bus.subscribe();

        let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();

        // 1. Hostname update
        table
            .update(DeviceUpdate::CliHostUpdated {
                mac,
                hostname: Some(Some("cli-host".to_string())),
                v4_static: None,
                v6_suffix: None,
            })
            .await;

        let mut events = vec![];
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }

        assert!(
            events.iter().any(|e| matches!(
                e,
                LanforgeEvent::DeviceUpdated {
                    mac: _,
                    change: DeviceChange::HostnameChanged { .. }
                }
            )),
            "Deve publicar HostnameChanged"
        );

        // 2. Static IPv4 update
        table
            .update(DeviceUpdate::CliHostUpdated {
                mac,
                hostname: None,
                v4_static: Some(Some("1.2.3.4".parse().unwrap())),
                v6_suffix: None,
            })
            .await;

        let mut events = vec![];
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }

        assert!(
            events.iter().any(|e| matches!(
                e,
                LanforgeEvent::DeviceUpdated {
                    mac: _,
                    change: DeviceChange::V4StaticChanged { .. }
                }
            )),
            "Deve publicar V4StaticChanged"
        );
    }
}
