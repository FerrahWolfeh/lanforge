# LANforge — Arquitetura

Daemon unificado de controle de rede IPv4/IPv6 para Raspberry Pi 4B.
Substitui: radvd, dnsmasq (DHCP + DNS local), ipv6_namer.
Integra com: pihole-FTL (DNS upstream + UI), systemd-networkd (PPPoE/WAN), nftables.

---

## Filosofia central

O programa nasceu como um tracker de SLAAC (`ipv6_namer`) e cresceu absorvendo todos os
serviços que antes se comunicavam via arquivos e sinais — um modelo frágil e com condições
de corrida inevitáveis.

A decisão central é **um processo, múltiplas tasks tokio supervisionadas**, com um
**modelo device-first**: o `lanforge` tem uma noção primária de *quem está na rede*.
Os serviços de IP (DHCP), LAN (RA) e resolução (DNS) servem *em função dos devices*,
não o contrário.

Na prática isso significa que ao invés do programa manter o status das leases e tentar
reconstruir a identidade dos devices a partir delas, ele mantém a identidade primeiro
e deriva as leases e respostas DNS a partir dela.

**Motivos concretos:**

- Uma única conexão netlink alimenta todos os serviços via canal interno
- A tabela de devices é estado compartilhado — IPC adicionaria complexidade sem ganho
- Rust isola falhas por task; um panic não derruba o processo
- O PPPoE é a única exceção: processo separado, porque é o único que mata a internet
  se travar junto com outra coisa

---

## Visão geral do sistema

```
┌────────────────────────────────────────────────────────────────────────────┐
│                            lanforge (processo)                             │
│                                                                            │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         ┌──────────┐ │
│   │  DHCPv4  │ │  DHCPv6  │ │    RA    │ │  SLAAC   │         │   DNS    │ │
│   │ :67/udp  │ │ :547/udp │ │  ICMPv6  │ │  tracker │         │ :53/udp  │ │
│   └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘         └─────▲────┘ │
│        │            │            │            │                     │      │
│        └────────────┴─────┬──────┴────────────┘                     │      │
│                           │ DeviceUpdate                            │      │
│                 ┌─────────▼─────────┐                               │      │
│                 │   ManagedTable    │                               │      │
│                 │ (autoridade única)│───────────────────────────────┘      │
│                 │   DeviceTable +   │           read-only                  │
│                 │   apply_update()  │                                      │
│                 └─────────┬─────────┘                                      │
│                           │ LanforgeEvent                                  │
│                 ┌─────────▼─────────┐                                      │
│                 │     EventBus      │                                      │
│                 │ (broadcast chan)  │                                      │
│                 └─────────┬─────────┘                                      │
│                           │                                                │
│                 ┌─────────┴──────────────┐                                 │
│                 │                        │                                 │
│          ┌──────▼───────┐         ┌──────▼───────┐                         │
│          │  db_worker   │         │   Netlink    │                         │
│          │   (SQLite)   │         │  (1 socket)  │                         │
│          │   debounce   │         │              │                         │
│          └──────────────┘         └──────────────┘                         │
│                                                                            │
│   ┌────────────────────────────────────────────────────────────────────┐   │
│   │ Supervisor — reinicia tasks com backoff, propaga erros fatais      │   │
│   └────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────┘
                 ▲                                                    │       
                 │ PPPoE (proc separado)                              │ upstream DNS
                 │                                                    ▼       
        ┌────────┴─────────┐                                   ┌──────┴───────┐
        │   pppoe-client   │                                   │  pihole-FTL  │
        │ (proc separado)  │                                   │(UI + filtros)│
        └──────────────────┘                                   └──────────────┘
```

---

## Fluxo de escrita de estado

Nenhum módulo escreve diretamente nos campos de `Device`. O caminho único é:

```
Protocolo aprende algo
                    │
                    │ cria DeviceUpdate
                    ▼
       ManagedTable::update(update)
                    │
                    ├─► DeviceTable::apply_update(update) ──► retorna bool (mudou?)
                    │        (merging + precedência)
                    │
                    ├─► se mudou + device novo ──► EventBus::publish(DeviceDiscovered)
                    │
                    ├─► se mudou ────────────────► EventBus::publish(DeviceUpdated)
                    │
                    └─► se mudou ────────────────► EventBus::publish(DeviceTableDirty)
                                                                     │
                                                                     ▼
                                                                 db_worker
                                                               (debounce 3s)
                                                                     │
                                                                     ▼
                                                               SQLite::save()
```

Regras de precedência em `apply_update`:

- Hostname estático (TOML) nunca é sobrescrito por `HostnameHint` dinâmico
- Config estática de IP tem prioridade na resolução DNS sobre lease dinâmico
- `NdpSeen` nunca marca dirty — é ruído de rede, não mudança de identidade
- `SlaacObserved` só é emitido para IPs no mesmo /64 que o GUA atual

---

## Fluxo do GUA dinâmico

O prefixo GUA do ISP é dinâmico por natureza — não é configurado no TOML,
é descoberto em runtime pelo RA ao ler os endereços da interface:

```
RA detecta novo GUA na interface
    └─► EventBus::publish(PrefixChanged { gua: Some(...) })
              │
              ▼
        main.rs: current_gua = gua   ← variável local no loop principal
              │
              ▼
        run_scan(..., current_gua)
              │
              ▼
        NeighborEvent::to_device_update(gua.as_ref())
              │
    ┌─────────┴──────────┐
    ▼                    ▼
SlaacObserved        NdpSeen
(IP no /64 do GUA)   (link-local / sem GUA)
```

Sem GUA configurado (ISP sem IPv6 ou delegação pendente), `current_gua = None`
e todos os eventos NDP viram `NdpSeen` — comportamento conservador correto.

---

## Estrutura de módulos

```
src/
├── main.rs          Bootstrap, loop principal (Netlink + timers + sinais)
├── config.rs        Config (clap + TOML + env), builders para configs de serviço
├── supervisor.rs    Reinício com backoff exponencial
│
├── bus.rs           EventBus + LanforgeEvent + DeviceChange + ManagedTable
├── state.rs         Device, DeviceTable, DeviceUpdate, MacAddr, leases
│
├── netlink.rs       NeighborEvent, extract_neigh_info, get_ipv6_neighbors
├── db.rs            LeaseDb (SQLite), db_worker (reativo, debounce)
│
├── ra/
│   ├── mod.rs       ra_service() — RA RFC 4861/8106, detecta GUA dinâmico
│   ├── config.rs    RaConfig, PrefixConfig, RdnssConfig
│   └── packet.rs    build_ra_packet(), icmpv6_checksum()
│
├── dhcp/
│   ├── identity.rs  DeviceIdentity — resolve identidade a partir de MAC/DUID/vendor
│   ├── v4/
│   │   ├── mod.rs   dhcpv4_service() — AF_PACKET, emite DeviceUpdate
│   │   ├── server.rs DhcpServer, HandleResult
│   │   ├── pool.rs  Alocador de IPs
│   │   ├── raw.rs   RawSender (AF_PACKET Layer 2)
│   │   └── config.rs Dhcpv4Config
│   └── v6/
│       ├── mod.rs   dhcpv6_service() — UDP:547, emite DeviceUpdate
│       ├── server.rs Dhcpv6Server, HandleResult (recebe &ManagedTable)
│       ├── duid.rs  Duid, parse/geração DUID-LL/LLT/EN
│       ├── pool.rs  Ipv6Pool
│       └── config.rs Dhcpv6Config
│
├── dns/
│   └── mod.rs       dns_service() — A/AAAA/PTR, forward upstream, lê ManagedTable
│
└── slaac/
    └── mod.rs       process_cycle_v2() — dump NDP, emite DeviceUpdate
```

---

## Tipos centrais (`state.rs`)

### `MacAddr`

```rust
pub struct MacAddr(pub [u8; 6]);

impl From<[u8; 6]> for MacAddr { ... }   // zero-cost
impl AsRef<[u8; 6]> for MacAddr { ... }  // zero-cost, útil para FFI/Netlink
impl Display for MacAddr { ... }         // "aa:bb:cc:dd:ee:ff"
```

### `DeviceUpdate` — único canal de escrita

```rust
pub enum DeviceUpdate {
    V4LeaseGranted  { mac, ip: Ipv4Addr, expires },
    V6LeaseGranted  { mac, duid: Duid, ip: Ipv6Addr, expires },
    SlaacObserved   { mac, addr: Ipv6Addr },   // marca dirty
    NdpSeen         { mac, ip: Ipv6Addr },     // NÃO marca dirty
    HostnameHint    { mac, hostname },         // ignorado se is_static
    DuidAssociated  { mac, duid },
    SlaacCleared    { mac },
}
```

### `Device`

```rust
pub struct Device {
    pub mac:       MacAddr,
    pub hostname:  String,
    pub is_static: bool,           // config estática — protegido de sobrescrita
    pub duid:      Option<Duid>,
    pub v4:        Option<V4Lease>,
    pub v6:        Option<V6Lease>,
    pub slaac:     Vec<Ipv6Addr>,
    pub last_seen: SystemTime,
}
```

### `DeviceTable` — leituras públicas relevantes

```rust
impl DeviceTable {
    pub fn apply_update(&mut self, update: DeviceUpdate) -> bool;

    pub fn find_by_duid(&self, duid: &Duid) -> Option<&Device>;
    pub fn find_device_by_mac(&self, mac: MacAddr) -> Option<&Device>;
    pub fn find_duid_by_mac(&self, mac: MacAddr) -> Option<&Duid>;

    pub fn devices(&self) -> impl Iterator<Item = &Device>;
    pub fn static_entries(&self) -> impl Iterator<Item = &StaticEntry>;
    pub fn get_mac_from_ndp_cache(&self, ip: &Ipv6Addr) -> Option<MacAddr>;

    pub fn expire_stale(&mut self) -> bool;
    pub fn load_static_devices(&mut self, entries: &[StaticDeviceCfg]);
}
```

### `ManagedTable` — o que os serviços recebem (`Arc<ManagedTable>`)

```rust
pub struct ManagedTable {
    inner: RwLock<DeviceTable>,
    bus:   Arc<EventBus>,
}

impl ManagedTable {
    pub async fn update(&self, update: DeviceUpdate);         // escreve + publica
    pub async fn read(&self)  -> RwLockReadGuard<DeviceTable>; // leitura (DNS, CLI)
    pub async fn write(&self) -> RwLockWriteGuard<DeviceTable>; // manutenção apenas
}
```

---

## EventBus (`bus.rs`)

### Eventos device-centric

Os serviços de protocolo não publicam no bus diretamente. O `ManagedTable` publica
em nome deles após aplicar o `DeviceUpdate`.

```rust
pub enum LanforgeEvent {
    // Ciclo de vida de identidades
    DeviceDiscovered { mac: MacAddr },
    DeviceUpdated    { mac: MacAddr, change: DeviceChange },
    DeviceExpired    { mac: MacAddr },

    // Infra de rede
    PrefixChanged    { gua: Option<Ipv6Addr> },

    // Controle
    DeviceTableDirty,   // → db_worker persiste
    ReloadConfig,
    Shutdown,           // → flush imediato + encerramento gracioso
}

pub enum DeviceChange {
    V4Assigned      { ip: Ipv4Addr },
    V4Expired,
    V6Assigned      { ip: Ipv6Addr },
    V6Expired,
    SlaacObserved   { addr: Ipv6Addr },
    HostnameChanged { hostname: String },
    DuidAssociated,
}
```

---

## DNS interno (`dns/mod.rs`)

O `lanforge` inclui um servidor DNS autoritativo para a LAN. O pihole-FTL
aponta para ele como upstream local (ex: `127.0.0.1:5300`).

```
Query DNS recebida (A/AAAA/PTR)
    │
    ▼
normalize_name()          remove sufixo do search_domain
    │
    ▼
ManagedTable::read()      snapshot do estado atual
    │
    ├─► resolve_local()   hostname → IP(s) do device
    │       │  estático tem precedência sobre lease dinâmico
    │       │  fallback: "host-{mac_sem_dois_pontos}"
    │
    └─► resolve_ptr()     IP reverso → hostname do device
            │  checa: v4 lease, static entry, v6 lease, slaac[]
            │
            se não encontrou → forward_to_upstream() → Unbound :5335
```

O DNS é **reativo de graça**: quando `ManagedTable::update` muda o estado,
a próxima query já reflete a mudança — sem reload, sem arquivo de hosts,
sem mecanismo extra.

---

## Persistência (`db.rs`)

### Schema SQLite

```sql
CREATE TABLE devices (
    mac       TEXT PRIMARY KEY,
    hostname  TEXT NOT NULL,
    is_static INTEGER NOT NULL,
    duid      BLOB,
    last_seen INTEGER NOT NULL        -- unix timestamp
);
CREATE TABLE v4_leases (
    mac TEXT PRIMARY KEY REFERENCES devices(mac),
    ip TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE v6_leases (
    mac TEXT PRIMARY KEY REFERENCES devices(mac),
    ip TEXT NOT NULL, expires INTEGER NOT NULL
);
CREATE TABLE slaac_addrs (
    mac TEXT NOT NULL REFERENCES devices(mac),
    ip  TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);
```

### Bootstrap

```
lanforge sobe
    │
    ├─► LeaseDb::load_table()       reconstrói DeviceTable via apply_update()
    │         └─► *table.write() = persisted
    │
    ├─► load_static_devices(cfg)    TOML tem precedência sobre DB
    │
    └─► serviços sobem              já com estado completo em memória
```

### db_worker (reativo)

```
EventBus::DeviceTableDirty recebido
    │
    ├─► drain_with_debounce(3s)    absorve Dirty extras, retorna em Shutdown
    │
    ├─► ManagedTable::read()       snapshot breve (read lock)
    │
    └─► spawn_blocking             rusqlite é síncrono — não bloqueia runtime
            └─► LeaseDb::save_table()   transação única, DELETE + INSERT
```

---

## Configuração (`config.rs`)

Três camadas em ordem crescente de precedência:

1. Valores default hardcoded
2. Arquivo TOML (`--config` ou `LANFORGE_CONFIG`, default `/etc/lanforge/lanforge.toml`)
3. Variáveis de ambiente / flags CLI

```toml
[general]
iface_lan     = "end0"
iface_wan     = "ppp0"
leases_db     = "/var/lib/lanforge/leases.db"
target_prefix = "fd97:f00d:cafe:3731"   # prefixo para scan SLAAC
debounce_secs = 2
fallback_mins = 5
# gua_prefix não existe — GUA é aprendido dinamicamente pelo RA

[ra]
enabled         = true
managed         = true
other_config    = true
max_interval    = 100
router_lifetime = 1800
mtu             = 1492   # PPPoE

[[ra.prefix]]
source  = "ula"
address = "fd97:f00d:cafe:3731::"

[[ra.prefix]]
source = "auto_gua"   # detectado dinamicamente da interface

[[ra.rdnss]]
servers  = ["fd97:f00d:cafe:3731::1"]
lifetime = 600

[dhcp.v4]
enabled     = true
range_start = "192.168.0.100"
range_end   = "192.168.0.254"
lease_time  = 86400
router      = "192.168.0.1"
dns         = ["192.168.0.1"]

[dhcp.v6]
enabled    = true
lease_time = 86400

[dns]
enabled       = true
listen        = "0.0.0.0:5300"
upstream      = "127.0.0.1:5335"   # Unbound
search_domain = "lan"
ttl           = 60

[[devices]]
mac       = "e0:d5:5e:e2:d4:89"
hostname  = "Archie"
v4_ip     = "192.168.0.2"
v6_suffix = "::1057:cafe"          # → fd97:f00d:cafe:3731::1057:cafe

[[devices]]
mac      = "aa:bb:cc:dd:ee:ff"
hostname = "Fuyu-PC"
v4_ip    = "192.168.0.3"
```

---

## Capabilities necessárias (systemd)

```ini
[Service]
AmbientCapabilities    = CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet  = CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
```

- `CAP_NET_RAW` — socket ICMPv6 raw (RA) e AF_PACKET (DHCPv4)
- `CAP_NET_ADMIN` — operações netlink, join multicast
- `CAP_NET_BIND_SERVICE` — bind em portas < 1024 (67, 547, 53)

---

## SD card e escritas

O RPi usa SD card — escritas frequentes degradam o cartão.

O `db_worker` usa debounce de 3s: durante um boot storm com dezenas de
devices aparecendo em sequência, o SQLite é escrito uma vez só ao final,
não uma vez por device. Em `Shutdown` o flush é imediato e síncrono antes
de encerrar.

Opção adicional: montar `/var/lib/lanforge/` em tmpfs e sincronizar para disco
apenas no shutdown gracioso. O WAL mode do SQLite já minimiza escritas em disco;
o tmpfs é uma camada extra para casos de carga muito alta.

---

## Roadmap

### ✅ Fase 0 — Fundação
- `state.rs`, `bus.rs`, `supervisor.rs`, `netlink.rs`, `config.rs`

### ✅ Fase 1 — RA (substitui radvd)
- `ra_service()` com RFC 4861/8106 completo
- Detecção dinâmica de GUA, `PrefixChanged` no EventBus

### ✅ Fase 2 — DHCPv4 (substitui dnsmasq DHCP v4)
- `dhcpv4_service()` com AF_PACKET, state machine completa
- Leases estáticos e dinâmicos, persistência SQLite

### ✅ Fase 3 — SLAAC tracker v2
- `process_cycle_v2()` via `ManagedTable` diretamente
- Condição de corrida do `ipv6_namer` eliminada

### ✅ Fase 4 — DHCPv6 stateful (substitui dnsmasq DHCP v6)
- `dhcpv6_service()` com IA_NA, DUID, Rapid Commit
- Sufixo ULA fixo via DUID ou MAC fallback

### ✅ Fase 4.4 — Zero-Cost Abstractions
- `MacAddr` com `From`/`AsRef`, `NeighborEvent`, `Duid` tipado
- `to_device_update()` no `NeighborEvent`

### ✅ Fase 4.5 — Master Client Manager
- `DeviceUpdate` como único canal de escrita
- `ManagedTable` como wrapper que publica no EventBus automaticamente
- `db_worker` reativo com debounce
- EventBus device-centric (`DeviceDiscovered`, `DeviceUpdated`, `DeviceExpired`)

### ✅ Fase 4.6 — DNS interno (substitui hosts file + SIGHUP)
- `dns_service()` autoritativo para a LAN
- A/AAAA/PTR a partir do `ManagedTable` diretamente
- Forward para Unbound para queries externas
- Reativo de graça — sem reload, sem arquivo intermediário

---

### 🔜 Fase 5 — Hardening e observabilidade

- `control.rs` — socket Unix JSON para `lanforge devices` / `lanforge status`
- Graceful shutdown com SIGTERM (RA anuncia `router_lifetime=0` antes de sair)
- DHCP FORCERENEW no startup para devices sem entrada no SQLite (RFC 3203, best-effort)
- Testes de integração com netns (namespace de rede isolado)

### 🔜 Fase 6 — PPPoE client (processo separado)
Processo separado que comunica estado via socket unix.
O `lanforge` detecta mudança de prefixo via netlink (`RTNLGRP_IPV6_IFADDR` em `ppp0`)
sem precisar de comunicação explícita com o cliente PPPoE.

### 🔜 Fase 7 — Webview
Interface web embutida no binário via `rust-embed` + Axum.
Consome os mesmos endpoints JSON do socket de controle via HTTP.
Task não-crítica no supervisor — falha não afeta o daemon.