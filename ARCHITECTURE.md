# lanforge — Plano Arquitetural

Daemon unificado de controle de rede IPv4/IPv6 para Raspberry Pi 4B.
Substitui progressivamente: radvd, dnsmasq (DHCP), ipv6_namer.
Integra com: pihole-FTL (DNS), systemd-networkd (PPPoE/WAN), nftables.

---

## Contexto e filosofia

O programa nasceu como um tracker de SLAAC (`ipv6_namer`) e vai crescer absorvendo
serviços que hoje se comunicam via arquivos e sinais — um modelo frágil.

A decisão central é **um processo, múltiplas tasks tokio supervisionadas**.
O modelo arquitetural segue o padrão **Master Client Manager**, onde uma estrutura central (`DeviceTable`) é a única autoridade de estado e persistência, enquanto os servidores (DHCP, RA, SLAAC) atuam como **propagadores de protocolo**.

Os motivos são concretos:

- Uma única conexão netlink alimenta todos os serviços via canal interno
- A tabela de leases é estado compartilhado; IPC adicionaria complexidade sem ganho
- Rust já isola falhas por task; um panic não derruba o processo
- O PPPoE é a única exceção: processo separado, porque é o único que mata a internet se travar junto com outra coisa

---

## Visão geral do sistema

```
┌───────────────────────────────────────────────────────────────┐
│                         lanforge (processo)                   │
│                                                               │
│  ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌───────────┐  │
│  │  DHCPv4  │   │  DHCPv6   │   │    RA    │   │   SLAAC   │  │
│  │  server  │   │  server   │   │ service  │   │  tracker  │  │
│  └────┬─────┘   └─────┬─────┘   └────┬─────┘   └─────┬─────┘  │
│       │               │              │                │       │
│       └───────────────┴──────────────┴────────────────┘       │
│                               │                               │
│                    ┌──────────▼──────────┐                    │
│                    │      EventBus       │                    │
│                    │  (broadcast chan)   │                    │
│                    └──────────┬──────────┘                    │
│                               │                               │
│            ┌──────────────────┼──────────────────┐            │
│            │                  │                  │            │
│   ┌────────▼──────┐  ┌───────▼───────┐  ┌───────▼────────┐    │
│   │  LeaseTable   │  │  Netlink sub  │  │  HostsWriter   │    │
│   │ (SharedState) │  │  (1 socket)   │  │  → pihole-FTL  │    │
│   └───────────────┘  └───────────────┘  └────────────────┘    │
│                                                               │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │                   Supervisor                              ││
│  │   reinicia tasks com backoff, propaga erros fatais        ││
│  └──────────────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────┘
         ▲                                        │
         │ lê /run/lanforge/prefix (socket unix)      │ SIGHUP
         │                                        ▼
┌────────┴──────────┐                    ┌────────────────┐
│  pppoe-client     │                    │   pihole-FTL   │
│  (proc separado)  │                    │   (DNS + UI)   │
└───────────────────┘                    └────────────────┘
```

---

## Estrutura de módulos

```
lanforge/
├── Cargo.toml
├── ARCHITECTURE.md             ← este arquivo
│
└── src/
    ├── main.rs                 CLI (clap subcomandos) + bootstrap do runtime
    ├── config.rs               Configuração completa (clap + env + arquivo TOML)
    │
    ├── supervisor.rs           Loop de supervisão de tasks (reinício com backoff)
    ├── bus.rs                  EventBus + todos os tipos de eventos
    ├── state.rs                LeaseTable + tipos compartilhados (Lease, Duid, MacAddr...)
    │
    ├── hosts.rs                HostsWriter — gera arquivo de hosts e manda SIGHUP
    ├── netlink.rs              Wrapper do Handle rtnetlink; único ponto de entrada netlink
    │
    ├── ra/
    │   ├── mod.rs              ra_service() — entry point da task
    │   ├── config.rs           RaConfig, PrefixConfig, RdnssConfig, DnsslConfig
    │   └── packet.rs           build_ra_packet(), icmpv6_checksum(), helpers de socket
    │
    ├── dhcp/
    │   ├── mod.rs              Ponto de entrada; decide qual servidor subir
    │   ├── v4/
    │   │   ├── mod.rs          dhcpv4_service() — task entry point
    │   │   ├── socket.rs       AF_PACKET raw + UDP:67 (dois sockets necessários)
    │   │   ├── state_machine.rs DISCOVER→OFFER→REQUEST→ACK + RENEW/REBIND/RELEASE
    │   │   ├── pool.rs         Alocador de IPs do pool (range configurável)
    │   │   └── options.rs      Serialização/parse das opções DHCP (router, DNS, lease time...)
    │   └── v6/
    │       ├── mod.rs          dhcpv6_service() — task entry point
    │       ├── socket.rs       UDP:547, multicast ff02::1:2
    │       ├── state_machine.rs SOLICIT→ADVERTISE→REQUEST→REPLY + RENEW/REBIND/RELEASE
    │       ├── duid.rs         Parse/geração de DUID-LLT, DUID-LL, DUID-EN
    │       └── options.rs      IA_NA, IA_TA, opções DNS, informação de prefixo
    │
    ├── slaac/
    │   └── mod.rs              Tracker de endereços SLAAC via eventos netlink NDP
    │                           Resolve hostname imediatamente: config estática → lease v4
    │                           Sem hostname na config/lease → entrada omitida do hosts file
    │
    └── pppoe/                  FUTURO — cliente PPPoE (processo separado ou feature flag)
        └── mod.rs
```

---

## Tipos de dados centrais (`state.rs`)

O modelo central é um **Device** — um dispositivo físico que pode ter v4, v6
e endereços SLAAC ao mesmo tempo. Não há leases separados por família; tudo
que se sabe sobre um dispositivo fica num lugar só, indexado pelo MAC.

```rust
pub struct MacAddr([u8; 6]);

/// DUID opaco (DUID-LLT, DUID-LL ou DUID-EN).
/// Aprendido no primeiro contato DHCPv6 e associado ao MAC do dispositivo.
pub struct Duid(Vec<u8>);

/// Tudo que se sabe sobre um dispositivo na rede.
pub struct Device {
    pub mac:      MacAddr,
    pub hostname: String,

    /// true = veio da config estática; false = aprendido dinamicamente
    pub is_static: bool,

    /// DUID aprendido na primeira troca DHCPv6.
    /// None até o dispositivo fazer DHCPv6 pela primeira vez.
    pub duid: Option<Duid>,

    /// Lease IPv4 ativo, se houver.
    pub v4: Option<V4Lease>,

    /// Lease IPv6 stateful ativo, se houver.
    pub v6: Option<V6Lease>,

    /// Endereços SLAAC observados via NDP (pode haver mais de um por dispositivo).
    pub slaac: Vec<Ipv6Addr>,

    /// Última vez que o dispositivo foi visto na rede (qualquer protocolo).
    pub last_seen: SystemTime,
}

pub struct V4Lease {
    pub ip:      Ipv4Addr,
    pub expires: SystemTime,
}

pub struct V6Lease {
    pub ip:      Ipv6Addr,
    pub expires: SystemTime,
}

/// Registro de config estática — lido do config.toml no startup.
/// Define hostname e endereços fixos para um MAC conhecido.
pub struct StaticEntry {
    pub mac:      MacAddr,
    pub hostname: String,
    pub v4_ip:    Option<Ipv4Addr>,
    /// Sufixo IPv6 fixo (ex: ::1057:cafe). Entregue via DUID se disponível,
    /// senão via MAC. Ver seção "Entrega do sufixo IPv6 estático".
    pub v6_suffix: Option<Ipv6Addr>,
}

/// Tabela de dispositivos — compartilhada entre todas as tasks via Arc<RwLock<...>>
pub struct DeviceTable {
    /// Dispositivos indexados por MAC.
    devices: HashMap<MacAddr, Device>,

    /// Índice secundário: DUID → MAC. Populado quando o dispositivo faz DHCPv6.
    /// Permite lookup rápido sem varrer todos os dispositivos.
    duid_index: HashMap<Duid, MacAddr>,

    /// Config estática carregada do config.toml. Imutável em runtime.
    static_entries: HashMap<MacAddr, StaticEntry>,
}

impl DeviceTable {
    /// Retorna o Device para um MAC, criando uma entrada vazia se necessário.
    pub fn get_or_insert(&mut self, mac: MacAddr) -> &mut Device;

    /// Lookup por DUID — usado pelo servidor DHCPv6 para identificar o dispositivo.
    pub fn find_by_duid(&self, duid: &Duid) -> Option<&Device>;

    /// Hostname efetivo para um MAC.
    /// Ordem: config estática → hostname dinâmico aprendido → None.
    pub fn hostname_for(&self, mac: &MacAddr) -> Option<&str>;

    /// Sufixo IPv6 estático para um dispositivo, se configurado.
    /// Ver seção "Entrega do sufixo IPv6 estático" para lógica de entrega.
    pub fn v6_suffix_for(&self, mac: &MacAddr) -> Option<Ipv6Addr>;

    /// Remove leases expirados. Dispositivos sem nenhum lease/SLAAC mas
    /// com entrada estática são mantidos (para resolver hostname imediatamente
    /// quando reaparecerem). Dispositivos dinâmicos sem atividade há >7 dias
    /// são removidos.
    pub fn expire_stale(&mut self) -> bool;

    pub fn save(&self, path: &Path) -> Result<()>;
    pub fn load(path: &Path) -> Result<Self>;
}
```

### Schema SQLite

Uma tabela por conceito, sem duplicar o hostname em cada lease:

```sql
-- Dispositivo físico — uma linha por MAC
CREATE TABLE devices (
    mac         TEXT PRIMARY KEY,       -- "aa:bb:cc:dd:ee:ff"
    hostname    TEXT NOT NULL,
    is_static   INTEGER NOT NULL,       -- 0/1
    duid        BLOB,                   -- NULL até primeiro DHCPv6
    last_seen   INTEGER NOT NULL        -- unix timestamp
);

-- Lease IPv4 — 0 ou 1 por dispositivo
CREATE TABLE v4_leases (
    mac         TEXT PRIMARY KEY REFERENCES devices(mac),
    ip          TEXT NOT NULL,
    expires     INTEGER NOT NULL
);

-- Lease IPv6 stateful — 0 ou 1 por dispositivo
CREATE TABLE v6_leases (
    mac         TEXT PRIMARY KEY REFERENCES devices(mac),
    ip          TEXT NOT NULL,
    expires     INTEGER NOT NULL
);

-- Endereços SLAAC — 0..N por dispositivo
CREATE TABLE slaac_addrs (
    mac         TEXT NOT NULL REFERENCES devices(mac),
    ip          TEXT NOT NULL,
    PRIMARY KEY (mac, ip)
);

-- Config estática — carregada do TOML mas espelhada aqui para
-- estar disponível antes do TOML ser lido (ex: startup de emergência)
CREATE TABLE static_entries (
    mac         TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    v4_ip       TEXT,
    v6_suffix   TEXT                    -- ex: "::1057:cafe"
);
```

### Entrega do sufixo IPv6 estático

Dispositivos com sufixo fixo configurado (equivalente ao `[::1057:cafe]` do dnsmasq)
recebem o endereço completo pelo servidor DHCPv6. A ordem de tentativa é:

```
1. DUID disponível na DeviceTable?
   → entrega via IA_NA com o DUID como chave de identidade
   → mais confiável: persiste mesmo se o MAC mudar (ex: troca de placa de rede)

2. DUID não disponível (primeiro contato DHCPv6 ou dispositivo nunca fez v6)?
   → entrega via MAC extraído da opção Client Link-Layer Address (opt 79)
     ou cruzado com a tabela NDP do netlink (MAC → IP link-local → DUID)
   → associa o DUID aprendido nesta troca ao dispositivo para uso futuro

3. Nem DUID nem MAC identificável?
   → aloca endereço dinâmico do pool, sem sufixo fixo
```

Na prática, após o primeiro DHCPv6 bem-sucedido o DUID está gravado e todas
as trocas seguintes usam o caminho 1. O caminho 2 é só para o primeiro contato.

---

## EventBus (`bus.rs`)

O barramento interno substitui a comunicação por arquivo/sinal entre serviços.
Usa `tokio::sync::broadcast` — múltiplos consumidores, produtor único por tipo de evento.

```rust
#[derive(Clone, Debug)]
pub enum lanforgeEvent {
    // Gerados pelo tracker netlink
    NeighbourUp   { mac: MacAddr, ip: IpAddr, iface: u32 },
    NeighbourDown { mac: MacAddr, ip: IpAddr },
    SlaacSeen     { mac: MacAddr, ip: Ipv6Addr },  // novo endereço SLAAC detectado
    PrefixChanged { gua: Option<Ipv6Addr> },

    // Gerados pelos servers DHCP
    LeaseGranted  { mac: MacAddr, ip: IpAddr, hostname: String },
    LeaseReleased { mac: MacAddr, ip: IpAddr },
    LeaseExpired  { mac: MacAddr, ip: IpAddr },
    DuidLearned   { mac: MacAddr, duid: Duid },    // primeiro DHCPv6 do dispositivo

    // Controle interno
    ReloadConfig,
    DeviceTableDirty,    // aciona HostsWriter (renomeado de HostsFileDirty)
}

pub struct EventBus {
    tx: broadcast::Sender<lanforgeEvent>,
}

impl EventBus {
    pub fn subscribe(&self) -> broadcast::Receiver<lanforgeEvent>;
    pub fn publish(&self, event: lanforgeEvent);
}
```

Cada serviço recebe um `Receiver` no startup e publica no `Sender` compartilhado.
O `HostsWriter` é simplesmente um consumidor que age em `LeaseGranted/Released/Expired`.

---

## Supervisor (`supervisor.rs`)

Política de reinício por serviço: backoff exponencial com jitter, número máximo de
tentativas configurável, distinção entre erro recuperável e fatal.

```rust
pub struct ServiceSpec {
    pub name:         &'static str,
    pub critical:     bool,      // se true e falhar definitivamente, mata o processo
    pub max_retries:  u32,       // None = infinito
    pub base_backoff: Duration,
    pub max_backoff:  Duration,
    pub factory:      Box<dyn Fn() -> JoinHandle<Result<()>> + Send>,
}
```

Um serviço `critical = true` (ex: acesso ao socket netlink) que falha definitivamente
gera `std::process::exit(1)` — o systemd reinicia o processo completo.
Um serviço não-crítico (ex: RA) que falha fica em backoff sem afetar os demais.

---

## CLI e modos de operação (`main.rs`)

```
lanforge run         # modo principal — sobe todos os serviços habilitados em config
lanforge ra          # só o serviço de RA (debug/teste isolado)
lanforge dhcp        # só os servers DHCP
lanforge reload      # envia SIGUSR1 para o daemon em execução
lanforge devices     # lista dispositivos conhecidos (v4, v6, SLAAC, last seen)
lanforge devices -v  # inclui DUID e detalhes de cada lease
lanforge status      # saúde dos serviços (RA, DHCPv4, DHCPv6, tracker)
```

`argv[0]` também funciona como dispatch se o binário for linkado como `lanforge-ra` etc.

### Protocolo do socket de controle (`/run/lanforge/control.sock`)

Socket unix de domínio, orientado a mensagens, protocolo JSON simples.
Os subcomandos de consulta (`devices`, `status`) são clientes deste socket —
podem ser usados por qualquer processo externo sem precisar de permissões especiais.

**Request:**
```json
{ "cmd": "devices" }
{ "cmd": "devices", "filter": { "hostname": "Archie" } }
{ "cmd": "status" }
{ "cmd": "reload" }
```

**Response — `devices`:**
```json
{
  "devices": [
    {
      "mac": "e0:d5:5e:e2:d4:89",
      "hostname": "Archie",
      "is_static": true,
      "last_seen": "2025-03-17T14:32:00Z",
      "v4": { "ip": "192.168.0.2", "expires": "2025-03-18T14:32:00Z" },
      "v6": { "ip": "fd97:f00d:cafe:3731::1057:cafe", "expires": "2025-03-18T14:32:00Z" },
      "slaac": [
        "fd97:f00d:cafe:3731::e2d5:5eff:fee2:d489",
        "2a01:xxx:yyy:zzz::e2d5:5eff:fee2:d489"
      ]
    }
  ]
}
```

**Response — `status`:**
```json
{
  "services": {
    "ra":     { "state": "running", "uptime_secs": 3600 },
    "dhcp_v4": { "state": "running", "leases_active": 12 },
    "dhcp_v6": { "state": "running", "leases_active": 8 },
    "slaac":   { "state": "running", "addrs_tracked": 24 }
  }
}

---

## Configuração (`config.rs`)

Três camadas em ordem crescente de precedência:

1. Valores default hardcoded no código
2. Arquivo TOML (path via `--config` ou env `lanforge_CONFIG`, default `/etc/lanforge/lanforge.toml`)
3. Variáveis de ambiente (`lanforge_RA_IFACE`, `lanforge_DHCP_RANGE` etc.)

```toml
[general]
iface_lan = "end0"
iface_wan = "ppp0"
hosts_file = "/mnt/ram/dnsmasq/ipv6_slaac_hosts"
leases_db  = "/var/lib/lanforge/leases.db"
dns_reload_cmd = "pkill -HUP pihole-FTL"

[ra]
enabled          = true
managed          = true
other_config     = true
max_interval     = 100
router_lifetime  = 1800
mtu              = 1492       # PPPoE — anuncia MTU correto para clientes

[[ra.prefix]]
source           = "ula"
address          = "fd97:f00d:cafe:3731::"

[[ra.prefix]]
source           = "auto_gua"   # detecta da interface

[[ra.rdnss]]
servers          = ["fd97:f00d:cafe:3731::1"]
lifetime         = 600

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

# Dispositivos estáticos — um bloco por dispositivo físico, ambas as stacks juntas.
# v4_ip e v6_suffix são opcionais: omitir significa sem reserva naquela família.
# v6_suffix é o sufixo host (/128) que compõe o ULA completo com o prefixo configurado.
[[devices]]
mac        = "e0:d5:5e:e2:d4:89"
hostname   = "Archie"
v4_ip      = "192.168.0.2"
v6_suffix  = "::1057:cafe"       # → fd97:f00d:cafe:3731::1057:cafe

[[devices]]
mac        = "aa:bb:cc:dd:ee:ff"
hostname   = "Fuyu-PC"
v4_ip      = "192.168.0.3"
# sem v6_suffix: recebe endereço dinâmico do pool DHCPv6

[[devices]]
mac        = "11:22:33:44:55:66"
hostname   = "PrinterHQ"
v4_ip      = "192.168.0.10"
# dispositivos que nunca fazem DHCPv6 não precisam de v6_suffix
```

---

## Integração com PPPoE (processo separado)

O cliente PPPoE vai rodar como processo independente e comunicar estado via um
socket unix simples em `/run/lanforge/pppoe.sock` ou um arquivo em `/run/lanforge/prefix`.
O `lanforge` observa esse arquivo/socket e publica `PrefixChanged` no EventBus quando
o GUA muda — o serviço de RA reage automaticamente sem precisar de restart.

Alternativamente, o netlink já notifica mudanças de endereço na interface `ppp0`
via `RTNLGRP_IPV6_IFADDR` — o `lanforge` pode detectar a mudança de prefixo diretamente
sem nenhuma comunicação explícita com o cliente PPPoE.

---

## Integração com pihole-FTL

O pihole-FTL hoje usa o dnsmasq como upstream local para resolver hostnames da LAN.
Com o dnsmasq saindo, a integração muda ligeiramente mas continua simples:
**o pihole passa a ler o arquivo de hosts diretamente**, o que ele já suporta nativamente
via `addn-hosts` na config do pihole-FTL — nenhum código novo necessário.

O `lanforge` continua sendo responsável por escrever esse arquivo e mandar SIGHUP.
O arquivo é gerado a partir da `DeviceTable` numa única passagem — um dispositivo,
todos os seus endereços, sem iterar estruturas separadas:

```rust
// hosts.rs
pub fn write_hosts_file(table: &DeviceTable, path: &Path) -> Result<bool> {
    let mut lines = BTreeSet::new(); // BTree para output determinístico

    for device in table.devices.values() {
        let Some(hostname) = table.hostname_for(&device.mac) else { continue };

        if let Some(v4) = &device.v4 {
            lines.insert(format!("{} {}", v4.ip, hostname));
        }
        if let Some(v6) = &device.v6 {
            lines.insert(format!("{} {}", v6.ip, hostname));
        }
        for addr in &device.slaac {
            lines.insert(format!("{} {}-slaac", addr, hostname));
        }
    }
    // diff contra conteúdo anterior, write se mudou, retorna true se escreveu
}
```

Não há servidor DNS dentro do `lanforge`. O pihole-FTL continua sendo o único
resolvedor DNS da rede — o `lanforge` apenas alimenta os dados que ele precisa.

---

## Dependências (`Cargo.toml`)

```toml
[dependencies]
# Async runtime
tokio      = { version = "1", features = ["full"] }
futures    = "0.3"

# CLI e config
clap       = { version = "4", features = ["derive", "env"] }
toml       = "0.8"
serde      = { version = "1", features = ["derive"] }

# Networking
rtnetlink  = "0.14"
netlink-packet-route = "0.19"
netlink-packet-core  = "0.7"
netlink-sys          = "0.8"
socket2    = { version = "0.5", features = ["all"] }
libc       = "0.2"

# DHCP parsing
dhcproto   = "0.11"

# RNG (usa hardware RNG do BCM2711 via getrandom)
rand       = "0.8"

# Persistência de leases
rusqlite   = { version = "0.31", features = ["bundled"] }
# alternativa mais leve se quiser evitar SQLite:
# bincode  = "1"

# Observabilidade
tracing              = "0.1"
tracing-subscriber   = { version = "0.3", features = ["env-filter"] }
anyhow               = "1"
```

---

## Roadmap de implementação

Cada fase pode ir para produção de forma independente, substituindo um serviço de cada vez.

### Fase 0 — Fundação (sem user-facing features novas)
Refatora o código atual sem mudar comportamento.

- Extrai `state.rs` com `LeaseTable` e tipos básicos
- Extrai `bus.rs` com `EventBus`
- Implementa `supervisor.rs` básico (reinício com backoff)
- Move o loop netlink para `netlink.rs`
- Passa o tracker SLAAC existente a usar `EventBus` em vez de polling direto
- Adiciona `config.rs` com suporte a TOML (mantendo compatibilidade com as env vars atuais)

Resultado: comportamento idêntico ao atual, mas com fundação para crescer.

### Fase 1 — RA (substitui radvd)
Integra o `ra/` já desenvolvido usando a nova fundação.

- `ra_service()` publica `PrefixChanged` quando detecta mudança de GUA
- SLAAC tracker consome `PrefixChanged` para atualizar prefix watchlist
- Remove dependência do radvd

### Fase 2 — DHCPv4 (substitui dnsmasq DHCP)
A fase mais trabalhosa por causa do socket `AF_PACKET`.

- Implementa `dhcp/v4/` com state machine completa
- Leases estáticos lidos de `config.toml` (equivalente dos `dhcp-host=`)
- Leases dinâmicos gravados em `LeaseTable` com persistência SQLite
- `LeaseGranted` dispara `HostsFileDirty` → atualiza pihole
- Testa em paralelo com dnsmasq antes de desligar

### Fase 3 — SLAAC tracker v2 (sem arquivo externo)
Com DHCPv4 dentro do processo, o tracker simplifica bastante e a condição de
corrida do modelo atual desaparece.

**A condição de corrida atual**: o `ipv6_namer` só consegue nomear um endereço
SLAAC depois que o lease DHCPv4 correspondente está no arquivo `dnsmasq.leases`.
Se um dispositivo aparece na rede (evento NDP) antes de renovar o lease DHCP
— comum após reboot do `lanforge` ou do dnsmasq — o endereço fica sem hostname
até o próximo ciclo DHCP, que pode demorar horas.

**A correção**: com a config estática dentro do processo, `hostname_for_mac()`
resolve no momento do evento NDP, independente do estado do lease DHCP.

- Remove leitura do `dnsmasq.leases` — usa `DeviceTable` diretamente
- Remove leitura do `dnsmasq-dhcp.conf` — usa config estática do `config.toml`
- SLAAC hostname resolvido na ordem: config estática → lease v4 ativo → omitido
- Remove dependência do dnsmasq completamente
- Muda config do pihole-FTL para `addn-hosts` apontando para o hosts file do `lanforge`

### Fase 4 — DHCPv6 stateful (substitui dnsmasq DHCPv6)
Com v4 estável, adiciona o server v6.

- Implementa `dhcp/v6/` com IA_NA
- Entrega de sufixo fixo via DUID (primário) ou MAC (fallback primeiro contato)
- DUID aprendido gravado na `DeviceTable` via evento `DuidLearned`
- Leases estáticos ULA (os `[::xxx]` que estão hoje no dnsmasq)

### Fase 4.4 — Abstrações de Zero Custo
Refatoração de código "raw" para estruturas de dados seguras e expressivas.

- Encapsula construção de pacotes RA e DHCP Raw em Builders/Structs.
- Transforma eventos Netlink e NDP em objetos com semântica rica.
- Substitui manipulação direta de offsets por tipos Newtype e traits.
- Objetivo: Simplificar a lógica antes da grande mudança de estado da 4.5.

### Fase 4.5 — Refatoração Master Client Manager
Desacopla a lógica de pacotes da gestão de estado.

- `DeviceTable` assume o papel de Master Manager (autoridade única).
- DHCPv4/v6 retornam `DeviceUpdate` em vez de manipular a tabela diretamente.
- Centralização da lógica de persistência e eventos no Manager.
- Base para o futuro resolvedor DNS dinâmico e CLI.

### Fase 5 — Hardening e observabilidade
Antes de declarar produção estável.

- `lanforge devices` e `lanforge status` funcionais via socket de controle
- Graceful shutdown com SIGTERM (RA com `router_lifetime=0` antes de sair)
- Renovação de lease sem interrupção para clientes ativos
- DHCP FORCERENEW no startup para dispositivos sem entrada no SQLite (opcional)
- Testes de integração com netns (namespace de rede isolado)

### Fase 6 — PPPoE client (futuro, separado)
Processo separado que herda a interface com o `lanforge` via socket unix.
Escopo separado — não bloqueia nenhuma das fases anteriores.

### Fase 7 — Webview (pós backend completo)
Interface web local embutida no binário, servida por uma task Axum no mesmo
runtime tokio. Sem processo separado, sem arquivos externos — o HTML/JS é
compilado dentro do binário via `rust-embed`.

Depende do backend completo (Fases 1–5) e da CLI estar funcional, pois a
webview consome os mesmos endpoints JSON do socket de controle, só via HTTP.

- Task HTTP (`axum`) adicionada ao supervisor, não-crítica (falha não afeta o daemon)
- Endpoints espelham o protocolo do socket: `GET /api/devices`, `GET /api/status`
- UI estática compilada no binário: zero dependência de arquivos em disco
- Porta configurável, bind em `127.0.0.1` por padrão (sem exposição na LAN sem config explícita)
- Autenticação fora do escopo inicial — acesso local via SSH tunnel se necessário

---

## Notas de operação

### Capabilities necessárias (systemd unit)

```ini
[Service]
AmbientCapabilities = CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet = CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
```

`CAP_NET_RAW` — socket ICMPv6 raw (RA) e AF_PACKET (DHCPv4)
`CAP_NET_ADMIN` — operações netlink, join multicast
`CAP_NET_BIND_SERVICE` — bind em portas < 1024 (DHCP porta 67/547)

### Persistência entre reinícios e resolução de hostnames

A condição de corrida do modelo atual tem duas variantes que têm soluções diferentes.

**Caso 1: dispositivo já conhecido, lanforge reiniciou**

O dispositivo está na rede com endereço ativo, mas o `lanforge` perdeu o estado no
reboot e não sabe mais quem ele é. É o caso mais comum e o mais fácil de resolver.

A solução é o SQLite carregado no startup antes de qualquer coisa:

```
lanforge sobe
→ carrega LeaseTable do SQLite
→ query NDP (já feito hoje em process_cycle)
→ cruza MAC dos vizinhos com a tabela em memória
→ hosts file escrito imediatamente com hostnames corretos
→ pihole-FTL recebe SIGHUP
```

Sem esperar nenhum evento de rede. O dispositivo aparece com hostname na
mesma passagem inicial que o código atual já executa — só que agora com a
tabela populada de antemão em vez de vazia.

**Caso 2: dispositivo desconhecido, nunca fez DHCP com o lanforge**

O SQLite não ajuda aqui — o dispositivo genuinamente nunca foi visto. Para este
caso existe o **DHCP FORCERENEW** (RFC 3203): o servidor envia um pacote unicast
para o cliente sinalizando que ele deve renovar o lease imediatamente. O cliente
responde com um REQUEST normal e o ciclo completo acontece em segundos.

O fluxo no startup ficaria:

```
carrega SQLite
→ query NDP
→ para cada MAC sem entrada no SQLite mas com IP conhecido via NDP
  → envia DHCP FORCERENEW para aquele IP
→ cliente responde com REQUEST em ~segundos
→ lease gravado, hostname resolvido, hosts file atualizado
```

Ressalva prática: FORCERENEW suporta autenticação opcional (RFC 3118) que
praticamente nenhum cliente implementa. Na prática funciona com a maioria dos
dispositivos, mas alguns podem ignorar pacotes não autenticados. Não é uma
garantia, é uma melhoria de best-effort.

**Recomendação de implementação**: começar apenas com o SQLite (Caso 1). Ele
resolve a esmagadora maioria dos reboots reais porque os dispositivos da rede
já foram vistos antes. O FORCERENEW (Caso 2) pode ser adicionado na Fase 5
de hardening se os testes mostrarem que o Caso 1 deixa lacunas relevantes.

**Mecanismo de flush para o SD card**: leases são escritos no SQLite com debounce
de 5s após cada mudança. O arquivo SQLite fica em tmpfs (`/run/lanforge/leases.db`)
e é sincronizado para disco (`/var/lib/lanforge/leases.db`) apenas em shutdown gracioso
via SIGTERM + a cada 10 minutos via timer interno. No startup, o `lanforge` copia o
arquivo de disco para tmpfs antes de abrir a conexão SQLite.

### SD card e escritas

O RPi usa SD card. Escritas frequentes degradam o cartão.
Mitigação: montar `/var/lib/lanforge/` em tmpfs e fazer sync para disco apenas em
shutdown gracioso + a cada N minutos. O arquivo de hosts já vai para `/mnt/ram/`
(tmpfs), o que está correto.
