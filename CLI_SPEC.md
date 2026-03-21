# lanforge CLI — Especificação

Interface de linha de comando e socket de controle para o daemon `lanforge`.

---

## Visão geral

A CLI comunica com o daemon via socket Unix JSON em `/run/lanforge/control.sock`.
Os comandos de consulta e gerenciamento funcionam sem permissões especiais.
Comandos que modificam estado requerem que o socket esteja acessível (grupo `lanforge` ou root).

```
lanforge <comando> [subcomando] [flags]
```

---

## Comandos planejados

### Consulta e monitoramento

| Comando | Descrição |
|---|---|
| `lanforge devices` | Lista todos os devices conhecidos |
| `lanforge devices --verbose` | Lista com detalhes completos (DUID, expiração, SLAAC) |
| `lanforge devices --filter <hostname\|mac\|ip>` | Filtra a listagem |
| `lanforge devices --format json` | Output JSON para scripting |
| `lanforge watch` | Live view reativo via socket (sem polling) |
| `lanforge status` | Saúde dos serviços, pool, rede, persistência |
| `lanforge log [--follow]` | EventBus interno em tempo real |

### Gerenciamento de leases

| Comando | Descrição |
|---|---|
| `lanforge lease renew <mac>` | Envia DHCP FORCERENEW (RFC 3203) para o device |
| `lanforge lease release <mac>` | Libera o lease e remove da tabela dinâmica |
| `lanforge scan` | Dispara ciclo NDP imediato com feedback |
| `lanforge export [--format json\|csv]` | Snapshot completo da tabela |

### Gerenciamento de devices customizados

| Comando | Descrição |
|---|---|
| `lanforge host add` | Prompt interativo para adicionar device |
| `lanforge host add <mac>` | Adiciona device com MAC pré-preenchido |
| `lanforge host set <mac> <campo> <valor>` | Atualiza campo específico de um device |
| `lanforge host list` | Lista devices gerenciados via CLI (não do TOML) |
| `lanforge host remove <mac>` | Remove device da tabela de runtime |

### Manutenção

| Comando | Descrição |
|---|---|
| `lanforge reload` | Envia SIGUSR1 (recarrega config estática do TOML) |
| `lanforge db vacuum` | Compacta SQLite e remove expirados |
| `lanforge shutdown` | Encerramento gracioso com flush imediato |

### Subsistemas individuais (para debug/teste)

| Comando | Descrição |
|---|---|
| `lanforge run --only ra` | Sobe apenas o serviço de RA |
| `lanforge run --only dhcpv4` | Sobe apenas o DHCPv4 |
| `lanforge run --only dhcpv6` | Sobe apenas o DHCPv6 |
| `lanforge run --only dns` | Sobe apenas o DNS |
| `lanforge run --only slaac` | Sobe apenas o tracker SLAAC |

---

## Gerenciamento de devices customizados

### Filosofia

Devices adicionados via CLI vivem numa camada intermediária entre os estáticos
do TOML (imutáveis em runtime) e os dinâmicos aprendidos pelos protocolos.
São persistidos no SQLite com uma flag `managed = true` e sobrevivem a reboots.

Três níveis de configuração possíveis, do mais simples ao mais completo:

1. **Só hostname** — associa um nome legível ao MAC. O device ainda recebe IP
   dinâmico do pool, mas resolve no DNS com o hostname configurado.

2. **Hostname + V4 fixo** — equivale a um `dhcp-host=` do dnsmasq.
   O pool reserva o IP e o DHCPv4 sempre entrega para aquele MAC.

3. **Hostname + V4 + sufixo ULA** — configuração completa, equivalente a um
   `[[devices]]` no TOML, mas adicionada em runtime sem editar arquivo.

### Prompt interativo: `lanforge host add`

```
$ lanforge host add

  Adicionar device

  MAC address: aa:bb:cc:dd:ee:ff
  Hostname:    meu-device

  Nível de configuração:
  [1] Só hostname (IP dinâmico do pool)
  [2] Hostname + IPv4 fixo
  [3] Hostname + IPv4 fixo + sufixo ULA

  Escolha [1]: 2

  IPv4 fixo: 192.168.0.50

  Confirmar?
    MAC       aa:bb:cc:dd:ee:ff
    hostname  meu-device
    V4 fixo   192.168.0.50

  [s/N]: s

  ✓ Device adicionado. Hostname resolve imediatamente em .lan
```

### Com MAC pré-preenchido: `lanforge host add <mac>`

```
$ lanforge host add aa:bb:cc:dd:ee:ff

  Adicionar device  ·  aa:bb:cc:dd:ee:ff

  ℹ  Device já visto na rede (last seen há 4 minutos, IP 192.168.0.142)

  Hostname:    solarium

  Nível de configuração:
  [1] Só hostname (IP dinâmico do pool)
  [2] Hostname + IPv4 fixo
  [3] Hostname + IPv4 fixo + sufixo ULA

  Escolha [1]: 1

  ✓ Hostname "solarium" associado a aa:bb:cc:dd:ee:ff
    Resolve imediatamente como solarium.lan → 192.168.0.142
```

### Atualização pontual: `lanforge host set`

```
$ lanforge host set aa:bb:cc:dd:ee:ff hostname novo-nome
  ✓ hostname atualizado: meu-device → novo-nome

$ lanforge host set aa:bb:cc:dd:ee:ff v4 192.168.0.55
  ✓ IPv4 fixo definido: 192.168.0.55
  ℹ  O device receberá o novo IP no próximo ciclo DHCP

$ lanforge host set aa:bb:cc:dd:ee:ff v6-suffix ::1234
  ✓ sufixo ULA definido: fd97:f00d:cafe:3731::1234
```

### Listagem: `lanforge host list`

```
$ lanforge host list

  DEVICES GERENCIADOS VIA CLI  ·  3 entries

  MAC                HOSTNAME       V4 FIXO          SUFIXO ULA       ADICIONADO
  ─────────────────────────────────────────────────────────────────────────────
  aa:bb:cc:dd:ee:ff  solarium       —                —                ontem 14:22
  11:22:33:44:55:66  impressora     192.168.0.50     —                há 3 dias
  de:ad:be:ef:00:01  nas-storage    192.168.0.20     ::dead:beef      há 1 semana

  Use "lanforge host remove <mac>" para remover.
```

### Remoção: `lanforge host remove`

```
$ lanforge host remove aa:bb:cc:dd:ee:ff

  Remover device aa:bb:cc:dd:ee:ff (solarium)?

  ℹ  O device ainda está ativo na rede (IP 192.168.0.142)
     Após remoção, continuará com IP dinâmico mas sem hostname.

  [s/N]: s

  ✓ Device removido da tabela gerenciada.
```

---

## Mockup: `lanforge devices`

```
$ lanforge devices

  DEVICES  ·  12 known  ·  10 online  ·  last scan 3s ago

  ──────────────────────────────────────────────────────────────────────────────
  HOST              MAC                V4               V6 / SLAAC
  ──────────────────────────────────────────────────────────────────────────────
  Archie      ★    e0:d5:5e:e2:d4:89  192.168.0.2      fd97::1057:cafe        ↑
                                                        2804:abcd::e2d5:5eff   ↑
              lease V4 até amanhã 08:14  ·  V6 até amanhã 08:14

  Fuyu-PC     ★    aa:bb:cc:dd:ee:ff  192.168.0.3      fd97::bbcc:ddff        ↑
              lease V4 até amanhã 14:22  ·  sem DHCPv6

  solarium    ·    3c:0a:7a:d8:11:78  192.168.0.104    fd97::3e0a:7aff        ↑
                                                        2804:abcd::3e0a:7aff   ↑
              lease V4 expira em 6h  ·  V6 expira em 6h

  PrinterHQ   ★    11:22:33:44:55:66  192.168.0.10     —
              sem lease ativo  ·  last seen há 2 dias

  impressora  ·    11:22:33:44:55:66  192.168.0.50     —
              lease V4 expira em 18h  ·  IP fixo via CLI

  host-aabb…  –    bb:aa:dd:cc:ee:ff  192.168.0.187    —
              lease V4 expira em 18h  ·  sem DHCPv6

  ──────────────────────────────────────────────────────────────────────────────
  ★ TOML estático   · gerenciado via CLI   – dinâmico   ↑ SLAAC ativo
```

---

## Mockup: `lanforge devices --verbose`

```
$ lanforge devices --verbose

  DEVICES  ·  12 known  ·  10 online  ·  last scan 3s ago

  ┌─ Archie ★ ─────────────────────────────────────────────────────────────────┐
  │  MAC        e0:d5:5e:e2:d4:89                                             │
  │  DUID       00:03:00:01:e0:d5:5e:e2:d4:89  (DUID-LL)                     │
  │  last seen  há 3 segundos                                                  │
  │  origem     TOML estático                                                  │
  │                                                                            │
  │  V4         192.168.0.2              expira 2026-03-22 08:14  (reservado) │
  │  V6         fd97::1057:cafe          expira 2026-03-22 08:14  (reservado) │
  │  SLAAC      fd97::e2d5:5eff:fee2:d489                                     │
  │             2804:abcd:1234:5678::e2d5:5eff:fee2:d489                      │
  └────────────────────────────────────────────────────────────────────────────┘

  ┌─ solarium · ───────────────────────────────────────────────────────────────┐
  │  MAC        3c:0a:7a:d8:11:78                                             │
  │  DUID       00:01:00:01:2a:4b:6c:8d:3c:0a:7a:d8:11:78  (DUID-LLT)       │
  │  last seen  há 3 segundos                                                  │
  │  origem     hostname via CLI (adicionado ontem 14:22)                     │
  │                                                                            │
  │  V4         192.168.0.104            expira em 6h (dinâmico)              │
  │  V6         fd97::3e0a:7aff:fed8:1178 expira em 6h (dinâmico)             │
  │  SLAAC      fd97::3e0a:7aff:fed8:1178                                     │
  │             2804:abcd::3e0a:7aff:fed8:1178                                │
  └────────────────────────────────────────────────────────────────────────────┘
```

---

## Mockup: `lanforge status`

```
$ lanforge status

  LANFORGE  ·  uptime 4d 12h 33m  ·  v0.5.0

  SERVIÇOS
  ─────────────────────────────────────────────────────────────────────────────
  ● RA          online    uptime 4d 12h
                          GUA  2804:abcd:1234:5678::/64  (dinâmico)
                          ULA  fd97:f00d:cafe:3731::/64
                          intervalo ~100s  ·  MTU 1492  ·  M=1 O=1

  ● DHCPv4      online    uptime 4d 12h
                          pool 192.168.0.100–254
                          12 leases ativos  ·  143 livres
                          próxima expiração em 6h  (solarium)

  ● DHCPv6      online    uptime 4d 12h
                          pool fd97::100–200
                          9 leases ativos  ·  247 livres
                          próxima expiração em 6h  (solarium)

  ● DNS         online    uptime 4d 12h
                          escutando 0.0.0.0:5300
                          upstream 127.0.0.1:5335 (Unbound)
                          domínio .lan  ·  TTL 60s

  ● SLAAC       online    uptime 4d 12h
                          24 endereços rastreados
                          último scan há 3s  ·  GUA 2804:abcd::/64

  DEVICES
  ─────────────────────────────────────────────────────────────────────────────
  12 conhecidos  ·  10 online  ·  2 estáticos sem atividade
  7 do TOML  ·  3 gerenciados via CLI  ·  2 dinâmicos puros

  PERSISTÊNCIA
  ─────────────────────────────────────────────────────────────────────────────
  SQLite   /var/lib/lanforge/leases.db  ·  148 KB
           último flush há 12s  ·  debounce 3s
           WAL mode  ·  sem erros

  REDE
  ─────────────────────────────────────────────────────────────────────────────
  LAN      end0  ·  192.168.0.1/16  ·  fd97::1/64
  WAN      ppp0  ·  CGNAT (sem IPv4 público)
           GUA   2804:abcd:1234:5678::/64  (delegado pelo ISP)
```

---

## Protocolo do socket (`/run/lanforge/control.sock`)

Socket Unix de domínio, mensagens JSON delimitadas por newline (`\n`).

### Requests

```json
{ "cmd": "devices" }
{ "cmd": "devices", "filter": "solarium" }
{ "cmd": "status" }
{ "cmd": "scan" }
{ "cmd": "reload" }
{ "cmd": "shutdown" }

{ "cmd": "host_add", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "solarium" }
{ "cmd": "host_add", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "impressora", "v4": "192.168.0.50" }
{ "cmd": "host_add", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "nas", "v4": "192.168.0.20", "v6_suffix": "::dead:beef" }

{ "cmd": "host_set", "mac": "aa:bb:cc:dd:ee:ff", "field": "hostname", "value": "novo-nome" }
{ "cmd": "host_set", "mac": "aa:bb:cc:dd:ee:ff", "field": "v4", "value": "192.168.0.55" }
{ "cmd": "host_set", "mac": "aa:bb:cc:dd:ee:ff", "field": "v6_suffix", "value": "::1234" }

{ "cmd": "host_remove", "mac": "aa:bb:cc:dd:ee:ff" }
{ "cmd": "host_list" }

{ "cmd": "lease_renew",  "mac": "aa:bb:cc:dd:ee:ff" }
{ "cmd": "lease_release","mac": "aa:bb:cc:dd:ee:ff" }
```

### Response — `devices`

```json
{
  "devices": [
    {
      "mac": "e0:d5:5e:e2:d4:89",
      "hostname": "Archie",
      "origin": "static",
      "online": true,
      "last_seen": "2026-03-21T14:32:00Z",
      "duid": "00:03:00:01:e0:d5:5e:e2:d4:89",
      "v4": { "ip": "192.168.0.2", "expires": "2026-03-22T08:14:00Z", "reserved": true },
      "v6": { "ip": "fd97::1057:cafe", "expires": "2026-03-22T08:14:00Z", "reserved": true },
      "slaac": [
        "fd97::e2d5:5eff:fee2:d489",
        "2804:abcd::e2d5:5eff:fee2:d489"
      ]
    }
  ],
  "meta": {
    "total": 12,
    "online": 10,
    "last_scan_secs_ago": 3
  }
}
```

### Response — `status`

```json
{
  "uptime_secs": 390813,
  "version": "0.5.0",
  "services": {
    "ra":     { "state": "running", "uptime_secs": 390813, "gua": "2804:abcd::/64", "ula": "fd97:f00d:cafe:3731::/64" },
    "dhcp_v4":{ "state": "running", "uptime_secs": 390813, "leases_active": 12, "pool_free": 143 },
    "dhcp_v6":{ "state": "running", "uptime_secs": 390813, "leases_active": 9,  "pool_free": 247 },
    "dns":    { "state": "running", "uptime_secs": 390813, "upstream": "127.0.0.1:5335" },
    "slaac":  { "state": "running", "uptime_secs": 390813, "addrs_tracked": 24, "last_scan_secs_ago": 3 }
  },
  "db": {
    "path": "/var/lib/lanforge/leases.db",
    "size_bytes": 151552,
    "last_flush_secs_ago": 12
  },
  "network": {
    "lan_iface": "end0",
    "wan_iface": "ppp0",
    "gua": "2804:abcd:1234:5678::/64",
    "ula": "fd97:f00d:cafe:3731::/64"
  },
  "devices": {
    "total": 12,
    "online": 10,
    "static_toml": 7,
    "managed_cli": 3,
    "dynamic": 2
  }
}
```

---

## Schema SQLite — campo adicional para devices CLI

```sql
-- Devices gerenciados via CLI têm managed = true e origin = 'cli'
-- Devices do TOML têm is_static = true e origin = 'toml'
-- Devices dinâmicos têm ambos false e origin = 'dynamic'

ALTER TABLE devices ADD COLUMN origin TEXT NOT NULL DEFAULT 'dynamic';
ALTER TABLE devices ADD COLUMN managed_at INTEGER;  -- unix timestamp da adição via CLI
```

A distinção `origin` permite que `lanforge host list` filtre apenas os entries
adicionados via CLI, e que o bootstrap saiba não sobrescrever entries do TOML
com o que veio do DB (o TOML sempre tem precedência).

---

## Notas de implementação

**Precedência de configuração em runtime:**

```
TOML estático  >  CLI gerenciado  >  dinâmico de protocolo
```

Um device adicionado via CLI com hostname `"solarium"` não sobrescreve um
`[[devices]]` do TOML que tenha o mesmo MAC — o TOML vence sempre.

**Persistência dos entries CLI:**

Entries adicionados via CLI são gravados no SQLite imediatamente (sem debounce),
pois são ações explícitas do usuário. O `db_worker` normal cobre o restante.

**`host add` com MAC já na tabela:**

Se o MAC já existe como device dinâmico, o comando eleva o entry para `managed`
sem perder o lease ativo. O hostname passa a resolver no DNS imediatamente.

Se o MAC já existe como entry do TOML, o comando recusa com erro explicativo
e sugere editar o arquivo de configuração.