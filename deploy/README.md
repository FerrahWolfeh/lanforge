# Guia de Implantação do Lanforge (Systemd & Edge Gateway no Fedora Server)

Este diretório contém a infraestrutura de implantação para o **Lanforge** em roteadores e gateways edge baseados em Linux (especialmente Fedora Server).

---

## 1. O Que Foi Aprimorado no Lanforge?

1. **Systemd Native Signaling (`Type=notify` via `sd-notify`)**:
   - O daemon `lanforged` utiliza o protocolo oficial do systemd.
   - Só emite `READY=1` e `Status="Operational (... services active on <iface>)"` após **todos os subsistemas internos** (DHCP, DNS, RA, DB worker, UDS, HTTP) estarem 100% iniciados e com sockets abertos.
2. **Watchdog do Systemd (`WatchdogSec=30s`)**:
   - O daemon monitora automaticamente a variável `WATCHDOG_USEC` injetada pelo systemd.
   - Mantém uma task leve em background enviando `WATCHDOG=1` a cada 15 segundos. Se a thread principal ou o reactor assíncrono travar em deadlock, o systemd reinicia o roteador automaticamente.
3. **Graceful Stopping (`STOPPING=1`)**:
   - Ao receber `SIGTERM` ou `SIGINT`, emite `STOPPING=1` e `Status="Shutting down..."`, cancelando serviços e gravando o cache de banco de dados (`redb`) com segurança antes de sair.
4. **Atualização Atômica Sem Queda da Rede**:
   - As atualizações baixam os binários para `/tmp`, realizam a substituição atômica via `install` (evitando erro de `Text file busy`) e reiniciam o daemon em ~150 milissegundos.
5. **Acesso CLI Desprivilegiado (Sem `sudo`)**:
   - O socket UDS em `/run/lanforge/control.sock` possui grupo `lanforge` (permissão `0750`). Qualquer usuário local no grupo `lanforge` pode executar `lanforge status`, `lanforge lease list`, `lanforge whois`, etc. sem necessidade de `sudo`.

---

## 2. Hierarquia de Diretórios (Padrão FHS)

| Componente | Caminho no Sistema | Permissões | Descrição |
| :--- | :--- | :--- | :--- |
| **Daemon** | `/usr/local/bin/lanforged` | `0755 root:root` | Roteador e orquestrador central (WebUI embutida). |
| **CLI / TUI** | `/usr/local/bin/lanforge` | `0755 root:root` | Ferramenta administrativa para gerência local e remota. |
| **Updater** | `/usr/local/bin/lanforge-update` | `0755 root:root` | Script de atualização atômica via pull da estação de trabalho. |
| **Configuração** | `/etc/lanforge/lanforge.toml` | `0640 root:lanforge` | Arquivo de configuração principal (WebUI na porta 8096). |
| **Ambiente** | `/etc/lanforge/lanforge.env` | `0640 root:lanforge` | Variáveis de ambiente e hosts de build. |
| **Banco Persistente** | `/var/lib/lanforge/config.redb` | `0750 root:lanforge` | Dados persistentes (usuários, hosts estáticos, rewrites). |
| **Runtime Temporário** | `/run/lanforge/control.sock` | `0750 root:lanforge` | Socket de controle UDS em `tmpfs`. |

---

## 3. Workflows de Atualização

### Modo A: PULL Direto do Mini PC (Recomendado para o dia a dia)

Estando conectado via SSH no Mini PC (gateway), basta rodar:

```bash
sudo lanforge-update user@workstation
# Ou apenas 'sudo lanforge-update' caso BUILD_HOST esteja configurado em /etc/lanforge/lanforge.env
```

O script:
1. Conecta via SCP na estação de compilação configurada;
2. Puxa os binários `lanforged` e `lanforge` gerados na pasta de release;
3. Valida a integridade dos binários;
4. Instala atomicamente em `/usr/local/bin/`;
5. Aplica `restorecon` para validação do SELinux;
6. Reinicia o serviço `systemctl restart lanforge` (downtime < 200ms);
7. Exibe o status operacional do systemd.

*Dica: Defina a estação de compilação editando `/etc/lanforge/lanforge.env` (`BUILD_HOST=usuario@host`).*

---

### Modo B: PUSH a partir da Estação de Trabalho

Estando na estação de trabalho onde você desenvolve:

```bash
# Compila lanforged e lanforge (CLI) e envia para o gateway
TARGET=user@gateway ./deploy/deploy-remote.sh

# Se alterou a WebUI e deseja recompilar o frontend antes:
TARGET=user@gateway ./deploy/deploy-remote.sh --ui

# Para compilar e enviar apenas o daemon:
TARGET=user@gateway ./deploy/deploy-remote.sh --daemon

# Para compilar e enviar apenas a CLI:
TARGET=user@gateway ./deploy/deploy-remote.sh --cli
```

---

## 4. Setup Inicial de um Novo Gateway

Para configurar uma máquina Fedora Server do zero:

```bash
# Opção 1: Via script de push da estação de trabalho
TARGET=user@gateway ./deploy/deploy-remote.sh --setup

# Opção 2: Localmente no Gateway
sudo ./deploy/install.sh
```

O instalador automático:
- Cria o grupo `lanforge`;
- Adiciona o usuário atual ao grupo `lanforge`;
- Cria os diretórios `/etc/lanforge` e `/var/lib/lanforge` com permissões adequadas;
- Instala a unit `lanforge.service` no systemd;
- Configura o SELinux (`http_port_t` na porta 8096 e fcontext FHS);
- Recarrega o systemd.

---

## 5. Operação e Monitoramento

```bash
# Iniciar / Ativar no boot
sudo systemctl enable --now lanforge

# Verificar status detalhado e watchdog
systemctl status lanforge

# Acompanhar logs em tempo real
journalctl -u lanforge -f

# Usar a CLI sem sudo (para usuários do grupo lanforge)
lanforge status
lanforge lease list
```
