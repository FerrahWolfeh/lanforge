# Lanforge Deployment Guide (Systemd & Linux Edge Gateways)

This directory contains production deployment configurations, scripts, and systemd units for deploying **Lanforge** on Linux edge gateways and SBC routers (e.g. Fedora Server, Debian/Ubuntu, Arch Linux ARM).

---

## 1. Systemd Integration & Architecture

1. **Native Systemd Signaling (`Type=notify`)**:
   - The `lanforged` daemon integrates directly with `sd-notify`.
   - Emits `READY=1` and status metrics only after **all internal subsystems** (DHCP, DNS, RA, DB worker, UDS, HTTP) have successfully initialized and bound their respective sockets.
2. **Systemd Watchdog Supervision (`WatchdogSec=30s`)**:
   - The daemon automatically detects `WATCHDOG_USEC` injected by systemd.
   - A dedicated heartbeat worker emits `WATCHDOG=1` every 15 seconds. If the async runtime or main thread encounters a deadlock, systemd restarts the daemon automatically.
3. **Graceful Teardown (`STOPPING=1`)**:
   - Upon receiving `SIGTERM` or `SIGINT`, the daemon signals `STOPPING=1`, cooperatively shuts down active services, commits persistent state to `redb`, and terminates cleanly.
4. **Atomic In-Place Binaries Replacement**:
   - Update scripts download release binaries to `/tmp` and perform atomic installations via `install -Dm755` (preventing `Text file busy` errors) with near-instantaneous service restarts (< 200ms).
5. **Unprivileged CLI Administration**:
   - The UDS control socket at `/run/lanforge/control.sock` is owned by group `lanforge` with permissions `0750`. Local users in the `lanforge` group can execute `lanforge status`, `lanforge dhcp leases`, `lanforge devices`, etc. without requiring `sudo`.

---

## 2. Directory Hierarchy (FHS Compliance)

| Component | Filesystem Path | Permissions | Description |
|:----------|:----------------|:------------|:------------|
| **Daemon** | `/usr/local/bin/lanforged` | `0755 root:root` | Core router and orchestration daemon. |
| **CLI Client** | `/usr/local/bin/lanforge` | `0755 root:root` | Command-line management client. |
| **Updater** | `/usr/local/bin/lanforge-update` | `0755 root:root` | Script for atomic workstation pull updates. |
| **Configuration** | `/etc/lanforge/lanforge.toml` | `0640 root:lanforge` | Primary configuration file (default HTTP port 8088). |
| **Environment** | `/etc/lanforge/lanforge.env` | `0640 root:lanforge` | Environment variables and build station configuration. |
| **Persistent DB** | `/var/lib/lanforge/config.redb` | `0750 root:lanforge` | Persistent state storage (users, static hosts, DNS rules). |
| **Runtime Socket** | `/run/lanforge/control.sock` | `0750 root:lanforge` | Local UDS control socket in `tmpfs`. |

---

## 3. Remote Deployment Workflows

### Mode A: Direct PULL from the Gateway (Recommended)

From an SSH session on the gateway router:

```bash
sudo lanforge-update user@workstation
# Or bare 'sudo lanforge-update' if BUILD_HOST is set in /etc/lanforge/lanforge.env
```

The updater script:
1. Connects via SCP to the designated workstation build directory.
2. Retrieves newly compiled `lanforged` and `lanforge` release binaries.
3. Validates binary integrity.
4. Installs binaries atomically to `/usr/local/bin/`.
5. Restores SELinux labels (`restorecon`).
6. Restarts the service with minimal downtime (`systemctl restart lanforge`).

### Mode B: Direct PUSH from Workstation

From your local development machine:

```bash
# Build and deploy both daemon and CLI to the gateway
TARGET=user@gateway ./deploy/deploy-remote.sh

# Recompile WebUI static bundle prior to deployment
TARGET=user@gateway ./deploy/deploy-remote.sh --ui

# Deploy only the daemon binary
TARGET=user@gateway ./deploy/deploy-remote.sh --daemon

# Deploy only the CLI binary
TARGET=user@gateway ./deploy/deploy-remote.sh --cli
```

---

## 4. Initial Gateway Setup

To bootstrap a clean Linux machine from scratch:

```bash
# Option 1: Remote push from development workstation
TARGET=user@gateway ./deploy/deploy-remote.sh --setup

# Option 2: Locally on the gateway machine
sudo ./deploy/install.sh
```

The automated installer:
- Creates the system `lanforge` group.
- Adds the current user to the `lanforge` group.
- Creates `/etc/lanforge` and `/var/lib/lanforge` directories with secure permissions.
- Installs the systemd unit `lanforge.service`.
- Configures SELinux network policies and FHS contexts.
- Reloads the systemd daemon.

---

## 5. Operations & Monitoring

```bash
# Enable and start service on boot
sudo systemctl enable --now lanforge

# Inspect service status and watchdog health
systemctl status lanforge

# Follow system logs in real-time
journalctl -u lanforge -f

# Run unprivileged CLI commands (for users in the lanforge group)
lanforge status
lanforge dhcp leases
lanforge devices --online
```
