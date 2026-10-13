# Security Policy

## Supported Versions

| Version | Supported |
|:--------|:----------|
| `main` / latest git | :white_check_mark: |

Lanforge is an actively evolving project. Security fixes and patches are applied to the `main` branch.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Lanforge, please do not disclose it publicly via GitHub Issues. Instead:

- Use **[GitHub Private Vulnerability Reporting](https://github.com/FerrahWolfeh/lanforge/security/advisories/new)** (preferred).
- Or send an encrypted or direct email to **`ferrahwolfeh@proton.me`**.

Please include:
1. A description of the vulnerability and affected subsystem (DHCP, DNS, PPPoE, Firewall, HTTP API).
2. Steps or proof-of-concept to reproduce the behavior.
3. Potential impact on the host or local network.

We appreciate responsible disclosure and will acknowledge receipt promptly.

---

## Security & Isolation Model

Lanforge operates as a network edge orchestrator with strict boundary controls:

### 1. Kernel Capabilities & Privilege Dropping
The daemon executes with bounded Linux capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`, `CAP_BPF`), dropping all other privileges. Systemd units apply strict filesystem sandboxing (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`).

### 2. Local Control Socket (UDS)
The administrative Unix Domain Socket at `/run/lanforge/control.sock` is restricted to `root:lanforge` with `0750` permissions. Sensitive operations (such as new API token generation) are locked to local socket access.

### 3. Remote HTTP & Web API
- Remote access requires valid Bearer tokens or signed JWT session cookies.
- Passwords are encrypted and hashed with **Argon2id**.
- Exported token secrets in backups are encrypted client-side using **ChaCha20-Poly1305** and Argon2 key derivation.

### 4. Firewall Ingress Policy
Interfaces assigned to the `external` zone (e.g. `ppp0`, `wan0`) operate with strict `DROP` default policies on both `input` and `forward` chains. Host container engine port mappings (Netavark/Docker) are blocked on external interfaces unless explicitly authorized via port forwarding rules or IPv6 pinholes.
