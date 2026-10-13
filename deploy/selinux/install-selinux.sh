#!/usr/bin/env bash
set -euo pipefail

# SELinux configuration script for Lanforge on Fedora Server / RHEL
# Run as root or with sudo

echo "=== SELinux Configuration for Lanforge ==="

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root (use sudo)." >&2
    exit 1
fi

if ! command -v getenforce >/dev/null 2>&1; then
    echo "SELinux not detected on this system. Nothing to do."
    exit 0
fi

SELINUX_STATUS=$(getenforce)
echo "Current SELinux status: $SELINUX_STATUS"

if [[ "$SELINUX_STATUS" == "Disabled" ]]; then
    echo "SELinux is disabled. No action needed."
    exit 0
fi

# 1. Configure network ports (Port 8088 for WebUI / HTTP API as http_port_t)
echo "--> Configuring port 8088 (WebUI / HTTP API) in SELinux..."
if command -v semanage >/dev/null 2>&1; then
    if ! semanage port -l | grep -q "http_port_t.*\<8088\>"; then
        semanage port -a -t http_port_t -p tcp 8088 2>/dev/null || \
        semanage port -m -t http_port_t -p tcp 8088 2>/dev/null || true
        echo "    Port 8088 associated with http_port_t."
    else
        echo "    Port 8088 already associated with http_port_t."
    fi

    # Network booleans for local reverse proxies (e.g. Nginx, Caddy, SWAG)
    echo "--> Verifying network booleans for reverse proxies..."
    setsebool -P httpd_can_network_connect 1 2>/dev/null || true
    setsebool -P nis_enabled 1 2>/dev/null || true

    # 2. Register standard FHS file contexts
    echo "--> Registering standard file contexts..."
    semanage fcontext -a -t bin_t "/usr/local/bin/lanforge.*" 2>/dev/null || true
    semanage fcontext -a -t etc_t "/etc/lanforge(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t var_lib_t "/var/lib/lanforge(/.*)?" 2>/dev/null || true
    semanage fcontext -a -t var_run_t "/run/lanforge(/.*)?" 2>/dev/null || true
else
    echo "Warning: 'semanage' not found. Install with: dnf install policycoreutils-python-utils"
fi

# 3. Apply contexts to existing files
echo "--> Restoring file contexts (restorecon)..."
restorecon -v /usr/local/bin/lanforged /usr/local/bin/lanforge /usr/local/bin/lanforge-lab 2>/dev/null || true
restorecon -Rv /etc/lanforge /var/lib/lanforge 2>/dev/null || true
restorecon -Rv /run/lanforge 2>/dev/null || true

echo "=== SELinux successfully configured for Lanforge! ==="
