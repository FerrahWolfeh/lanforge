#!/usr/bin/env bash
set -euo pipefail

# Lanforge Installation and Initialization Script for Fedora Server / Linux
# Run as root or with sudo: sudo ./deploy/install.sh

echo "======================================================"
echo "    Lanforge Installer (Router & Core Daemon)         "
echo "======================================================"

if [[ $EUID -ne 0 ]]; then
    echo "Error: This installer must be run as root (use sudo)." >&2
    exit 1
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$PROJECT_ROOT/deploy"

# 1. Configure dedicated 'lanforge' system group for local UDS socket access
echo "--> [1/7] Setting up 'lanforge' system group..."
if ! getent group lanforge >/dev/null; then
    groupadd -r lanforge
    echo "    Group 'lanforge' created."
else
    echo "    Group 'lanforge' already exists."
fi

# Add sudo user to lanforge group (allows non-root CLI access)
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    usermod -aG lanforge "$SUDO_USER"
    echo "    User '$SUDO_USER' added to group 'lanforge' (CLI access without sudo)."
fi

# 2. Create standard FHS directories
echo "--> [2/7] Creating FHS directory layout (/etc/lanforge and /var/lib/lanforge)..."
mkdir -p /etc/lanforge
mkdir -p /var/lib/lanforge/tftp

chown -R root:lanforge /etc/lanforge
chmod 0755 /etc/lanforge

chown -R root:lanforge /var/lib/lanforge
chmod 0750 /var/lib/lanforge
chmod 0755 /var/lib/lanforge/tftp

# 3. Install compiled binaries if available
echo "--> [3/7] Checking for compiled binaries..."
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
if [ -d "/mnt/ram/.rsbuild" ]; then
    TARGET_DIR="/mnt/ram/.rsbuild"
fi
BIN_DIR="$TARGET_DIR/release"
if [ ! -d "$BIN_DIR" ] && [ -d "$TARGET_DIR/target/release" ]; then
    BIN_DIR="$TARGET_DIR/target/release"
fi

for bin in lanforged lanforge lanforge-lab; do
    if [ -f "$BIN_DIR/$bin" ]; then
        echo "    Installing $bin into /usr/local/bin/..."
        install -m 0755 "$BIN_DIR/$bin" "/usr/local/bin/$bin"
    elif [ -f "/usr/local/bin/$bin" ]; then
        echo "    Existing /usr/local/bin/$bin kept intact."
    else
        echo "    Warning: Binary $bin not found in $BIN_DIR."
    fi
done

# Install the quick-update script shortcut 'lanforge-update'
if [ -f "$DEPLOY_DIR/pull-update.sh" ]; then
    echo "    Installing updater shortcut into /usr/local/bin/lanforge-update..."
    install -m 0755 "$DEPLOY_DIR/pull-update.sh" /usr/local/bin/lanforge-update
fi

# 4. Copy default configuration templates if absent
echo "--> [4/7] Checking /etc/lanforge/ configuration templates..."
if [ ! -f /etc/lanforge/lanforge.toml ]; then
    echo "    Installing default /etc/lanforge/lanforge.toml..."
    cp "$DEPLOY_DIR/config/lanforge.toml" /etc/lanforge/lanforge.toml
    chown root:lanforge /etc/lanforge/lanforge.toml
    chmod 0640 /etc/lanforge/lanforge.toml
else
    echo "    Existing /etc/lanforge/lanforge.toml preserved."
fi

if [ ! -f /etc/lanforge/lanforge.env ]; then
    echo "    Installing default /etc/lanforge/lanforge.env..."
    cp "$DEPLOY_DIR/config/lanforge.env" /etc/lanforge/lanforge.env
    chown root:lanforge /etc/lanforge/lanforge.env
    chmod 0640 /etc/lanforge/lanforge.env
else
    echo "    Existing /etc/lanforge/lanforge.env preserved."
fi

# 5. Install systemd unit and sysusers
echo "--> [5/7] Installing systemd unit..."
cp "$DEPLOY_DIR/systemd/lanforge.service" /etc/systemd/system/lanforge.service
chmod 0644 /etc/systemd/system/lanforge.service

if [ -d /etc/sysusers.d ]; then
    cp "$DEPLOY_DIR/systemd/lanforge.sysusers" /etc/sysusers.d/lanforge.conf
    chmod 0644 /etc/sysusers.d/lanforge.conf
fi

systemctl daemon-reload
echo "    Systemd daemon reloaded."

# 6. Configure SELinux (if enabled)
echo "--> [6/7] Checking SELinux..."
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    bash "$DEPLOY_DIR/selinux/install-selinux.sh"
else
    echo "    SELinux is not active or not installed."
fi

echo ""
echo "======================================================"
echo "    Lanforge installation completed successfully!     "
echo "======================================================"
echo ""
echo "Recommended next steps:"
echo " 1. Review and configure your network interfaces in: /etc/lanforge/lanforge.toml"
echo " 2. Enable and start the service:"
echo "      sudo systemctl enable --now lanforge"
echo " 3. Follow live service logs:"
echo "      journalctl -u lanforge -f"
echo " 4. Inspect detailed status and watchdog health:"
echo "      systemctl status lanforge"
echo " 5. For future direct updates from the build machine, run:"
echo "      sudo lanforge-update"
echo ""
