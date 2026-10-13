#!/usr/bin/env bash
set -euo pipefail

# Lanforge Pull-Mode Updater Script for Gateway
# Runs on the Gateway to pull precompiled release binaries from the build workstation
# Usage:
#   sudo ./deploy/pull-update.sh <user@host>
#   sudo lanforge-update [user@host]

echo "======================================================"
echo "    Lanforge Updater (Pull Mode -> Edge Gateway)      "
echo "======================================================"

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run with root privileges (use sudo)." >&2
    exit 1
fi

# Source Lanforge environment overrides if present
if [ -f /etc/lanforge/lanforge.env ]; then
    # shellcheck disable=SC1091
    source /etc/lanforge/lanforge.env
fi

BUILD_HOST="${BUILD_HOST:-${1:-}}"
BUILD_DIR="${BUILD_DIR:-/mnt/ram/.rsbuild/release}"

if [ -z "$BUILD_HOST" ]; then
    echo "Error: Build host not configured!" >&2
    echo "Set BUILD_HOST in /etc/lanforge/lanforge.env or pass as argument:" >&2
    echo "  sudo $0 <user@build-workstation>" >&2
    exit 1
fi

echo "--> Build host:        $BUILD_HOST"
echo "--> Remote directory:  $BUILD_DIR"
echo ""

TMP_DAEMON="/tmp/lanforged.new.$$"
TMP_CLI="/tmp/lanforge.new.$$"

cleanup() {
    rm -f "$TMP_DAEMON" "$TMP_CLI"
}
trap cleanup EXIT

# 1. Download binaries via SCP to /tmp (prevents interrupting running service if download fails)
echo "--> [1/5] Downloading lanforged (daemon) binary..."
if ! scp "$BUILD_HOST:$BUILD_DIR/lanforged" "$TMP_DAEMON" 2>/dev/null; then
    ALT_DIR="${BUILD_DIR%/release}/target/release"
    echo "    Trying fallback path: $ALT_DIR/lanforged ..."
    scp "$BUILD_HOST:$ALT_DIR/lanforged" "$TMP_DAEMON"
fi

echo "--> [2/5] Downloading lanforge (CLI) binary..."
if ! scp "$BUILD_HOST:$BUILD_DIR/lanforge" "$TMP_CLI" 2>/dev/null; then
    ALT_DIR="${BUILD_DIR%/release}/target/release"
    echo "    Trying fallback path: $ALT_DIR/lanforge ..."
    scp "$BUILD_HOST:$ALT_DIR/lanforge" "$TMP_CLI"
fi

# 2. Validate downloaded binaries
if [ ! -s "$TMP_DAEMON" ] || [ ! -s "$TMP_CLI" ]; then
    echo "Error: One or more downloaded binaries are empty or missing!" >&2
    exit 1
fi

# 3. Atomic install to /usr/local/bin
echo "--> [3/5] Installing new binaries into /usr/local/bin/..."
install -m 0755 "$TMP_DAEMON" /usr/local/bin/lanforged
install -m 0755 "$TMP_CLI" /usr/local/bin/lanforge

# 4. Restore SELinux contexts to prevent AVC denials
echo "--> [4/5] Restoring SELinux contexts (restorecon)..."
restorecon -v /usr/local/bin/lanforged /usr/local/bin/lanforge 2>/dev/null || true

# 5. Restart systemd service
echo "--> [5/5] Restarting lanforge systemd service..."
systemctl restart lanforge

echo ""
echo "======================================================"
echo "    Update completed successfully!                    "
echo "======================================================"
echo ""
systemctl status lanforge --no-pager
