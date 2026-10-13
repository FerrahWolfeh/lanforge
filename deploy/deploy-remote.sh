#!/usr/bin/env bash
set -euo pipefail

# Automated Push Deployment Script from Development Workstation to Edge Gateway
# Usage:
#   TARGET=user@gateway ./deploy/deploy-remote.sh            # Build and deploy lanforged + lanforge (CLI)
#   TARGET=user@gateway ./deploy/deploy-remote.sh --daemon   # Build and deploy lanforged daemon only
#   TARGET=user@gateway ./deploy/deploy-remote.sh --cli      # Build and deploy lanforge CLI only
#   TARGET=user@gateway ./deploy/deploy-remote.sh --ui       # Rebuild WebUI bundle before compiling daemon
#   TARGET=user@gateway ./deploy/deploy-remote.sh --setup    # Run full initial installer on gateway

TARGET="${TARGET:-${GATEWAY_HOST:-}}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -z "$TARGET" ]; then
    echo "Error: Remote target not configured!" >&2
    echo "Set TARGET in the environment or run passing the host:" >&2
    echo "  TARGET=user@gateway $0 [options]" >&2
    exit 1
fi

# Locate compiled binaries (detects RAM disk if available, or default target directory)
TARGET_DIR="${CARGO_TARGET_DIR:-$PROJECT_ROOT/target}"
if [ -d "/mnt/ram/.rsbuild" ]; then
    TARGET_DIR="/mnt/ram/.rsbuild"
fi

BIN_DIR="$TARGET_DIR/release"
if [ ! -d "$BIN_DIR" ] && [ -d "$TARGET_DIR/target/release" ]; then
    BIN_DIR="$TARGET_DIR/target/release"
fi

echo "======================================================"
echo "    Lanforge Deployment (Push) -> $TARGET"
echo "======================================================"

build_ui() {
    echo ""
    echo "==> [WebUI] Building static SvelteKit frontend bundle..."
    (cd "$PROJECT_ROOT/web" && pnpm build)
    echo "==> [WebUI] Frontend built and ready to embed."
}

build_binaries() {
    local packages=("$@")
    echo ""
    echo "==> [Build] Compiling ${packages[*]} in release mode..."
    cd "$PROJECT_ROOT"
    local build_args=("--release" "--locked")
    for pkg in "${packages[@]}"; do
        build_args+=("-p" "$pkg")
    done
    cargo build "${build_args[@]}"
}

deploy_daemon() {
    local binary="$BIN_DIR/lanforged"
    if [ ! -f "$binary" ]; then
        echo "Error: Binary not found at $binary" >&2
        exit 1
    fi

    echo "==> [Daemon] Uploading lanforged to $TARGET:/tmp/..."
    scp "$binary" "$TARGET:/tmp/lanforged.new"

    echo "==> [Daemon] Installing and restarting service on gateway..."
    ssh -t "$TARGET" "
        sudo install -m 0755 /tmp/lanforged.new /usr/local/bin/lanforged && \
        rm -f /tmp/lanforged.new && \
        sudo restorecon -v /usr/local/bin/lanforged && \
        sudo systemctl restart lanforge && \
        systemctl status lanforge --no-pager
    "
    echo "==> [Daemon] Daemon deployment completed successfully!"
}

deploy_cli() {
    local binary="$BIN_DIR/lanforge"
    if [ ! -f "$binary" ]; then
        echo "Error: Binary not found at $binary" >&2
        exit 1
    fi

    echo "==> [CLI] Uploading lanforge (CLI) to $TARGET:/tmp/..."
    scp "$binary" "$TARGET:/tmp/lanforge.new"

    echo "==> [CLI] Installing to /usr/local/bin/..."
    ssh -t "$TARGET" "
        sudo install -m 0755 /tmp/lanforge.new /usr/local/bin/lanforge && \
        rm -f /tmp/lanforge.new && \
        sudo restorecon -v /usr/local/bin/lanforge
    "
    echo "==> [CLI] CLI deployment completed successfully!"
}

deploy_all() {
    build_binaries "lanforge" "lanforge-cli"

    local bin_daemon="$BIN_DIR/lanforged"
    local bin_cli="$BIN_DIR/lanforge"

    if [ ! -f "$bin_daemon" ] || [ ! -f "$bin_cli" ]; then
        echo "Error: Binaries not found in $BIN_DIR" >&2
        exit 1
    fi

    echo "==> Uploading lanforged and lanforge (CLI) to $TARGET:/tmp/..."
    scp "$bin_daemon" "$TARGET:/tmp/lanforged.new"
    scp "$bin_cli" "$TARGET:/tmp/lanforge.new"

    echo "==> Installing binaries and restarting service on gateway..."
    ssh -t "$TARGET" "
        sudo install -m 0755 /tmp/lanforged.new /usr/local/bin/lanforged && \
        sudo install -m 0755 /tmp/lanforge.new /usr/local/bin/lanforge && \
        rm -f /tmp/lanforged.new /tmp/lanforge.new && \
        sudo restorecon -v /usr/local/bin/lanforged /usr/local/bin/lanforge && \
        sudo systemctl restart lanforge && \
        systemctl status lanforge --no-pager
    "
    echo "==> [Full] Full deployment completed successfully!"
}

deploy_setup() {
    echo ""
    echo "==> [Initial Setup] Packaging deploy/ directory..."
    local tmp_tar="/tmp/lanforge-deploy-bundle-$$.tar.gz"
    tar -czf "$tmp_tar" -C "$PROJECT_ROOT" deploy

    echo "==> [Initial Setup] Uploading to $TARGET:/tmp/..."
    scp "$tmp_tar" "$TARGET:/tmp/lanforge-deploy-bundle.tar.gz"
    rm -f "$tmp_tar"

    echo "==> [Initial Setup] Running install.sh on gateway..."
    ssh -t "$TARGET" "
        cd /tmp && \
        tar -xzf lanforge-deploy-bundle.tar.gz && \
        sudo ./deploy/install.sh && \
        rm -rf lanforge-deploy-bundle.tar.gz deploy
    "
    echo "==> [Initial Setup] Remote setup completed!"
}

ACTION="${1:---all}"

case "$ACTION" in
    --daemon|-d)
        build_binaries "lanforge"
        deploy_daemon
        ;;
    --cli|-c)
        build_binaries "lanforge-cli"
        deploy_cli
        ;;
    --ui|-u)
        build_ui
        build_binaries "lanforge" "lanforge-cli"
        deploy_all
        ;;
    --setup)
        deploy_setup
        ;;
    --all|-a)
        deploy_all
        ;;
    *)
        echo "Unknown option: $ACTION"
        echo "Usage: $0 [--all | --daemon | --cli | --ui | --setup]"
        exit 1
        ;;
esac

echo ""
echo "======================================================"
echo "    Deployment finished on $TARGET!"
echo "======================================================"
