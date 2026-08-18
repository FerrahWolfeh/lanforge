#!/usr/bin/env bash
set -euo pipefail

# Lanforge Network Namespace (netns) Development & Testing Utility
# Allows running and testing Lanforge in an isolated network sandbox on your local machine.

NETNS_NAME="lanforge-dev"
HOST_IFACE="veth-host"
LAN_IFACE="veth-lan"
HOST_IP="192.168.100.1/24"
LAN_IP="192.168.100.2/24"
HTTP_PORT="9090"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DAEMON="${ROOT_DIR}/target/debug/lanforged"
BIN_CLI="${ROOT_DIR}/target/debug/lanforge"

function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This command requires root privileges. Please run with sudo." >&2
        exit 1
    fi
}

function build_binaries() {
    echo "🔨 Building lanforge and lanforge-cli..."
    cargo build --manifest-path "${ROOT_DIR}/Cargo.toml" -p lanforge -p lanforge-cli
}

function setup_netns() {
    check_root

    echo "🌐 Setting up isolated network namespace '${NETNS_NAME}'..."

    # Teardown any existing stale interfaces/namespace
    teardown_netns 2>/dev/null || true

    # Create network namespace
    ip netns add "${NETNS_NAME}"

    # Create veth pair
    ip link add "${HOST_IFACE}" type veth peer name "${LAN_IFACE}"

    # Move LAN interface to netns
    ip link set "${LAN_IFACE}" netns "${NETNS_NAME}"

    # Assign IP and bring up host interface
    ip addr add "${HOST_IP}" dev "${HOST_IFACE}"
    ip link set "${HOST_IFACE}" up

    # Assign IP and bring up loopback and LAN interface inside netns
    ip netns exec "${NETNS_NAME}" ip link set lo up
    ip netns exec "${NETNS_NAME}" ip addr add "${LAN_IP}" dev "${LAN_IFACE}"
    ip netns exec "${NETNS_NAME}" ip link set "${LAN_IFACE}" up

    echo "✅ Network namespace ready!"
    echo "   Host link:   ${HOST_IFACE} (${HOST_IP})"
    echo "   Netns link:  ${LAN_IFACE} (${LAN_IP})"
    echo "   Web Console: http://192.168.100.2:${HTTP_PORT}"
}

function teardown_netns() {
    check_root
    echo "🧹 Tearing down network namespace '${NETNS_NAME}'..."

    if ip link show "${HOST_IFACE}" &>/dev/null; then
        ip link delete "${HOST_IFACE}" 2>/dev/null || true
    fi

    if ip netns list | grep -qw "${NETNS_NAME}"; then
        ip netns delete "${NETNS_NAME}" 2>/dev/null || true
    fi

    echo "✅ Cleaned up."
}

function run_daemon() {
    check_root

    if ! ip netns list | grep -qw "${NETNS_NAME}"; then
        setup_netns
    fi

    if [[ ! -f "${BIN_DAEMON}" ]]; then
        build_binaries
    fi

    echo "🚀 Launching Lanforge daemon in '${NETNS_NAME}'..."
    ip netns exec "${NETNS_NAME}" "${BIN_DAEMON}" --iface-lan "${LAN_IFACE}" "$@"
}

function run_cli() {
    check_root

    if ! ip netns list | grep -qw "${NETNS_NAME}"; then
        echo "Error: Network namespace '${NETNS_NAME}' is not running. Start with '$0 run' or '$0 setup'." >&2
        exit 1
    fi

    ip netns exec "${NETNS_NAME}" "${BIN_CLI}" "$@"
}

function open_shell() {
    check_root

    if ! ip netns list | grep -qw "${NETNS_NAME}"; then
        setup_netns
    fi

    echo "🐚 Entering shell inside '${NETNS_NAME}' namespace (type 'exit' to leave)..."
    ip netns exec "${NETNS_NAME}" bash
}

function test_dhcp() {
    check_root
    echo "📡 Testing DHCP client on host interface '${HOST_IFACE}' against Lanforge in netns..."

    if command -v dhclient &>/dev/null; then
        dhclient -v -r "${HOST_IFACE}" || true
        dhclient -v -1 "${HOST_IFACE}"
    elif command -v udhcpc &>/dev/null; then
        udhcpc -i "${HOST_IFACE}" -n -q
    else
        echo "Error: Neither dhclient nor udhcpc found on host." >&2
        exit 1
    fi
}

function usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  setup       Create and configure the network namespace and veth pair"
    echo "  run         Start the Lanforge daemon inside the namespace"
    echo "  cli [args]  Execute a lanforge CLI command inside the namespace (e.g. init, status)"
    echo "  shell       Open an interactive shell inside the test network namespace"
    echo "  dhcp-test   Run a DHCP client on the host veth to test lease allocation"
    echo "  clean       Tear down the namespace and delete veth interfaces"
    echo "  build       Build the debug binaries with cargo"
    echo ""
    echo "Examples:"
    echo "  sudo $0 setup"
    echo "  sudo $0 run"
    echo "  sudo $0 cli init"
    echo "  sudo $0 cli status"
    echo "  sudo $0 clean"
}

case "${1:-}" in
    setup)
        setup_netns
        ;;
    run)
        shift || true
        run_daemon "$@"
        ;;
    cli)
        shift
        run_cli "$@"
        ;;
    shell)
        open_shell
        ;;
    dhcp-test)
        test_dhcp
        ;;
    clean)
        teardown_netns
        ;;
    build)
        build_binaries
        ;;
    *)
        usage
        ;;
esac
