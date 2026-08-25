---
name: lanforge-lab
description: Interactive lab testbed, simulation engine, and automated regression harness for Lanforge (DHCP, DNS, IPv6 RA, and Discovery). Use to test network behaviors, simulate clients, and run benchmarks without root permissions.
---

# Lanforge Lab (`lanforge-lab`)

`lanforge-lab` is the built-in laboratory workbench and simulation engine for Lanforge. It allows agents and developers to test, benchmark, and verify network services (DHCPv4, DNS, IPv6 RA, mDNS, and Discovery) without risking home network disruption or requiring root/sudo privileges for standard test runs.

## Key Capabilities

- **Rootless Direct Mode (Default):** Runs unprivileged against local test ports (`127.0.0.1:1067` for DHCP, `127.0.0.1:1053` for DNS). Zero `sudo` required.
- **Kernel Netns Mode:** Full L2/L3 isolation with Linux network namespaces and `veth` pairs when run as root (`sudo lanforge-lab --mode netns`).
- **Headless Mode (`--json`):** Returns machine-readable JSON outputs with latency metrics ($p50, p95, p99$) and standard exit codes (`0` for success, `1` for assertion failure).
- **Interactive TUI:** Full graphical terminal dashboard (`ratatui`) for manual experimentation.

---

## Agent CLI Reference (Headless Mode)

### 1. DHCP DORA Flow Simulation
Simulates a client connecting to the network (Discover $\to$ Offer $\to$ Request $\to$ Ack) and reports allocated IP, gateway, subnet mask, DNS servers, lease time, and latency:

```bash
# Run DHCP DORA with custom hostname and JSON output
cargo run --bin lanforge-lab -- run dhcp --hostname "test-device" --json

# Run DHCP DORA with strict assertion (fails with exit code 1 on error)
cargo run --bin lanforge-lab -- run dhcp --mac 02:42:ac:11:00:02 --assert-success
```

### 2. DNS Query & Adblock Testing
Sends DNS queries over UDP to verify local domain resolution, upstream resolution, or adblock blocking:

```bash
# Test local domain resolution
cargo run --bin lanforge-lab -- run dns --domain "router.lan" --json

# Test adblock domain blocking
cargo run --bin lanforge-lab -- run dns --domain "doubleclick.net" --json

# Test with strict assertion (asserts RCODE NoError)
cargo run --bin lanforge-lab -- run dns --domain "google.com" --assert-success
```

### 3. Full Regression Test Suite
Executes end-to-end tests across DHCP and DNS, outputting an aggregated JSON report:

```bash
cargo run --bin lanforge-lab -- suite --json
```

### 4. Stress Testing & Benchmarks
Measures throughput and latency percentiles under concurrent load:

```bash
# DHCP Storm (e.g. 100 concurrent clients)
cargo run --bin lanforge-lab -- bench dhcp-storm --clients 100 --concurrency 10 --json

# DNS Flood (e.g. 5,000 QPS for 3 seconds)
cargo run --bin lanforge-lab -- bench dns-flood --qps 5000 --duration 3 --json
```

---

## Programmatic Rust API (`lib.rs`)

For Rust unit and integration tests, use `lanforge_lab::harness::LabHarness` directly:

```rust
use lanforge_lab::harness::{LabHarness, LabMode};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::DnsRecordType;

#[tokio::test]
async fn test_dhcp_and_dns_pipeline() {
    // 1. Initialize harness in Direct / Unprivileged mode (no sudo needed)
    let harness = LabHarness::setup_direct().expect("Failed to initialize lab harness");
    assert_eq!(harness.mode(), LabMode::Direct);

    // 2. Simulate DHCP client DORA
    let mac = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let dhcp_res = harness.dhcp().simulate_dora(mac, Some("my-laptop")).await.unwrap();
    if dhcp_res.success {
        println!("Assigned IP: {:?}", dhcp_res.assigned_ip);
    }

    // 3. Query DNS
    let dns_res = harness.dns().query("lanforge.lan", DnsRecordType::A).await.unwrap();
    println!("DNS Status: {}, Latency: {} µs", dns_res.rcode, dns_res.latency_us);
}
```

---

## Running Automated Lab Tests

Run the test suite across the lab crate:

```bash
cargo test -p lanforge-lab
```
