use std::time::Duration;

use colored::Colorize;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dns::DnsRecordType;

use crate::cli::args::{BenchArgs, BenchTypeArg, ModeArg, RunArgs, ScenarioArg, SuiteArgs};
use crate::error::LabError;
use crate::harness::LabHarness;
use crate::netns::NetnsConfig;

pub struct CliRunner;

impl CliRunner {
    pub async fn run_scenario(
        args: RunArgs,
        mode: ModeArg,
        dhcp_server: std::net::SocketAddr,
        dns_server: std::net::SocketAddr,
        iface: Option<String>,
    ) -> Result<(), LabError> {
        let harness = Self::init_harness(mode, dhcp_server, dns_server, iface.as_deref())?;

        match args.scenario {
            ScenarioArg::Dhcp => {
                let mac = args
                    .mac
                    .as_deref()
                    .and_then(MacAddr::parse)
                    .unwrap_or(MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]));

                let res = harness
                    .dhcp()
                    .simulate_dora(mac, args.hostname.as_deref())
                    .await?;

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&res)?);
                } else {
                    println!("\n{}", "=== DHCP DORA Result ===".bold().cyan());
                    println!("Client MAC:        {}", res.client_mac);
                    println!("Hostname:          {:?}", res.hostname);
                    println!("Success:           {}", if res.success { "YES".green() } else { "NO".red() });
                    println!("Assigned IP:       {:?}", res.assigned_ip);
                    println!("Subnet Mask:       {:?}", res.subnet_mask);
                    println!("Router:            {:?}", res.router);
                    println!("DNS Servers:       {:?}", res.dns_servers);
                    println!("Lease Time:        {:?}s", res.lease_time_secs);
                    println!("Discover -> Offer: {:.2} ms", res.discover_to_offer_ms);
                    println!("Request  -> Ack:   {:.2} ms", res.request_to_ack_ms);
                    println!("Total Duration:    {:.2} ms", res.total_time_ms);
                    if let Some(err) = &res.error {
                        println!("Error Detail:      {}", err.red());
                    }
                }

                if args.assert_success && !res.success {
                    return Err(LabError::Assertion("DHCP DORA flow failed".to_string()));
                }
            }
            ScenarioArg::Dns => {
                let res = harness.dns().query(&args.domain, DnsRecordType::A).await?;

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&res)?);
                } else {
                    println!("\n{}", "=== DNS Query Result ===".bold().cyan());
                    println!("Domain:     {}", res.query_domain);
                    println!("Type:       {}", res.query_type);
                    println!("RCODE:      {}", res.rcode.yellow());
                    println!("Latency:    {} µs ({:.2} ms)", res.latency_us, res.latency_us as f64 / 1000.0);
                    println!("Blocked:    {}", if res.is_blocked { "YES (Adblock Hit)".red() } else { "NO".green() });
                    println!("Answers:    {:?}", res.answers);
                }

                if args.assert_success && res.rcode != "NoError" {
                    return Err(LabError::Assertion(format!("DNS query failed with RCODE {}", res.rcode)));
                }
            }
            ScenarioArg::Ra => {
                let res = harness.ra().send_rs_and_await_ra().await?;

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&res)?);
                } else {
                    println!("\n{}", "=== Router Advertisement (RA) Result ===".bold().cyan());
                    println!("Router IP:         {}", res.router_ip);
                    println!("Hop Limit:         {}", res.cur_hop_limit);
                    println!("Managed (M):       {}", res.managed_flag);
                    println!("Other Config (O):  {}", res.other_config_flag);
                    println!("Router Lifetime:   {}s", res.router_lifetime_secs);
                    println!("Latency:           {:.2} ms", res.latency_ms);
                    println!("Prefixes:          {} found", res.prefixes.len());
                    for p in &res.prefixes {
                        println!("  • {}/{} (On-Link: {}, Auto: {}, Valid: {}s)", p.prefix, p.prefix_len, p.on_link, p.auto_config, p.valid_lifetime_secs);
                    }
                    println!("RDNSS Servers:     {:?}", res.rdnss_servers);
                    println!("DNSSL Domains:     {:?}", res.dnssl_domains);
                }
            }
            ScenarioArg::Discovery => {
                let dur = crate::engine::DiscoveryEngine::probe_rtt(dhcp_server).await?;
                println!("Discovery RTT against {dhcp_server}: {:.2} ms", dur.as_secs_f64() * 1000.0);
            }
        }

        Ok(())
    }

    pub async fn run_bench(
        args: BenchArgs,
        mode: ModeArg,
        dhcp_server: std::net::SocketAddr,
        dns_server: std::net::SocketAddr,
        iface: Option<String>,
    ) -> Result<(), LabError> {
        let harness = Self::init_harness(mode, dhcp_server, dns_server, iface.as_deref())?;

        match args.benchmark {
            BenchTypeArg::DhcpStorm => {
                println!("{}", format!("Starting DHCP Storm with {} clients (concurrency {})...", args.clients, args.concurrency).cyan());
                let rep = harness.dhcp().storm_benchmark(args.clients, args.concurrency).await?;

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&rep)?);
                } else {
                    println!("\n{}", "=== DHCP Storm Report ===".bold().green());
                    println!("Total Clients:     {}", rep.total_clients);
                    println!("Successful Leases: {}", rep.successful_leases.to_string().green());
                    println!("Failed Leases:     {}", rep.failed_leases.to_string().red());
                    println!("Duration:          {:.2} s", rep.duration_secs);
                    println!("Throughput:        {:.1} DORA/s", rep.throughput_dora_per_sec.to_string().bold());
                    println!("Min Latency:       {:.2} ms", rep.min_latency_ms);
                    println!("p50 Latency:       {:.2} ms", rep.p50_latency_ms);
                    println!("p95 Latency:       {:.2} ms", rep.p95_latency_ms);
                    println!("p99 Latency:       {:.2} ms", rep.p99_latency_ms);
                    println!("Max Latency:       {:.2} ms", rep.max_latency_ms);
                }
            }
            BenchTypeArg::DnsFlood => {
                let dur = Duration::from_secs(args.duration);
                println!("{}", format!("Starting DNS Flood target QPS {} for {}s...", args.qps, args.duration).cyan());
                let rep = harness.dns().flood_benchmark(args.qps, dur, &[]).await?;

                if args.json {
                    println!("{}", serde_json::to_string_pretty(&rep)?);
                } else {
                    println!("\n{}", "=== DNS Flood Report ===".bold().green());
                    println!("Total Queries:      {}", rep.total_queries);
                    println!("Successful Queries: {}", rep.successful_queries.to_string().green());
                    println!("Failed Queries:     {}", rep.failed_queries.to_string().red());
                    println!("Blocked Queries:    {}", rep.blocked_count);
                    println!("Duration:           {:.2} s", rep.duration_secs);
                    println!("Actual QPS:         {:.1} QPS", rep.actual_qps.to_string().bold());
                    println!("Min Latency:        {} µs ({:.2} ms)", rep.min_latency_us, rep.min_latency_us as f64 / 1000.0);
                    println!("p50 Latency:        {} µs ({:.2} ms)", rep.p50_latency_us, rep.p50_latency_us as f64 / 1000.0);
                    println!("p95 Latency:        {} µs ({:.2} ms)", rep.p95_latency_us, rep.p95_latency_us as f64 / 1000.0);
                    println!("p99 Latency:        {} µs ({:.2} ms)", rep.p99_latency_us, rep.p99_latency_us as f64 / 1000.0);
                    println!("Max Latency:        {} µs ({:.2} ms)", rep.max_latency_us, rep.max_latency_us as f64 / 1000.0);
                }
            }
        }

        Ok(())
    }

    pub async fn run_suite(
        args: SuiteArgs,
        mode: ModeArg,
        dhcp_server: std::net::SocketAddr,
        dns_server: std::net::SocketAddr,
        iface: Option<String>,
    ) -> Result<(), LabError> {
        let harness = Self::init_harness(mode, dhcp_server, dns_server, iface.as_deref())?;
        let rep = harness.run_full_suite().await?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&rep)?);
        } else {
            println!("\n{}", "=== Lanforge Lab Full Regression Suite ===".bold().cyan());
            println!("DHCP DORA:      {}", if rep.dhcp_dora_passed { "PASSED".green() } else { "FAILED".red() });
            println!("DNS Local:      {}", if rep.dns_local_passed { "PASSED".green() } else { "FAILED".red() });
            println!("DNS Adblock:    {}", if rep.dns_adblock_passed { "PASSED".green() } else { "FAILED".red() });
            println!("DNS Upstream:   {}", if rep.dns_upstream_passed { "PASSED".green() } else { "FAILED".red() });
            println!("----------------------------------------------");
            println!("Overall Status: {}", if rep.all_passed { "ALL TESTS PASSED".bold().green() } else { "TESTS FAILED".bold().red() });
        }

        if !rep.all_passed {
            return Err(LabError::Assertion("Full regression suite failed".to_string()));
        }
        Ok(())
    }

    fn init_harness(
        mode: ModeArg,
        dhcp_server: std::net::SocketAddr,
        dns_server: std::net::SocketAddr,
        iface: Option<&str>,
    ) -> Result<LabHarness, LabError> {
        let harness = match mode {
            ModeArg::Auto => LabHarness::auto()?,
            ModeArg::Direct => LabHarness::setup_direct()?,
            ModeArg::Netns => LabHarness::setup_netns(NetnsConfig::default())?,
            ModeArg::Interface => {
                let if_name = iface.unwrap_or("veth-lf-host");
                LabHarness::targeting_interface(if_name, dhcp_server.port(), dns_server.port())
            }
        };

        Ok(harness.with_endpoints(dhcp_server, dns_server))
    }
}
