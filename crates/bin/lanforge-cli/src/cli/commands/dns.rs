use std::fmt::Write;
use std::fs::read_to_string;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::cli::wizard::{confirm_destructive, fuzzy_select_rewrite, prompt_select, prompt_text};
use crate::cli::{Execute, LanforgeClient};
use crate::render_output;
use chrono::Local;
use clap::Subcommand;
use color_eyre::eyre::{Result, bail};
use colored::Colorize;
use lanforge_api::api::{
    DnsAdblockStatusResponse, DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse,
    DnsCacheResponse, DnsCacheStatsExtResponse, DnsQueryLogEntry, DnsQueryResponse,
    DnsReverseResolversResponse, DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse,
};
use lanforge_api::rpc::RpcResponse;
use lanforge_types::events::{DnsEvent, LanforgeEvent};
use lanforge_types::network::DnsRecordType;
use lanforge_types::network::dns::adblock::{BlockingMode, RewriteRule};

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsArgs {
    #[command(subcommand)]
    pub action: DnsAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsAction {
    Stats,
    Analytics {
        #[arg(long)]
        limit: Option<usize>,
    },
    Upstreams(DnsUpstreamsArgs),
    Query {
        name: Option<String>,
        record_types: Vec<String>,
    },
    Cache(DnsCacheArgs),
    Log {
        #[arg(long)]
        follow: bool,
        #[arg(short, long)]
        n: Option<usize>,
        #[arg(long)]
        client: Option<String>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Adblock(DnsAdblockArgs),
    Rewrites(DnsRewritesArgs),
    Allowlist,
    ReverseResolver(DnsReverseResolverArgs),
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsUpstreamsArgs {
    #[command(subcommand)]
    pub action: Option<DnsUpstreamsAction>,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsUpstreamsAction {
    List,
    Add {
        addr: Option<String>,
        protocol: Option<String>,
        domain: Option<String>,
    },
    Remove {
        addr: Option<String>,
        protocol: Option<String>,
    },
    Clear,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsCacheArgs {
    #[command(subcommand)]
    pub action: DnsCacheAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsCacheAction {
    Dump {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Flush,
    Stats,
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsAdblockArgs {
    #[command(subcommand)]
    pub action: DnsAdblockAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsAdblockAction {
    Status,
    Enable,
    Disable {
        #[arg(long)]
        duration_secs: Option<u64>,
    },
    Reload,
    Block {
        domain: Option<String>,
    },
    Allow {
        domain: Option<String>,
    },
    Unallow {
        domain: Option<String>,
    },
    Config {
        #[arg(long)]
        mode: Option<String>,
        #[arg(long = "ip-v4")]
        ip_v4: Option<String>,
        #[arg(long = "ip-v6")]
        ip_v6: Option<String>,
    },
    Sources {
        #[command(subcommand)]
        action: DnsAdblockSourcesAction,
    },
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsAdblockSourcesAction {
    List,
    Add {
        url: Option<String>,
        kind: Option<String>,
    },
    Remove {
        url: Option<String>,
    },
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsRewritesArgs {
    #[command(subcommand)]
    pub action: DnsRewritesAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsRewritesAction {
    List,
    Add {
        domain: Option<String>,
        answer: Option<String>,
    },
    Remove {
        domain: Option<String>,
    },
    Clear,
    Import {
        file: String,
    },
    Export {
        file: String,
    },
}

fn ip_to_arpa(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(v6) => {
            let nibbles: Vec<u8> = v6
                .octets()
                .iter()
                .flat_map(|b| vec![b >> 4, b & 0xf])
                .collect();
            let mut arpa = String::new();
            for n in nibbles.iter().rev() {
                let _ = write!(arpa, "{n:x}.");
            }
            arpa.push_str("ip6.arpa");
            arpa
        }
    }
}

async fn execute_query(
    client: &LanforgeClient,
    name: Option<String>,
    record_types: Vec<String>,
) -> Result<()> {
    let mut final_name = match name {
        Some(n) => n,
        None => prompt_text("Domain name to query:", None)?,
    };
    let mut rtypes = record_types;
    if rtypes.is_empty() {
        if let Ok(ip) = final_name.parse::<IpAddr>() {
            rtypes.push("PTR".to_string());
            final_name = ip_to_arpa(ip);
        } else {
            rtypes.push("A".to_string());
        }
    }
    if client.json {
        let mut responses = Vec::new();
        for rt in &rtypes {
            let rt_enum = rt
                .parse()
                .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?;
            let resp = client.dns_query(final_name.clone(), Some(rt_enum)).await?;
            responses.push(resp);
        }
        if responses.len() == 1 {
            let s = serde_json::to_string_pretty(&responses[0])?;
            println!("{s}");
        } else {
            let s = serde_json::to_string_pretty(&responses)?;
            println!("{s}");
        }
        return Ok(());
    }
    for (i, rt) in rtypes.iter().enumerate() {
        if i > 0 {
            println!();
        }
        let rt_enum = rt
            .parse()
            .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?;
        let resp = client.dns_query(final_name.clone(), Some(rt_enum)).await?;
        render_dns_query(&resp, client.ascii);
    }
    Ok(())
}

impl Execute for DnsCacheArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DnsCacheAction::Dump { limit, offset } => {
                render_output!(
                    client,
                    client.dns_cache_dump(limit, offset).await?,
                    render_dns_cache
                )
            }
            DnsCacheAction::Flush => {
                if !confirm_destructive(client, "Are you sure you want to flush the DNS cache?")? {
                    return Ok(());
                }
                let resp = client.dns_cache_flush().await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsCacheAction::Stats => {
                render_output!(
                    client,
                    client.dns_cache_stats_ext().await?,
                    render_dns_cache_stats
                )
            }
        }
    }
}

async fn fetch_device_map(client: &LanforgeClient) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Ok(dev_resp) = client
        .list_devices(None, None, None, None, Some(10000), None)
        .await
    {
        for dev in dev_resp.devices {
            if !dev.hostname.is_empty() && dev.hostname != "<unknown>" {
                if let Some(v4) = dev.v4 {
                    map.insert(v4.ip.to_string(), dev.hostname.clone());
                }
                for ip in dev.seen_v4 {
                    map.insert(ip.to_string(), dev.hostname.clone());
                }
                if let Some(v6) = dev.v6 {
                    map.insert(v6.ip.to_string(), dev.hostname.clone());
                }
                for ip in dev.ipv6_addrs {
                    map.insert(ip.addr.to_string(), dev.hostname.clone());
                }
            }
        }
    }
    map
}

async fn execute_log(
    client: &LanforgeClient,
    follow: bool,
    n: Option<usize>,
    client_filter: Option<String>,
    offset: Option<usize>,
) -> Result<()> {
    if !follow {
        let resp = client
            .dns_query_log(false, n, client_filter, offset)
            .await?;
        for entry in &resp.entries {
            render_dns_log_entry(entry, client.ascii);
        }
        return Ok(());
    }

    let ip_to_host = fetch_device_map(client).await;

    #[cfg(feature = "remote")]
    if let Some(base) = &client.remote {
        use futures::StreamExt;
        use lanforge_types::events::TimedEvent;

        let resp = client
            .dns_query_log(false, n, client_filter.clone(), offset)
            .await?;
        for entry in &resp.entries {
            render_dns_log_entry(entry, client.ascii);
        }

        let mut params = vec!["follow=true".to_string()];
        if let Some(c) = &client_filter {
            params.push(format!("client={c}"));
        }
        let q = format!("?{}", params.join("&"));
        let url = format!("{base}/api/v1/dns/logs{q}");
        let mut req = client.http_client.get(&url);
        if let Some(t) = &client.token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        let mut resp = req.send().await?.bytes_stream();
        println!("Watching for remote DNS logs... (Ctrl+C to stop)");
        while let Some(chunk) = resp.next().await {
            if let Ok(bytes) = chunk {
                let s = String::from_utf8_lossy(&bytes);
                for line in s.lines() {
                    use lanforge_types::events::{DnsEvent, LanforgeEvent};

                    if let Some(json_str) = line.strip_prefix("data: ")
                        && let Ok(timed_event) = serde_json::from_str::<TimedEvent>(json_str)
                        && let LanforgeEvent::Dns(DnsEvent::QueryResolved(q)) = timed_event.event
                    {
                        let src_hostname = ip_to_host.get(&q.src_ip.to_string()).cloned();
                        let entry = DnsQueryLogEntry {
                            timestamp: q.timestamp,
                            src_ip: q.src_ip.to_string(),
                            src_mac: q.src_mac.map(|m| m.to_string()),
                            src_hostname,
                            domain: q.domain.to_string(),
                            qtype: q.qtype,
                            result: format!("{:?}", q.result),
                            upstream_us: q.upstream_us,
                            cached: q.cached,
                            answer: q.answer,
                        };
                        render_dns_log_entry(&entry, client.ascii);
                    }
                }
            }
        }
        return Ok(());
    }

    let mut rpc = client.connect_rpc().await?;
    let resp = rpc.dns_query_log(true, n, client_filter, offset).await?;
    for entry in &resp.entries {
        render_dns_log_entry(entry, client.ascii);
    }
    println!("Watching for DNS logs... (Ctrl+C to stop)");
    loop {
        match rpc.next_response().await {
            Ok(RpcResponse::Event(event)) => {
                if let LanforgeEvent::Dns(DnsEvent::QueryResolved(q)) = event.event {
                    let src_hostname = ip_to_host.get(&q.src_ip.to_string()).cloned();
                    let entry = DnsQueryLogEntry {
                        timestamp: q.timestamp,
                        src_ip: q.src_ip.to_string(),
                        src_mac: q.src_mac.map(|m| m.to_string()),
                        src_hostname,
                        domain: q.domain.to_string(),
                        qtype: q.qtype,
                        result: format!("{:?}", q.result),
                        upstream_us: q.upstream_us,
                        cached: q.cached,
                        answer: q.answer,
                    };
                    render_dns_log_entry(&entry, client.ascii);
                }
            }
            Ok(_) => {}
            Err(e) => {
                if e.to_string().contains("UnexpectedEof") || e.to_string().contains("early eof") {
                    break;
                }
                bail!("RPC Stream Error: {e}");
            }
        }
    }
    Ok(())
}

async fn execute_adblock_config(
    client: &LanforgeClient,
    mode: Option<String>,
    ip_v4: Option<String>,
    ip_v6: Option<String>,
) -> Result<()> {
    if mode.is_none() && ip_v4.is_none() && ip_v6.is_none() {
        let status = client.dns_adblock_status().await?;
        if client.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "blocking_mode": status.blocking_mode,
                    "blocking_ip_v4": status.blocking_ip_v4,
                    "blocking_ip_v6": status.blocking_ip_v6,
                }))?
            );
        } else {
            println!(" DNS ADBLOCK CONFIGURATION \n");
            println!("  {:<20} {}", "Blocking Mode:", status.blocking_mode);
            if let Some(ip) = status.blocking_ip_v4 {
                println!("  {:<20} {}", "IPv4 Target:", ip);
            }
            if let Some(ip) = status.blocking_ip_v6 {
                println!("  {:<20} {}", "IPv6 Target:", ip);
            }
        }
        return Ok(());
    }

    let final_mode = if let Some(m) = mode {
        let parsed: BlockingMode = m
            .parse()
            .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?;
        Some(parsed)
    } else {
        None
    };

    let final_ipv4 = if let Some(ip) = ip_v4 {
        let parsed: Ipv4Addr = ip
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("Invalid IPv4: {e}"))?;
        Some(parsed)
    } else {
        None
    };

    let final_ipv6 = if let Some(ip) = ip_v6 {
        let parsed: Ipv6Addr = ip
            .parse()
            .map_err(|e| color_eyre::eyre::eyre!("Invalid IPv6: {e}"))?;
        Some(parsed)
    } else {
        None
    };

    let resp = client
        .dns_adblock_config_set(final_mode, final_ipv4, final_ipv6)
        .await?;
    println!("✓ {}", resp.message);
    Ok(())
}

impl Execute for DnsAdblockArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DnsAdblockAction::Status => {
                render_output!(
                    client,
                    client.dns_adblock_status().await?,
                    render_adblock_status
                )
            }
            DnsAdblockAction::Enable => {
                let resp = client.dns_adblock_set(true, None).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsAdblockAction::Disable { duration_secs } => {
                let resp = client.dns_adblock_set(false, duration_secs).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsAdblockAction::Reload => {
                let resp = client.dns_adblock_reload().await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsAdblockAction::Block { domain } => {
                let final_domain = match domain {
                    Some(d) => d,
                    None => prompt_text("Domain to block:", None)?,
                };
                let resp = client.dns_block(final_domain).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsAdblockAction::Allow { domain } => {
                let final_domain = match domain {
                    Some(d) => d,
                    None => prompt_text("Domain to allow:", None)?,
                };
                let resp = client.dns_allow(final_domain).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsAdblockAction::Unallow { domain } => {
                let final_domain = if let Some(d) = domain {
                    d
                } else {
                    let resp = client.dns_allowlist().await?;
                    let items = resp
                        .allowlist
                        .into_iter()
                        .map(|e| format!("{} ({})", e.domain, e.id))
                        .collect::<Vec<_>>();
                    let choice = prompt_select(
                        "Select allowlist entry to remove:",
                        items.iter().map(String::as_str).collect(),
                    )?;
                    let parts: Vec<&str> = choice.split_whitespace().collect();
                    parts[0].to_string()
                };
                let resp = client.dns_unallow(final_domain).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsAdblockAction::Config { mode, ip_v4, ip_v6 } => {
                execute_adblock_config(client, mode, ip_v4, ip_v6).await
            }
            DnsAdblockAction::Sources { action } => action.execute(client).await,
        }
    }
}

impl Execute for DnsAdblockSourcesAction {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self {
            Self::List => {
                render_output!(
                    client,
                    client.dns_adblock_url_list().await?,
                    render_adblock_urls
                )
            }
            Self::Add { url, kind } => {
                let final_url = match url {
                    Some(u) => u,
                    None => prompt_text("Source URL:", None)?,
                };
                let final_kind = match kind {
                    Some(k) => k
                        .parse()
                        .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?,
                    None => prompt_select("List kind:", vec!["blocklist", "allowlist"])?
                        .parse()
                        .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?,
                };
                let resp = client.dns_adblock_url_add(final_url, final_kind).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            Self::Remove { url } => {
                let final_url = if let Some(u) = url {
                    u
                } else {
                    let resp = client.dns_adblock_url_list().await?;
                    let items = resp.urls;
                    let choice = prompt_select(
                        "Select source to remove:",
                        items.iter().map(|s| s.url.as_str()).collect(),
                    )?;
                    choice.to_string()
                };
                let resp = client.dns_adblock_url_remove(final_url).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
        }
    }
}

impl Execute for DnsRewritesArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DnsRewritesAction::List => {
                render_output!(client, client.dns_rewrites().await?, render_rewrites)
            }
            DnsRewritesAction::Add { domain, answer } => {
                let final_domain = match domain {
                    Some(d) => d,
                    None => prompt_text("Domain name:", None)?,
                };
                let final_answer = match answer {
                    Some(a) => a,
                    None => prompt_text("Answer (IP or Target):", None)?,
                };
                let rtype = if final_answer.parse::<Ipv4Addr>().is_ok() {
                    DnsRecordType::A
                } else if final_answer.parse::<Ipv6Addr>().is_ok() {
                    DnsRecordType::AAAA
                } else {
                    DnsRecordType::CNAME
                };
                let rule = RewriteRule {
                    id: None,
                    domain: final_domain,
                    rtype,
                    answer: final_answer
                        .parse()
                        .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?,
                };
                let resp = client.dns_rewrite_add(rule).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsRewritesAction::Remove { domain } => {
                let final_id = if let Some(d) = domain {
                    let resp = client.dns_rewrites().await?;
                    let rule = resp.rewrites.into_iter().find(|r| r.domain == d);
                    match rule {
                        Some(r) => r.id.unwrap(),
                        None => bail!("Rewrite rule for domain '{d}' not found."),
                    }
                } else {
                    let rw = fuzzy_select_rewrite(client, "Select rewrite rule to remove:").await?;
                    rw.id.unwrap()
                };
                let resp = client.dns_rewrite_remove(final_id).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsRewritesAction::Clear => {
                if !confirm_destructive(
                    client,
                    "Are you sure you want to clear all DNS rewrite rules?",
                )? {
                    return Ok(());
                }
                let resp = client.dns_rewrite_clear().await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsRewritesAction::Import { file } => {
                let content = read_to_string(&file)?;
                let rules: Vec<RewriteRule> = serde_json::from_str(&content)?;
                let resp = client.dns_rewrite_import(rules).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsRewritesAction::Export { file } => {
                let resp = client.dns_rewrites().await?;
                let json = serde_json::to_string_pretty(&resp.rewrites)?;
                std::fs::write(&file, json)?;
                println!(
                    "✓ Exported {} rewrite rules to {}",
                    resp.rewrites.len(),
                    file
                );
                Ok(())
            }
        }
    }
}

impl Execute for DnsUpstreamsArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        let action = self.action.unwrap_or(DnsUpstreamsAction::List);
        match action {
            DnsUpstreamsAction::List => {
                render_output!(client, client.dns_upstreams().await?, render_dns_upstreams)
            }
            DnsUpstreamsAction::Add {
                addr,
                protocol,
                domain,
            } => {
                let final_addr = match addr {
                    Some(a) => a.parse()?,
                    None => prompt_text("Upstream Address (IP:Port):", None)?.parse()?,
                };
                let final_proto = match protocol {
                    Some(p) => p
                        .parse()
                        .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?,
                    None => prompt_select("Protocol:", vec!["Udp", "Https", "Tls", "Quic"])?
                        .parse()
                        .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?,
                };
                let resp = client
                    .dns_upstream_add(final_addr, final_proto, domain)
                    .await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsUpstreamsAction::Remove { addr, protocol } => {
                let (final_addr, final_proto) = if let (Some(a), Some(p)) = (addr, protocol) {
                    (
                        a.parse()?,
                        p.parse()
                            .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?,
                    )
                } else {
                    let resp = client.dns_upstreams().await?;
                    if resp.upstreams.is_empty() {
                        bail!("No upstreams configured.");
                    }
                    let items = resp
                        .upstreams
                        .iter()
                        .map(|u| format!("{} ({})", u.target, u.protocol))
                        .collect::<Vec<_>>();
                    let choice = prompt_select(
                        "Select upstream to remove:",
                        items.iter().map(String::as_str).collect(),
                    )?;
                    let parts: Vec<&str> = choice.split_whitespace().collect();
                    let a = parts[0].parse()?;
                    let p = parts[1]
                        .trim_matches(|c| c == '(' || c == ')')
                        .parse()
                        .map_err(|e: String| color_eyre::eyre::eyre!("{e}"))?;
                    (a, p)
                };
                let resp = client.dns_upstream_remove(final_addr, final_proto).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsUpstreamsAction::Clear => {
                if !confirm_destructive(
                    client,
                    "Are you sure you want to remove all DNS upstreams?",
                )? {
                    return Ok(());
                }
                let resp = client.dns_upstreams().await?;
                for u in resp.upstreams {
                    let _ = client.dns_upstream_remove(u.target, u.protocol).await;
                }
                println!("✓ Cleared all DNS upstreams");
                Ok(())
            }
        }
    }
}

impl Execute for DnsArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DnsAction::Stats => render_output!(client, client.dns_stats().await?, render_dns_stats),
            DnsAction::Analytics { limit } => render_output!(
                client,
                client.dns_analytics(limit).await?,
                render_dns_analytics
            ),
            DnsAction::Upstreams(args) => args.execute(client).await,
            DnsAction::Query { name, record_types } => {
                execute_query(client, name, record_types).await
            }
            DnsAction::Cache(args) => args.execute(client).await,
            DnsAction::Log {
                follow,
                n,
                client: client_filter,
                offset,
            } => execute_log(client, follow, n, client_filter, offset).await,
            DnsAction::Adblock(args) => args.execute(client).await,
            DnsAction::Rewrites(args) => args.execute(client).await,
            DnsAction::Allowlist => {
                render_output!(client, client.dns_allowlist().await?, render_allowlist)
            }
            DnsAction::ReverseResolver(args) => args.execute(client).await,
        }
    }
}

pub fn render_dns_stats(resp: &DnsStatsResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS RESOLVER STATISTICS \n");
    println!("  {:<25} {}", "Total Requests:", resp.total_requests);
    println!("  {:<25} {}", "Cache Hits:", resp.cache_hits);
    println!("  {:<25} {}", "Cache Misses:", resp.cache_misses);
    println!("  {:<25} {}", "Upstream Errors:", resp.upstream_errors);
    println!("  {:<25} {}", "Authoritative Queries:", resp.auth_queries);
    println!("  {:<25} {}", "Recursive Queries:", resp.recursions);
    println!("  {:<25} {}", "Blocked Queries:", resp.blocked_queries);
    println!("  {:<25} {}", "Successfully Resolved:", resp.resolved_total);
    println!("  {:<25} {}", "Failed Queries:", resp.failed_total);
    println!(
        "  {:<25} {} / {}",
        "Cache Utilization:", resp.cache_entries, resp.cache_capacity
    );
    println!("{}", hline.repeat(50));
}

pub fn render_dns_analytics(resp: &DnsAnalyticsResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS ANALYTICS \n");
    println!("  Top Domains:");
    for d in &resp.top_domains {
        println!("    {:<30} | {}", d.domain, d.count);
    }
    println!("{}", hline.repeat(50));
    println!("  Top Clients:");
    for c in &resp.top_clients {
        let host = c.hostname.as_deref().unwrap_or(&c.ip);
        println!("    {:<30} | {}", host, c.count);
    }
    println!("{}", hline.repeat(50));
    println!("  Query Types:");
    for q in &resp.query_types {
        println!("    {:<10} | {}", q.qtype, q.count);
    }
}

pub fn render_dns_upstreams(resp: &DnsUpstreamsResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS UPSTREAMS HEALTH \n");
    println!("  {:<30} | {:<10} | LATENCY", "UPSTREAM", "STATUS");
    println!("{}", hline.repeat(60));
    for u in &resp.upstreams {
        let status = if u.status.eq_ignore_ascii_case("healthy")
            || u.status.eq_ignore_ascii_case("online")
        {
            "Healthy".green()
        } else {
            "Failing".red()
        };
        let rtt_ms = u.rtt_ewma_us / 1000;
        println!("  {:<30} | {:<10} | {}ms", u.target, status, rtt_ms);
    }
}

pub fn render_dns_query(resp: &DnsQueryResponse, _ascii: bool) {
    let auth_str = if resp.authoritative {
        format!("Authoritative - {}", resp.result).green()
    } else {
        format!("Non-Authoritative - {}", resp.result).yellow()
    };
    println!(
        " {}   latency: {}ms  ({auth_str})",
        "QUERY RESULT".bold(),
        resp.latency_ms.to_string().yellow()
    );
    if resp.result == "Blocked" || resp.result == "CachedBlock" {
        println!("{}", "Domain blocked by AdBlocker.".red());
    } else if resp.records.is_empty() {
        println!("{}", "No records found.".red());
    } else {
        for r in &resp.records {
            println!(
                "{} {} {} {} {} {}",
                r.kind.to_string().cyan(),
                r.name,
                "->".dimmed(),
                r.data.green(),
                "TTL".dimmed(),
                r.ttl.to_string().yellow(),
            );
        }
    }
}

pub fn render_dns_cache(resp: &DnsCacheResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS CACHE DUMP ({} entries) \n", resp.total);
    println!("  {:<30} | {:<5} | {:<10} | DATA", "NAME", "TYPE", "TTL");
    println!("{}", hline.repeat(80));
    for c in &resp.entries {
        println!(
            "  {:<30} | {:<5?} | {:<10} | {}",
            c.name, c.kind, c.expires_in_secs, c.data
        );
    }
}

pub fn render_dns_cache_stats(resp: &DnsCacheStatsExtResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS CACHE EXTENDED STATS \n");
    println!("  {:<25} {}", "Total Entries:", resp.total_entries);
    println!(
        "  {:<25} {} bytes",
        "Memory Usage:", resp.memory_usage_bytes
    );
    println!("  {:<25} {}s", "Average TTL:", resp.average_ttl_secs);
    println!("{}", hline.repeat(50));
    println!("  Entries by Type:");
    for (t, count) in &resp.entries_by_type {
        println!("    {t:<10?} | {count}");
    }
}

pub fn render_dns_log_entry(entry: &DnsQueryLogEntry, ascii: bool) {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(entry.timestamp.cast_signed(), 0)
        .map(|utc| DateTime::<Local>::from(utc).format("%H:%M:%S").to_string())
        .unwrap_or_default();

    let client_raw = entry.src_hostname.as_deref().unwrap_or(&entry.src_ip);
    let client_trunc = if client_raw.chars().count() > 20 {
        format!("{}...", client_raw.chars().take(17).collect::<String>())
    } else {
        client_raw.to_string()
    };
    let client_padded = format!("{client_trunc:<20}");

    let qtype_str = entry.qtype.to_string();
    let qtype_padded = format!("{qtype_str:<5}");
    let qtype_colored = match entry.qtype {
        DnsRecordType::A => qtype_padded.cyan(),
        DnsRecordType::AAAA => qtype_padded.green(),
        DnsRecordType::CNAME => qtype_padded.yellow(),
        DnsRecordType::HTTPS | DnsRecordType::SVCB => qtype_padded.magenta(),
        _ => qtype_padded.dimmed(),
    };

    let domain_trunc = if entry.domain.chars().count() > 35 {
        format!("{}...", entry.domain.chars().take(32).collect::<String>())
    } else {
        entry.domain.clone()
    };
    let domain_padded = format!("{domain_trunc:<35}");

    let status_colored = match entry.result.as_str() {
        "Blocked" => entry.result.red(),
        "CachedBlock" => entry.result.truecolor(255, 165, 0),
        "Rewritten" | "Cached" => entry.result.cyan(),
        "Forwarded" | "Local" => entry.result.green(),
        "NxDomain" | "Error" => entry.result.yellow(),
        _ => entry.result.normal(),
    };

    let latency_ms = f64::from(entry.upstream_us) / 1000.0;
    let latency_str = if entry.upstream_us == 0 {
        "(0ms)".dimmed()
    } else if latency_ms >= 10.0 {
        format!("({latency_ms:.1}ms)").yellow()
    } else {
        format!("({latency_ms:.1}ms)").dimmed()
    };

    let sep = if ascii { "|".dimmed() } else { "│".dimmed() };

    println!(
        "{} {} {} {} {} {} {} {}",
        dt.dimmed(),
        sep,
        client_padded.bright_blue(),
        sep,
        qtype_colored,
        domain_padded,
        sep,
        format_args!("{status_colored} {latency_str}")
    );
}

pub fn render_adblock_status(resp: &DnsAdblockStatusResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS ADBLOCK STATUS \n");
    let status_str = if resp.enabled {
        "Enabled".green()
    } else {
        "Disabled".red()
    };
    println!("  {:<20} {}", "Status:", status_str);
    println!("  {:<20} {}", "Blocking Mode:", resp.blocking_mode);
    if let Some(ip) = resp.blocking_ip_v4 {
        println!("  {:<20} {}", "IPv4 Target:", ip);
    }
    if let Some(ip) = resp.blocking_ip_v6 {
        println!("  {:<20} {}", "IPv6 Target:", ip);
    }
    println!("  {:<20} {}", "Blocklist Rules:", resp.blocklist_size);
    println!("  {:<20} {}", "Allowlist Rules:", resp.allowlist_size);
    if let Some(rem) = resp.remaining_secs {
        println!("  {:<20} {}s", "Disabled For:", rem);
    }
    println!("{}", hline.repeat(50));
}

pub fn render_adblock_urls(resp: &DnsAdblockUrlsResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS ADBLOCK SOURCES \n");
    println!("  {:<12} | URL", "KIND");
    println!("{}", hline.repeat(80));
    for u in &resp.urls {
        let kind_color =
            if u.kind == lanforge_types::network::dns::adblock::AdblockUrlKind::Blocklist {
                colored::Color::Red
            } else {
                colored::Color::Green
            };
        println!("  {:<12} | {}", u.kind.to_string().color(kind_color), u.url);
    }
}

pub fn render_rewrites(resp: &DnsRewritesResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS REWRITE RULES \n");
    println!("  {:<30} | ANSWER (TARGET)", "DOMAIN");
    println!("{}", hline.repeat(70));
    for r in &resp.rewrites {
        println!("  {:<30} | {}", r.domain, r.answer);
    }
}

pub fn render_allowlist(resp: &DnsAllowlistResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS ALLOWLIST \n");
    println!("  {:<6} | DOMAIN", "ID");
    println!("{}", hline.repeat(50));
    for a in &resp.allowlist {
        println!("  {:<6} | {}", a.id, a.domain);
    }
}

#[derive(clap::Args, Debug, Clone, PartialEq, Eq)]
pub struct DnsReverseResolverArgs {
    #[command(subcommand)]
    pub action: DnsReverseResolverAction,
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum DnsReverseResolverAction {
    List,
    Add {
        subnet: Option<String>,
        resolver_uri: Option<String>,
    },
    Remove {
        subnet: Option<String>,
    },
}

impl Execute for DnsReverseResolverArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DnsReverseResolverAction::List => {
                render_output!(
                    client,
                    client.dns_reverse_resolver_list().await?,
                    render_dns_reverse_resolvers
                )
            }
            DnsReverseResolverAction::Add {
                subnet,
                resolver_uri,
            } => {
                let final_subnet = match subnet {
                    Some(s) => s,
                    None => prompt_text("Subnet CIDR (e.g. 100.64.0.0/10):", None)?,
                };
                let final_resolver = match resolver_uri {
                    Some(r) => r,
                    None => prompt_text("Resolver URI (e.g. udp://100.100.100.100:53):", None)?,
                };
                let resp = client
                    .dns_reverse_resolver_add(final_subnet, final_resolver)
                    .await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
            DnsReverseResolverAction::Remove { subnet } => {
                let final_subnet = if let Some(s) = subnet {
                    s
                } else {
                    let resp = client.dns_reverse_resolver_list().await?;
                    if resp.resolvers.is_empty() {
                        bail!("No reverse resolvers configured.");
                    }
                    let items = resp
                        .resolvers
                        .iter()
                        .map(|r| format!("{} ({})", r.subnet, r.resolver))
                        .collect::<Vec<_>>();
                    let choice = prompt_select(
                        "Select reverse resolver to remove:",
                        items.iter().map(String::as_str).collect(),
                    )?;
                    let parts: Vec<&str> = choice.split_whitespace().collect();
                    parts[0].to_string()
                };
                let resp = client.dns_reverse_resolver_remove(final_subnet).await?;
                println!("✓ {}", resp.message);
                Ok(())
            }
        }
    }
}

pub fn render_dns_reverse_resolvers(resp: &DnsReverseResolversResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS REVERSE RESOLVERS \n");
    println!("  {:<30} | RESOLVER TARGET", "SUBNET");
    println!("{}", hline.repeat(60));
    for r in &resp.resolvers {
        println!("  {:<30} | {}", r.subnet, r.resolver);
    }
}
