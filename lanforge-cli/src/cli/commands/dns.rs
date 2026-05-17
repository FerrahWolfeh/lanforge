use crate::cli::{Execute, LanforgeClient};
use clap::Subcommand;
use color_eyre::eyre::{Result, bail};
use colored::Colorize;
use lanforge_api::api::{
    DnsAdblockStatusResponse, DnsAdblockUrlsResponse, DnsAllowlistResponse, DnsAnalyticsResponse,
    DnsCacheResponse, DnsCacheStatsExtResponse, DnsQueryLogEntry, DnsQueryResponse,
    DnsRewritesResponse, DnsStatsResponse, DnsUpstreamsResponse,
};
use lanforge_types::network::dns::adblock::RewriteRule;

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
    Upstreams,
    Query {
        name: Option<String>,
        record_type: Option<String>,
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

impl Execute for DnsArgs {
    async fn execute(self, client: &LanforgeClient) -> Result<()> {
        match self.action {
            DnsAction::Stats => {
                let resp = client.dns_stats().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_dns_stats(&resp, client.ascii);
            }
            DnsAction::Analytics { limit } => {
                let resp = client.dns_analytics(limit).await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_dns_analytics(&resp, client.ascii);
            }
            DnsAction::Upstreams => {
                let resp = client.dns_upstreams().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_dns_upstreams(&resp, client.ascii);
            }
            DnsAction::Query { name, record_type } => {
                let final_name = match name {
                    Some(n) => n,
                    None => crate::cli::wizard::prompt_text("Domain name to query:", None)?,
                };
                let mut final_rt = record_type;
                if final_rt.is_none() && final_name.parse::<std::net::IpAddr>().is_ok() {
                    final_rt = Some("PTR".to_string());
                }
                let final_rt = match final_rt {
                    Some(r) => Some(r),
                    None => Some(
                        crate::cli::wizard::prompt_select(
                            "Record type:",
                            vec!["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "SRV"],
                        )?
                        .to_string(),
                    ),
                };

                let resp = client.dns_query(final_name, final_rt).await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_dns_query(&resp, client.ascii);
            }
            DnsAction::Cache(args) => match args.action {
                DnsCacheAction::Dump { limit, offset } => {
                    let resp = client.dns_cache_dump(limit, offset).await?;
                    if client.json {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                        return Ok(());
                    }
                    render_dns_cache(&resp, client.ascii);
                }
                DnsCacheAction::Flush => {
                    if !crate::cli::wizard::confirm_destructive(
                        client,
                        "Are you sure you want to flush the DNS cache?",
                    )? {
                        return Ok(());
                    }
                    let resp = client.dns_cache_flush().await?;
                    println!("✓ {}", resp.message);
                }
                DnsCacheAction::Stats => {
                    let resp = client.dns_cache_stats_ext().await?;
                    if client.json {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                        return Ok(());
                    }
                    render_dns_cache_stats(&resp, client.ascii);
                }
            },
            DnsAction::Log {
                follow,
                n,
                client: client_filter,
                offset,
            } => {
                #[cfg(feature = "remote")]
                if let Some(base) = &client.remote {
                    use futures::StreamExt;

                    let mut params = Vec::new();
                    params.push(format!("follow={follow}"));
                    if let Some(num) = n {
                        params.push(format!("n={num}"));
                    }
                    if let Some(c) = &client_filter {
                        params.push(format!("client={c}"));
                    }
                    if let Some(o) = offset {
                        params.push(format!("offset={o}"));
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
                                if let Some(json_str) = line.strip_prefix("data: ")
                                    && let Ok(entry) =
                                        serde_json::from_str::<DnsQueryLogEntry>(json_str)
                                {
                                    render_dns_log_entry(&entry, client.ascii);
                                }
                            }
                        }
                    }
                    return Ok(());
                }

                let mut rpc = client.connect_rpc().await?;
                rpc.dns_query_log(follow, n, client_filter, offset).await?;
                println!("Watching for DNS logs... (Ctrl+C to stop)");
                loop {
                    match rpc.next_response().await {
                        Ok(lanforge_api::rpc::RpcResponse::DnsQueryLog(resp)) => {
                            for entry in &resp.entries {
                                render_dns_log_entry(entry, client.ascii);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            if e.to_string().contains("UnexpectedEof") {
                                break;
                            }
                            bail!("RPC Stream Error: {e}");
                        }
                    }
                }
                return Ok(());
            }
            DnsAction::Adblock(args) => match args.action {
                DnsAdblockAction::Status => {
                    let resp = client.dns_adblock_status().await?;
                    if client.json {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                        return Ok(());
                    }
                    render_adblock_status(&resp, client.ascii);
                }
                DnsAdblockAction::Enable => {
                    let resp = client.dns_adblock_set(true, None).await?;
                    println!("✓ {}", resp.message);
                }
                DnsAdblockAction::Disable { duration_secs } => {
                    let resp = client.dns_adblock_set(false, duration_secs).await?;
                    println!("✓ {}", resp.message);
                }
                DnsAdblockAction::Reload => {
                    let resp = client.dns_adblock_reload().await?;
                    println!("✓ {}", resp.message);
                }
                DnsAdblockAction::Block { domain } => {
                    let final_domain = match domain {
                        Some(d) => d,
                        None => crate::cli::wizard::prompt_text("Domain to block:", None)?,
                    };
                    let resp = client.dns_block(final_domain).await?;
                    println!("✓ {}", resp.message);
                }
                DnsAdblockAction::Allow { domain } => {
                    let final_domain = match domain {
                        Some(d) => d,
                        None => crate::cli::wizard::prompt_text("Domain to allow:", None)?,
                    };
                    let resp = client.dns_allow(final_domain).await?;
                    println!("✓ {}", resp.message);
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
                        let choice = crate::cli::wizard::prompt_select(
                            "Select allowlist entry to remove:",
                            items.iter().map(std::string::String::as_str).collect(),
                        )?;
                        let parts: Vec<&str> = choice.split_whitespace().collect();
                        parts[0].to_string()
                    };
                    let resp = client.dns_unallow(final_domain).await?;
                    println!("✓ {}", resp.message);
                }
                DnsAdblockAction::Sources { action } => match action {
                    DnsAdblockSourcesAction::List => {
                        let resp = client.dns_adblock_url_list().await?;
                        if client.json {
                            println!("{}", serde_json::to_string_pretty(&resp)?);
                            return Ok(());
                        }
                        render_adblock_urls(&resp, client.ascii);
                    }
                    DnsAdblockSourcesAction::Add { url, kind } => {
                        let final_url = match url {
                            Some(u) => u,
                            None => crate::cli::wizard::prompt_text("Source URL:", None)?,
                        };
                        let final_kind = match kind {
                            Some(k) => k,
                            None => crate::cli::wizard::prompt_select(
                                "List kind:",
                                vec!["blocklist", "allowlist"],
                            )?
                            .to_string(),
                        };
                        let resp = client.dns_adblock_url_add(final_url, final_kind).await?;
                        println!("✓ {}", resp.message);
                    }
                    DnsAdblockSourcesAction::Remove { url } => {
                        let final_url = if let Some(u) = url {
                            u
                        } else {
                            let resp = client.dns_adblock_url_list().await?;
                            let items = resp.urls;
                            let choice = crate::cli::wizard::prompt_select(
                                "Select source to remove:",
                                items.iter().map(|s| s.url.as_str()).collect(),
                            )?;
                            choice.to_string()
                        };
                        let resp = client.dns_adblock_url_remove(final_url).await?;
                        println!("✓ {}", resp.message);
                    }
                },
            },
            DnsAction::Rewrites(args) => match args.action {
                DnsRewritesAction::List => {
                    let resp = client.dns_rewrites().await?;
                    if client.json {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                        return Ok(());
                    }
                    render_rewrites(&resp, client.ascii);
                }
                DnsRewritesAction::Add { domain, answer } => {
                    let final_domain = match domain {
                        Some(d) => d,
                        None => crate::cli::wizard::prompt_text("Domain name:", None)?,
                    };
                    let final_answer = match answer {
                        Some(a) => a,
                        None => crate::cli::wizard::prompt_text("Answer (IP or Target):", None)?,
                    };
                    let rtype = if final_answer.parse::<std::net::Ipv4Addr>().is_ok() {
                        lanforge_types::network::DnsRecordType::A
                    } else if final_answer.parse::<std::net::Ipv6Addr>().is_ok() {
                        lanforge_types::network::DnsRecordType::AAAA
                    } else {
                        lanforge_types::network::DnsRecordType::CNAME
                    };
                    let rule = RewriteRule {
                        id: None,
                        domain: final_domain,
                        rtype,
                        answer: final_answer,
                    };
                    let resp = client.dns_rewrite_add(rule).await?;
                    println!("✓ {}", resp.message);
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
                        let rw = crate::cli::wizard::fuzzy_select_rewrite(
                            client,
                            "Select rewrite rule to remove:",
                        )
                        .await?;
                        rw.id.unwrap()
                    };
                    let resp = client.dns_rewrite_remove(final_id).await?;
                    println!("✓ {}", resp.message);
                }
                DnsRewritesAction::Clear => {
                    if !crate::cli::wizard::confirm_destructive(
                        client,
                        "Are you sure you want to clear all DNS rewrite rules?",
                    )? {
                        return Ok(());
                    }
                    let resp = client.dns_rewrite_clear().await?;
                    println!("✓ {}", resp.message);
                }
                DnsRewritesAction::Import { file } => {
                    let content = std::fs::read_to_string(&file)?;
                    let rules: Vec<RewriteRule> = serde_json::from_str(&content)?;
                    let resp = client.dns_rewrite_import(rules).await?;
                    println!("✓ {}", resp.message);
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
                }
            },
            DnsAction::Allowlist => {
                let resp = client.dns_allowlist().await?;
                if client.json {
                    println!("{}", serde_json::to_string_pretty(&resp)?);
                    return Ok(());
                }
                render_allowlist(&resp, client.ascii);
            }
        }
        Ok(())
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

pub fn render_dns_query(resp: &DnsQueryResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS QUERY RESULTS \n");
    println!(
        "  Latency: {}ms | Authoritative: {}",
        resp.latency_ms, resp.authoritative
    );
    println!("{}", hline.repeat(60));
    for r in &resp.records {
        println!("  {:<20} {:<5?} {}", r.name, r.kind, r.data);
    }
}

pub fn render_dns_cache(resp: &DnsCacheResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS CACHE DUMP ({} entries) \n", resp.total);
    println!(
        "  {:<30} | {:<5} | {:<10} | {}",
        "NAME", "TYPE", "TTL", "DATA"
    );
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

pub fn render_dns_log_entry(entry: &DnsQueryLogEntry, _ascii: bool) {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp(entry.timestamp.cast_signed(), 0)
        .map(|dt| dt.format("%H:%M:%S").to_string())
        .unwrap_or_default();
    let client_str = entry.src_hostname.as_deref().unwrap_or(&entry.src_ip);
    let status_color = if entry.result == "Blocked" {
        colored::Color::Red
    } else if entry.cached {
        colored::Color::Cyan
    } else {
        colored::Color::Green
    };
    println!(
        "{} | {:<15} | {:<5?} {:<30} | {} ({})",
        dt.dimmed(),
        client_str,
        entry.qtype,
        entry.domain,
        entry.result.color(status_color),
        entry.upstream_us
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
    println!("  {:<12} | {}", "KIND", "URL");
    println!("{}", hline.repeat(80));
    for u in &resp.urls {
        let kind_color = if u.kind == "blocklist" {
            colored::Color::Red
        } else {
            colored::Color::Green
        };
        println!("  {:<12} | {}", u.kind.color(kind_color), u.url);
    }
}

pub fn render_rewrites(resp: &DnsRewritesResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS REWRITE RULES \n");
    println!("  {:<30} | {}", "DOMAIN", "ANSWER (TARGET)");
    println!("{}", hline.repeat(70));
    for r in &resp.rewrites {
        println!("  {:<30} | {}", r.domain, r.answer);
    }
}

pub fn render_allowlist(resp: &DnsAllowlistResponse, ascii: bool) {
    let hline = if ascii { "-" } else { "─" };
    println!(" DNS ALLOWLIST \n");
    println!("  {:<6} | {}", "ID", "DOMAIN");
    println!("{}", hline.repeat(50));
    for a in &resp.allowlist {
        println!("  {:<6} | {}", a.id, a.domain);
    }
}
