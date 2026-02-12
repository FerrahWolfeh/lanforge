use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use tracing::{error, info, warn};
// Importamos os bitflags de estado corretamente
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState,
};
use rtnetlink::{IpVersion, new_connection};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use sysinfo::{Signal, System};
use tokio::signal::unix::{SignalKind, signal};

// --- CONFIGURAÇÃO ---
const LEASES_FILE: &str = "/mnt/ram/dnsmasq/dnsmasq.leases";
const OUTPUT_FILE: &str = "/mnt/ram/dnsmasq/ipv6_slaac_hosts";
const TARGET_PREFIX: &str = "fd97:f00d:cafe:3731";

// Hosts estáticos no dnsmasq (não recebem sufixo -slaac)
const DNSMASQ_CONFIG: &str = "/etc/dnsmasq.conf";

// Hosts estáticos identificados via dnsmasq.conf

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Configurar logs sem timestamp (systemd já coloca)
    tracing_subscriber::fmt()
        .without_time()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Iniciando ipv6_namer em modo daemon (aguardando SIGUSR1)...");

    // 2. Verificação de robustez: Configuração do Dnsmasq deve existir
    if !std::path::Path::new(DNSMASQ_CONFIG).exists() {
        error!(
            "CRÍTICO: Arquivo de configuração {} não encontrado. Abortando.",
            DNSMASQ_CONFIG
        );
        std::process::exit(1);
    }

    // 3. Configurar handler de sinal SIGUSR1
    let mut sigusr1 = signal(SignalKind::user_defined1())?;

    // 4. Loop principal
    loop {
        // Executa o scan imediatamente e depois espera sinal
        if let Err(e) = process_cycle().await {
            error!("Erro no ciclo de processamento: {:?}", e);
        }

        info!("Ciclo concluído. Aguardando sinal SIGUSR1 para próximo scan...");
        sigusr1.recv().await;
        info!("Sinal SIGUSR1 recebido! Iniciando scan...");
    }
}

async fn process_cycle() -> Result<()> {
    // Leases podem não existir logo após boot, isso é recuperável (apenas warning)
    let mac_map = get_mac_hostname_map().unwrap_or_else(|e| {
        warn!("Não foi possível ler leases (pode ser temporário): {}", e);
        HashMap::new()
    });

    if mac_map.is_empty() {
        // Apenas log de debug/info, pois pode ser normal em um sistema recém-iniciado
        info!("Nenhum lease encontrado no momento.");
    }

    let static_suffixes = get_static_suffixes().unwrap_or_else(|e| {
        warn!("Falha ao ler {}: {}", DNSMASQ_CONFIG, e);
        HashMap::new()
    });

    let neighbors = get_ipv6_neighbors().await?;

    let mut new_lines = HashSet::new();

    for (ip, mac) in neighbors {
        let mac_norm = mac.to_lowercase();

        if let Some(hostname) = mac_map.get(&mac_norm) {
            // Hostname já vem minúsculo do get_mac_hostname_map
            let is_static_ip = if let Some(suffix) = static_suffixes.get(&mac_norm) {
                // Checa se o final do IP bate com o sufixo configurado
                let clean_suffix = suffix.trim_matches(|c| c == '[' || c == ']');
                ip.ends_with(clean_suffix)
            } else {
                false
            };

            let entry = if is_static_ip {
                format!("{} {}", ip, hostname)
            } else {
                format!("{} {} {}-slaac", ip, hostname, hostname)
            };
            new_lines.insert(entry);
        }
    }

    update_file_if_changed(new_lines)?;
    Ok(())
}

fn get_mac_hostname_map() -> Result<HashMap<String, String>> {
    let file =
        File::open(LEASES_FILE).with_context(|| format!("Falha ao abrir {}", LEASES_FILE))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let mac = parts[1].to_string().to_lowercase();
            let hostname = parts[3].to_string().to_lowercase();
            if hostname != "*" {
                map.insert(mac, hostname);
            }
        }
    }
    Ok(map)
}

fn get_static_suffixes() -> Result<HashMap<String, String>> {
    let file =
        File::open(DNSMASQ_CONFIG).with_context(|| format!("Falha ao abrir {}", DNSMASQ_CONFIG))?;
    let reader = BufReader::new(file);
    let mut map = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if !line.starts_with("dhcp-host=") {
            continue;
        }

        // Ex: dhcp-host=e0:d5:5e:e2:d4:89,[::1057:cafe],192.168.0.2,Archie,infinite
        let content = line.trim_start_matches("dhcp-host=");
        let parts: Vec<&str> = content.split(',').collect();

        // Precisamos encontrar MAC e Sufixo IPv6
        let mut mac = None;
        let mut ipv6_suffix = None;

        for part in parts {
            let part = part.trim();
            // Heurística simples:
            // MAC tem : e não tem [] (len 17 tipicamente, mas pode variar)
            // IPv6 sufixo tem [] ou pelo menos :
            if part.contains(':') && !part.contains('[') && part.len() == 17 {
                mac = Some(part.to_lowercase());
            } else if part.starts_with('[') && part.ends_with(']') {
                ipv6_suffix = Some(part.to_string());
            }
        }

        if let (Some(m), Some(s)) = (mac, ipv6_suffix) {
            map.insert(m, s);
        }
    }
    Ok(map)
}

async fn get_ipv6_neighbors() -> Result<Vec<(String, String)>> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut neighbors = Vec::new();
    let mut stream = handle
        .neighbours()
        .get()
        .set_family(IpVersion::V6)
        .execute();

    while let Some(msg) = stream.try_next().await? {
        if let Some((ip, mac)) = parse_neighbor(msg)
            && ip.starts_with(TARGET_PREFIX)
        {
            neighbors.push((ip, mac));
        }
    }

    Ok(neighbors)
}

fn parse_neighbor(msg: NeighbourMessage) -> Option<(String, String)> {
    // CORREÇÃO 1: Usar bitflags methods para verificar o estado
    // Ignora se for INCOMPLETE ou FAILED
    if msg.header.state == NeighbourState::Incomplete || msg.header.state == NeighbourState::Failed
    {
        return None;
    }

    let mut ip_str = String::new();
    let mut mac_str = String::new();

    for attr in msg.attributes {
        match attr {
            // CORREÇÃO 2: Extrair IP do enum NeighbourAddress
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(ipv6)) => {
                ip_str = ipv6.to_string();
            }
            // CORREÇÃO 3: Nome correto da variante é LinkLocalAddress
            NeighbourAttribute::LinkLocalAddress(mac_bytes) => {
                mac_str = mac_bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(":");
            }
            _ => {}
        }
    }

    if !ip_str.is_empty() && !mac_str.is_empty() {
        Some((ip_str, mac_str))
    } else {
        None
    }
}

fn update_file_if_changed(new_lines: HashSet<String>) -> Result<()> {
    let mut old_lines = HashSet::new();

    if std::path::Path::new(OUTPUT_FILE).exists()
        && let Ok(file) = File::open(OUTPUT_FILE)
    {
        for l in BufReader::new(file).lines().map_while(Result::ok) {
            old_lines.insert(l.trim().to_string());
        }
    }

    let added: Vec<_> = new_lines.difference(&old_lines).collect();
    let removed: Vec<_> = old_lines.difference(&new_lines).collect();

    if !added.is_empty() {
        info!("Changes detected. Adding:");
        for item in &added {
            info!("+ {}", item);
        }
    }
    if !removed.is_empty() {
        info!("Changes detected. Removing:");
        for item in &removed {
            info!("- {}", item);
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        info!("Updating file and reloading dnsmasq...");

        let mut content = new_lines.clone().into_iter().collect::<Vec<_>>();
        content.sort();

        let mut file = File::create(OUTPUT_FILE).context("Erro ao gravar arquivo de hosts")?;
        for line in &content {
            writeln!(file, "{}", line)?;
        }

        reload_dnsmasq();
    } else {
        info!("No changes detected - file would remain unchanged");
    }
    Ok(())
}

fn reload_dnsmasq() {
    let mut system = System::new_all();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let sent_signal = system.processes_by_name("dnsmasq".as_ref()).any(|process| {
        if process.name() == "dnsmasq" {
            info!("Sending SIGHUP to dnsmasq (PID: {})", process.pid());
            process.kill_with(Signal::Hangup).unwrap_or(false)
        } else {
            false
        }
    });

    if sent_signal {
        info!("Signal sent successfully.");
    } else {
        warn!("Could not find dnsmasq process to reload.");
    }
}
