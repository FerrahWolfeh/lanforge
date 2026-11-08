//! Offline core workloads. Run timing and allocation profiling in separate processes.
#![allow(
    unused_crate_dependencies,
    reason = "benchmark targets see every daemon dependency"
)]

mod services;

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, ensure};
use clap::{Parser, ValueEnum};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_types::device::{IPv4State, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate, InterfaceState};
use serde_json::{Value, json};

#[cfg(feature = "hotpath-alloc")]
#[global_allocator]
static ALLOC: hotpath::CountingAllocator = hotpath::CountingAllocator::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Scenario {
    New,
    Renew,
    Arp,
    Ndp,
    Batch,
    Lookup,
    Snapshot,
    HeldSnapshot,
    Contended,
    Renumber,
    Dns,
    DnsBusy,
    Dhcp,
}

#[derive(Parser)]
struct Args {
    #[arg(long, default_value_t = 50, value_parser = clap::value_parser!(u32).range(2..=5000))]
    devices: u32,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=100000))]
    iterations: u32,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=10000))]
    warmup: u32,
    #[arg(long, value_enum, default_value = "renew")]
    scenario: Scenario,
    #[arg(skip)]
    names: Vec<String>,
}

fn mac(index: u32) -> MacAddr {
    let b = index.to_be_bytes();
    MacAddr([2, 0, b[0], b[1], b[2], b[3]])
}

fn ip(index: u32) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(Ipv4Addr::new(10, 10, 0, 2)) + index)
}

fn v6(index: u32) -> Ipv6Addr {
    Ipv6Addr::from(
        u128::from(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0)) + u128::from(index) + 2,
    )
}

fn lease(index: u32, epoch: SystemTime, sequence: u32) -> DeviceUpdate {
    DeviceUpdate::V4LeaseGranted {
        mac: mac(index),
        ip: ip(index),
        expires: epoch + Duration::from_secs(3600 + u64::from(sequence)),
    }
}

fn interface(generation: u32) -> InterfaceState {
    InterfaceState {
        v4: Some((Ipv4Addr::new(10, 10, 0, 1), 16)),
        link_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        gua: Some(Ipv6Addr::new(
            0x2001,
            0xdb8,
            1 + u16::try_from(generation % 2).expect("parity fits"),
            0,
            0,
            0,
            0,
            1,
        )),
        ula: Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        gua_preferred: 3600,
        gua_valid: 7200,
        mac: Some(MacAddr([2, 0, 0, 0, 0, 1])),
    }
}

fn setup(args: &Args, epoch: SystemTime) -> LanforgeContext {
    let ctx = LanforgeContext::new(Arc::new(EventBus::new()), State::new(), Some(2));
    ctx.set_target_interface_name("benchmark0".to_string());
    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex: 2,
        state: Box::new(interface(0)),
    });
    // Seed through the same entry point services use, with one copy for the entire fixture.
    let _ = ctx.apply_batch((0..args.devices).flat_map(|index| {
        [
            lease(index, epoch, 0),
            DeviceUpdate::DhcpHostnameHint {
                mac: mac(index),
                hostname: format!("host-{index}"),
            },
            DeviceUpdate::SlaacObserved {
                mac: mac(index),
                addr: v6(index),
                is_active: true,
            },
        ]
    }));
    if args.scenario == Scenario::Renumber {
        let _ = ctx.apply_batch((0..args.devices).map(|index| DeviceUpdate::CliHostUpdated {
            mac: mac(index),
            update: Box::new(CliHostUpdate {
                origin: Origin::Static,
                v6_suffix: FieldUpdate::Set(
                    format!("::{:x}", index + 2).parse().expect("valid suffix"),
                ),
                ..Default::default()
            }),
        }));
    }
    ctx
}

#[cfg_attr(feature = "hotpath", hotpath::measure)]
fn operation(ctx: &LanforgeContext, args: &Args, epoch: SystemTime, sequence: u32) {
    let index = sequence % args.devices;
    match args.scenario {
        Scenario::New => {
            black_box(ctx.apply(lease(args.devices + sequence, epoch, sequence)));
        }
        Scenario::Renew | Scenario::HeldSnapshot => {
            black_box(ctx.apply(lease(index, epoch, sequence)));
        }
        Scenario::Arp => {
            black_box(ctx.apply(DeviceUpdate::ArpSeen {
                mac: mac(index),
                ip: ip(index),
                is_active: true,
            }));
        }
        Scenario::Ndp => {
            black_box(ctx.apply(DeviceUpdate::NdpSeen {
                mac: mac(index),
                ip: v6(index),
                is_active: true,
            }));
        }
        Scenario::Batch => {
            black_box(ctx.apply_batch(
                (0..32).map(|offset| lease((index + offset) % args.devices, epoch, sequence)),
            ));
        }
        Scenario::Lookup => {
            black_box(ctx.get_by_hostname(&args.names[index as usize]));
        }
        Scenario::Snapshot => {
            black_box(ctx.snapshot_for_persistence());
        }
        Scenario::Renumber => {
            black_box(ctx.apply(DeviceUpdate::InterfaceIpsChanged {
                ifindex: 2,
                state: Box::new(interface(sequence)),
            }));
        }
        Scenario::Contended | Scenario::Dns | Scenario::DnsBusy | Scenario::Dhcp => {
            unreachable!("separate runner")
        }
    }
}

fn measured(ctx: &LanforgeContext, args: &Args, epoch: SystemTime) -> Vec<u64> {
    let mut samples = Vec::with_capacity(args.iterations as usize);
    for sequence in args.warmup..args.warmup + args.iterations {
        let started = Instant::now();
        operation(ctx, args, epoch, sequence);
        samples.push(u64::try_from(started.elapsed().as_nanos()).expect("sample fits u64"));
    }
    samples
}

fn validate(ctx: &LanforgeContext, args: &Args, epoch: SystemTime) -> Result<()> {
    let last = args.warmup + args.iterations - 1;
    let count = ctx.with_state(|state| state.devices.len());
    let expected = args.devices
        + if args.scenario == Scenario::New {
            args.warmup + args.iterations
        } else {
            0
        };
    ensure!(
        count == expected as usize,
        "unexpected device count: {count} != {expected}"
    );
    let index = if args.scenario == Scenario::New {
        args.devices + last
    } else {
        last % args.devices
    };
    let device = ctx.get_device(&mac(index)).expect("fixture device exists");
    if matches!(
        args.scenario,
        Scenario::New | Scenario::Renew | Scenario::HeldSnapshot | Scenario::Batch
    ) {
        let IPv4State::Dynamic(ref binding) = device.v4 else {
            anyhow::bail!("missing lease");
        };
        ensure!(binding.ip == ip(index), "incorrect lease IP");
        ensure!(
            SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(binding.expires))
                == epoch + Duration::from_secs(3600 + u64::from(last)),
            "lease expiry was not updated"
        );
    }
    ensure!(
        ctx.get_by_hostname("host-0").is_some(),
        "hostname index lost fixture"
    );
    if args.scenario == Scenario::Renumber {
        ctx.with_state(|state| {
            assert_eq!(
                state.interfaces.interface_ips.get(&2),
                Some(&interface(last))
            )
        });
        let prefix = interface(last).gua.expect("GUA configured");
        let address = Ipv6Addr::from((u128::from(prefix) & (!0_u128 << 64)) | 2);
        ensure!(
            ctx.get_by_ip(&IpAddr::V6(address)).is_some(),
            "new prefix not indexed"
        );
    }
    Ok(())
}

fn stats(mut samples: Vec<u64>) -> Value {
    samples.sort_unstable();
    let n = samples.len();
    let percentile = |p: usize| samples[(n * p).div_ceil(100).saturating_sub(1)];
    let total: u64 = samples.iter().sum();
    json!({"samples": n, "p50_ns": percentile(50), "p95_ns": percentile(95), "p99_ns": percentile(99),
        "mean_ns": total as f64 / n as f64, "sampled_ops_per_sec": n as f64 * 1e9 / total as f64})
}

fn contended(ctx: &LanforgeContext, args: &Args, epoch: SystemTime) -> Value {
    let start = Arc::new(Barrier::new(4));
    thread::scope(|scope| {
        let writers: Vec<_> = (0..2)
            .map(|writer| {
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    let mut samples = Vec::with_capacity(args.iterations as usize);
                    start.wait();
                    for sequence in 1..=args.iterations {
                        let index = (sequence * 2 + writer) % args.devices;
                        let now = Instant::now();
                        let _ = ctx.apply(lease(index, epoch, sequence));
                        samples.push(u64::try_from(now.elapsed().as_nanos()).expect("sample fits"));
                    }
                    samples
                })
            })
            .collect();
        let persistence_start = Arc::clone(&start);
        let persistence = scope.spawn(move || {
            persistence_start.wait();
            for _ in 0..args.iterations.div_ceil(10) {
                let snapshot = ctx.snapshot_for_persistence();
                assert_eq!(snapshot.devices.len(), args.devices as usize);
                black_box(snapshot);
                thread::yield_now();
            }
        });
        let mut reads = Vec::with_capacity(args.iterations as usize);
        start.wait();
        for sequence in 0..args.iterations {
            let index = sequence % args.devices;
            let now = Instant::now();
            let found = ctx.get_by_ip(&IpAddr::V4(ip(index)));
            reads.push(u64::try_from(now.elapsed().as_nanos()).expect("sample fits"));
            assert_eq!(found.expect("indexed device").mac, mac(index));
        }
        let writes: Vec<_> = writers
            .into_iter()
            .flat_map(|task| task.join().expect("writer completed"))
            .collect();
        persistence.join().expect("snapshot reader completed");
        json!({"reader": stats(reads), "writer": stats(writes), "writers": 2, "snapshot_reads": args.iterations.div_ceil(10)})
    })
}

#[cfg(feature = "hotpath")]
fn start_profile() -> Option<hotpath::HotpathGuard> {
    Some(
        hotpath::HotpathGuardBuilder::new("core_baseline")
            .percentiles(&[50.0, 95.0, 99.0])
            .functions_limit(0)
            .build(),
    )
}

#[cfg(not(feature = "hotpath"))]
const fn start_profile() -> Option<()> {
    None
}

fn main() -> Result<()> {
    let mut args = Args::parse();
    args.names = (0..args.devices)
        .map(|index| format!("host-{index}"))
        .collect();
    // Whole-second epoch makes expiry verification independent of record timestamp precision.
    let epoch = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    let ctx = setup(&args, epoch);
    let is_service = matches!(
        args.scenario,
        Scenario::Dns | Scenario::DnsBusy | Scenario::Dhcp
    );
    if !is_service && args.scenario != Scenario::Contended {
        for sequence in 0..args.warmup {
            operation(&ctx, &args, epoch, sequence);
        }
    }
    let _guard = if is_service { None } else { start_profile() };
    let started = Instant::now();
    let measurements = if is_service {
        services::run(&ctx, &args)?
    } else if args.scenario == Scenario::Contended {
        contended(&ctx, &args, epoch)
    } else {
        let samples = if args.scenario == Scenario::HeldSnapshot {
            ctx.with_state(|held| {
                let before = held.devices[&mac(0)].v4.clone();
                let samples = measured(&ctx, &args, epoch);
                assert_eq!(held.devices[&mac(0)].v4, before, "old snapshot changed");
                samples
            })
        } else {
            measured(&ctx, &args, epoch)
        };
        validate(&ctx, &args, epoch)?;
        stats(samples)
    };
    let elapsed = started.elapsed();
    println!(
        "{}",
        json!({"scenario": format!("{:?}", args.scenario), "devices": args.devices,
        "iterations": args.iterations, "warmup": args.warmup, "batch_size": if args.scenario == Scenario::Batch {32} else {1},
        "hotpath": cfg!(feature = "hotpath"), "alloc": cfg!(feature = "hotpath-alloc"),
        "elapsed_ns": elapsed.as_nanos(), "measurements": measurements})
    );
    Ok(())
}
