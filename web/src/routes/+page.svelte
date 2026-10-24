<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { formatBytes, formatBps, formatIpv6Prefix, createPolling } from "$lib/utils";
	import {
		status,
		dnsStats,
		leases,
		listDevices,
		scan,
		dnsAnalytics,
		trafficTelemetry,
	} from "$lib/api/client";
	import {
		normalizeServices,
		type StatusResponse,
		type DnsStatsResponse,
		type DnsAnalyticsResponse,
		type DhcpLease,
		type DeviceEntry,
		type ServiceBanner,
		type TrafficTelemetryResponse,
	} from "$lib/api/types";
	import Sparkline from "$lib/components/ui/sparkline.svelte";
	import TrafficActivityChart from "$lib/components/TrafficActivityChart.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatusDot from "$lib/components/StatusDot.svelte";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";

	let statusData = $state<StatusResponse | null>(null);
	let dnsData = $state<DnsStatsResponse | null>(null);
	let leasesData = $state<DhcpLease[] | null>(null);
	let devicesData = $state<{
		devices: DeviceEntry[];
		meta?: { total: number; online: number; last_scan_secs_ago: number };
	} | null>(null);
	let analyticsData = $state<DnsAnalyticsResponse | null>(null);
	let telemetryData = $state<TrafficTelemetryResponse | null>(null);
	let loadingData = $state(true);
	let scanning = $state(false);

	async function loadAll() {
		loadingData = true;
		try {
			const [s, dns, ls, dev, aRes, telem] = await Promise.allSettled([
				status(),
				dnsStats(),
				leases(),
				listDevices(),
				dnsAnalytics(10),
				trafficTelemetry(),
			]);
			if (s.status === "fulfilled") statusData = s.value;
			if (dns.status === "fulfilled") dnsData = dns.value;
			if (ls.status === "fulfilled") {
				leasesData = ls.value;
			}
			if (dev.status === "fulfilled") {
				devicesData = dev.value;
			}
			if (aRes.status === "fulfilled") {
				analyticsData = aRes.value;
			}
			if (telem.status === "fulfilled") {
				telemetryData = telem.value;
			}
		} finally {
			loadingData = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await scan();
			await loadAll();
			toast.success("Network status and devices refreshed");
		} catch {
			toast.error("Failed to refresh network data");
		} finally {
			scanning = false;
		}
	}

	onMount(() => {
		loadAll();
		return createPolling(() => {
			trafficTelemetry()
				.then((t) => {
					telemetryData = t;
				})
				.catch(() => {});
		}, 2500);
	});

	const rssBytes = $derived(
		statusData?.resources?.memory_rss_bytes ??
			statusData?.resources?.rss_bytes ??
			0,
	);
	const vmsBytes = $derived(
		statusData?.resources?.memory_vms_bytes ??
			statusData?.resources?.vms_bytes ??
			0,
	);

	const onlineDevicesCount = $derived.by(() => {
		if (!devicesData) return 0;
		if (devicesData.meta?.online !== undefined)
			return devicesData.meta.online;
		return devicesData.devices?.filter((d) => d.online).length ?? 0;
	});

	const totalDevicesCount = $derived.by(() => {
		if (!devicesData) return 0;
		if (devicesData.meta?.total !== undefined)
			return devicesData.meta.total;
		return devicesData.devices?.length ?? 0;
	});

	const dnsSparkline = $derived.by(() => {
		const points = analyticsData?.query_rate?.map((r) => r.count) ?? [];
		if (points.length > 0) return points.slice(-16);
		return [120, 140, 180, 220, 190, 260, 310, 290, 340, 380, 420, 390, 450, 480, 520, 500];
	});

	const devicesSparkline = $derived.by(() => {
		const c = onlineDevicesCount;
		if (c === 0) return [0, 0, 0, 0, 0, 0];
		return [
			Math.max(1, c - 2),
			Math.max(1, c - 1),
			Math.max(1, c - 1),
			c,
			Math.max(1, c - 1),
			c,
			c,
			c,
		];
	});

	const leasesSparkline = $derived.by(() => {
		const c = leasesData?.length ?? 0;
		if (c === 0) return [0, 0, 0, 0, 0, 0];
		return [
			Math.max(1, c - 3),
			Math.max(1, c - 2),
			Math.max(1, c - 1),
			c,
			Math.max(1, c - 1),
			c,
			c,
		];
	});

	const gatewayTraffic = $derived.by(() => {
		const wan = telemetryData?.wan_interface;
		if (wan) {
			const found = telemetryData?.interfaces?.find((i) => i.interface === wan);
			if (found) {
				return { rx: found.rx_rate_bps, tx: found.tx_rate_bps };
			}
		}
		// Fallback: sum across physical interfaces (excluding ifb* and veth*)
		let rx = 0;
		let tx = 0;
		for (const i of telemetryData?.interfaces ?? []) {
			if (i.interface.startsWith("ifb") || i.interface.startsWith("veth")) continue;
			rx += i.rx_rate_bps;
			tx += i.tx_rate_bps;
		}
		return { rx, tx };
	});

	const totalRxBps = $derived(gatewayTraffic.rx);
	const totalTxBps = $derived(gatewayTraffic.tx);
	const totalTrafficBps = $derived(totalRxBps + totalTxBps);
	const conntrack = $derived(telemetryData?.conntrack);

	const trafficSparkline = $derived.by(() => {
		const mbps = totalTrafficBps > 0 ? Math.round(totalTrafficBps / 1_000_000) : 12;
		return [
			Math.max(1, mbps * 0.6),
			Math.max(1, mbps * 0.8),
			Math.max(1, mbps * 0.7),
			Math.max(1, mbps * 1.1),
			Math.max(1, mbps * 0.9),
			Math.max(1, mbps * 1.0),
			Math.max(1, mbps * 1.2),
			Math.max(1, mbps),
		];
	});

	const conntrackSparkline = $derived.by(() => {
		const c = conntrack?.active_connections ?? 42;
		return [
			Math.max(1, c - 10),
			Math.max(1, c - 5),
			Math.max(1, c - 8),
			c,
			Math.max(1, c - 4),
			c,
			c,
			c,
		];
	});

	const statCards = $derived([
		{
			label: "Active Devices",
			value: devicesData
				? `${onlineDevicesCount} / ${totalDevicesCount}`
				: null,
			subtext: devicesData
				? `${onlineDevicesCount} online on LAN`
				: "LAN host activity",
			icon: WifiIcon,
			color: "emerald" as const,
			sparklineData: devicesSparkline,
			sparklineColor: "#10b981",
			href: "/network/devices",
		},
		{
			label: "DHCP Leases",
			value: leasesData ? leasesData.length.toString() : null,
			subtext: "Active IPv4/v6 leases",
			icon: NetworkIcon,
			color: "teal" as const,
			sparklineData: leasesSparkline,
			sparklineColor: "#14b8a6",
			href: "/dhcp/leases",
		},
		{
			label: "DNS Queries",
			value: dnsData ? dnsData.total_requests.toLocaleString() : null,
			subtext: dnsData
				? `${dnsData.cache_hits.toLocaleString()} cache hits`
				: "Total requests",
			icon: GlobeIcon,
			color: "sky" as const,
			sparklineData: dnsSparkline,
			sparklineColor: "#0ea5e9",
			href: "/dns/resolver",
		},
		{
			label: "Firewall Conntrack",
			value: conntrack
				? `${conntrack.active_connections.toLocaleString()} / ${conntrack.max_connections.toLocaleString()}`
				: null,
			subtext: conntrack
				? `${conntrack.utilization_percent.toFixed(1)}% session capacity`
				: "Active stateful sessions",
			icon: ShieldCheckIcon,
			color: "violet" as const,
			sparklineData: conntrackSparkline,
			sparklineColor: "#8b5cf6",
			href: "/firewall",
		},
	]);

	const liveBanners = $derived(normalizeServices(statusData));
	const bannersMap = $derived.by(() => {
		const m = new Map<string, ServiceBanner>();
		for (const b of liveBanners) {
			if (b.id) m.set(b.id.toLowerCase(), b);
			m.set(b.name.toLowerCase(), b);
		}
		return m;
	});

	function getBanner(id: string, name: string): ServiceBanner | undefined {
		return bannersMap.get(id.toLowerCase()) ?? bannersMap.get(name.toLowerCase());
	}

	const subsystemServices = [
		{
			id: "ra",
			name: "IPv6 Router Advertisements",
			tag: "RADVD / SLAAC",
			proto: "ICMPv6 (NDP)",
			desc: "Autoconfiguration prefix announcements (GUA/ULA)",
			href: "/network/ra",
		},
		{
			id: "dhcpv4",
			name: "DHCPv4 Server",
			tag: "Dynamic Leases",
			proto: "UDP Port 67",
			desc: "IPv4 address allocation with option 3 (gateway) & 6 (DNS)",
			href: "/dhcp/server",
		},
		{
			id: "dhcpv6",
			name: "DHCPv6 Server",
			tag: "Stateful / Stateless",
			proto: "UDP Port 547",
			desc: "IPv6 stateful address & prefix delegation",
			href: "/dhcp/pools",
		},
		{
			id: "dns",
			name: "DNS Resolver & Engine",
			tag: "DNS Cache & Block",
			proto: "UDP/TCP Port 53",
			desc: "Upstream recursive forwarding, cache, & adblock filtering",
			href: "/dns/resolver",
		},
		{
			id: "tftp",
			name: "Bootstrapping TFTP",
			tag: "PXE Boot",
			proto: "UDP Port 69",
			desc: "Network boot firmware & image distribution server",
			href: "/tftp",
		},
		{
			id: "pppoe",
			name: "PPPoE Concentrator",
			tag: "Relay / Tunnel",
			proto: "PPPoverEthernet",
			desc: "DSL/FTTH encapsulation & point-to-point tunneling",
			href: "/network/pppoe",
		},
		{
			id: "monitor",
			name: "Neighbor Monitor",
			tag: "Passive / Netlink",
			proto: "Kernel Netlink",
			desc: "Real-time L2/L3 neighbor discovery and device tracking",
			href: "/network/devices",
		},
	];
</script>

<svelte:head>
	<title>Dashboard — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5 sm:gap-6">
	<!-- Page Header -->
	<PageHeader
		title="Router Dashboard"
		description="Network status, DHCP leases, DNS activity, and connected devices"
		icon={MonitorIcon}
	>
		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				onclick={loadAll}
				disabled={loadingData}
				class="h-8 text-xs gap-1.5"
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={loadingData ? "animate-spin size-3.5" : "size-3.5"}
				/>
				Refresh
			</Button>
			<Button size="sm" onclick={triggerScan} disabled={scanning} class="h-8 text-xs gap-1.5">
				{#if scanning}
					<span
						class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
						data-icon="inline-start"
					></span>
				{:else}
					<ZapIcon data-icon="inline-start" class="size-3.5" />
				{/if}
				Scan Network
			</Button>
		{/snippet}
	</PageHeader>

	<!-- Top Stat Cards (Core Router Metrics) -->
	<StatCardGrid cols={4}>
		{#each statCards as card (card.label)}
			<StatCard
				label={card.label}
				value={card.value}
				subtext={card.subtext}
				icon={card.icon}
				color={card.color}
				href={card.href}
				sparkline={{ data: card.sparklineData, color: card.sparklineColor, height: 28 }}
				loading={loadingData || card.value === null}
			/>
		{/each}
	</StatCardGrid>

	<!-- Gateway Network Activity Hero Chart -->
	<TrafficActivityChart
		loading={loadingData}
		showDnsToggle={true}
		title="Real-Time Bandwidth & Throughput"
		{analyticsData}
		{statusData}
		{dnsData}
		{telemetryData}
	/>

	<!-- Main Grid: Subsystem Overview (2 Cols) + Network & System Vitals (1 Col) -->
	<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
		<!-- Left Main Panel: Router Service Health -->
		<Card.Root class="flex flex-col lg:col-span-2">
			<Card.Header class="p-4 py-3 border-b border-border/50">
				<div class="flex items-center justify-between gap-2 min-w-0">
					<div class="flex items-center gap-2 min-w-0">
						<ActivityIcon class="size-4 text-emerald-400 shrink-0" />
						<Card.Title class="text-sm sm:text-base font-semibold truncate">
							Service Status<span class="hidden md:inline">&nbsp;& Runtime Health</span>
						</Card.Title>
					</div>
					<div class="flex items-center gap-2 shrink-0">
						<a
							href="/system/services"
							class="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1 font-medium"
						>
							<span>All Daemons</span>
							<ArrowRightIcon class="size-3" />
						</a>
					</div>
				</div>
			</Card.Header>
			<Card.Content class="p-3 divide-y divide-border/40">
				{#each subsystemServices as svc (svc.name)}
					{@const banner = getBanner(svc.id, svc.name)}
					<div class="flex items-center justify-between py-2.5 px-2 hover:bg-muted/20 rounded-md transition-colors">
						<div class="flex items-center gap-3 min-w-0">
							<StatusDot state={banner?.state ?? "online"} size="sm" />
							<div class="flex flex-col min-w-0">
								<div class="flex items-center gap-2">
									<a href={svc.href} class="text-xs font-semibold text-foreground hover:text-primary transition-colors truncate">
										{svc.name}
									</a>
									<Badge variant="outline" class="text-[9px] font-mono px-1 py-0 hidden sm:inline-flex">
										{svc.tag}
									</Badge>
								</div>
								<span class="text-[11px] text-muted-foreground truncate">{svc.desc}</span>
							</div>
						</div>

						<div class="flex items-center gap-3 shrink-0 font-mono text-[11px]">
							<span class="text-muted-foreground text-[10px] hidden md:inline">
								{#if banner?.stats?.leases_active}
									{banner.stats.leases_active} leases
								{:else if banner?.stats?.cache_hit_rate}
									Hit: {banner.stats.cache_hit_rate}
								{:else if banner?.stats?.state}
									{banner.stats.state}
								{:else}
									{svc.proto}
								{/if}
							</span>
							<Badge
								variant={banner?.state === "online" || banner?.state === "active" ? "secondary" : "outline"}
								class="text-[10px] capitalize font-mono"
							>
								{banner?.state ?? "active"}
							</Badge>
						</div>
					</div>
				{/each}
			</Card.Content>
		</Card.Root>

		<!-- Right Main Panel: Network Vitals & Host Overview -->
		<Card.Root class="flex flex-col lg:col-span-1">
			<Card.Header class="p-4 py-3 border-b border-border/50">
				<div class="flex items-center gap-2 min-w-0">
					<CpuIcon class="size-4 text-purple-400 shrink-0" />
					<Card.Title class="text-sm sm:text-base font-semibold truncate">Network & Vitals</Card.Title>
				</div>
			</Card.Header>
			<Card.Content class="flex flex-1 flex-col gap-4 p-5 text-xs">
				{#if loadingData}
					<div class="flex flex-col gap-3">
						<Skeleton class="h-10 w-full" />
						<Skeleton class="h-10 w-full" />
						<Skeleton class="h-10 w-full" />
					</div>
				{:else}
					<!-- Interface & IPv4 -->
					<div
						class="flex flex-col gap-1.5 rounded-lg border border-border/60 bg-muted/20 p-3"
					>
						<div class="flex items-center justify-between">
							<span class="text-muted-foreground font-medium"
								>LAN Interface</span
							>
							<Badge variant="outline" class="font-mono text-[10px]"
								>{statusData?.network?.lan_iface || "eth0"}</Badge
							>
						</div>
						<div class="flex items-center justify-between font-mono">
							<span class="text-muted-foreground">IPv4 Gateway</span>
							<span class="text-emerald-400 font-semibold"
								>{statusData?.network?.lan_ipv4 || "192.168.1.1"}</span
							>
						</div>
					</div>

					<!-- IPv6 Prefixes -->
					<div
						class="flex flex-col gap-1.5 rounded-lg border border-border/60 bg-muted/20 p-3"
					>
						<span class="text-muted-foreground font-medium"
							>IPv6 Prefixes</span
						>
						<div class="flex justify-between font-mono text-[11px]">
							<span class="text-muted-foreground">GUA</span>
							<span class="text-sky-400 truncate max-w-[170px]" title={formatIpv6Prefix(statusData?.network?.gua)}
								>{formatIpv6Prefix(statusData?.network?.gua)}</span
							>
						</div>
						<div class="flex justify-between font-mono text-[11px]">
							<span class="text-muted-foreground">ULA</span>
							<span class="text-purple-400 truncate max-w-[170px]" title={formatIpv6Prefix(statusData?.network?.ula)}
								>{formatIpv6Prefix(statusData?.network?.ula)}</span
							>
						</div>
					</div>

					<!-- Database Engine -->
					<div
						class="flex flex-col gap-1.5 rounded-lg border border-border/60 bg-muted/20 p-3"
					>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-1.5">
								<DatabaseIcon class="size-3.5 text-amber-400" />
								<span class="text-muted-foreground font-medium"
									>Database Storage</span
								>
							</div>
							<Badge
								variant="secondary"
								class="text-[10px] uppercase font-mono"
							>
								redb
							</Badge>
						</div>
						<div class="flex items-center justify-between font-mono text-[11px]">
							<span class="text-muted-foreground">Footprint</span>
							<span class="text-foreground font-medium">
								{statusData?.db?.size_bytes ? formatBytes(statusData.db.size_bytes) : "—"}
							</span>
						</div>
						<div class="flex items-center justify-between font-mono text-[11px]">
							<span class="text-muted-foreground">Last Disk Sync</span>
							<span class="text-emerald-400 font-medium">
								{statusData?.db?.last_flush_secs_ago !== undefined ? `${statusData.db.last_flush_secs_ago}s ago` : "—"}
							</span>
						</div>
					</div>

					<!-- Process Memory -->
					<div
						class="flex flex-col gap-1.5 rounded-lg border border-border/60 bg-muted/20 p-3"
					>
						<div class="flex items-center justify-between">
							<span class="text-muted-foreground font-medium"
								>Process Memory (RSS / VMS)</span
							>
						</div>
						<div class="flex items-center justify-between font-mono">
							<span class="text-foreground font-bold"
								>{formatBytes(rssBytes)}</span
							>
							<span class="text-muted-foreground text-[11px]"
								>VMS: {formatBytes(vmsBytes)}</span
							>
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
</div>
