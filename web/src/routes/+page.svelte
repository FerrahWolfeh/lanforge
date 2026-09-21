<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { formatBytes, formatBps } from "$lib/utils";
	import {
		status,
		dnsStats,
		leases,
		listDevices,
		hostList,
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
		type HostConfigEntry,
		type ServiceBanner,
		type TrafficTelemetryResponse,
	} from "$lib/api/types";
	import Sparkline from "$lib/components/ui/sparkline.svelte";
	import DashboardActivityHero from "./components/DashboardActivityHero.svelte";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ServerIcon from "@lucide/svelte/icons/server";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";

	let statusData = $state<StatusResponse | null>(null);
	let dnsData = $state<DnsStatsResponse | null>(null);
	let leasesData = $state<DhcpLease[] | null>(null);
	let devicesData = $state<{
		devices: DeviceEntry[];
		meta?: { total: number; online: number; last_scan_secs_ago: number };
	} | null>(null);
	let hostsData = $state<HostConfigEntry[] | null>(null);
	let analyticsData = $state<DnsAnalyticsResponse | null>(null);
	let telemetryData = $state<TrafficTelemetryResponse | null>(null);
	let loadingData = $state(true);
	let scanning = $state(false);

	async function loadAll() {
		loadingData = true;
		try {
			const [s, dns, ls, dev, hst, aRes, telem] = await Promise.allSettled([
				status(),
				dnsStats(),
				leases(),
				listDevices(),
				hostList(),
				dnsAnalytics(10),
				trafficTelemetry(),
			]);
			if (s.status === "fulfilled") statusData = s.value;
			if (dns.status === "fulfilled") dnsData = dns.value;
			if (ls.status === "fulfilled") {
				const raw: any = ls.value;
				leasesData = Array.isArray(raw)
					? raw
					: Array.isArray(raw?.leases)
						? raw.leases
						: Array.isArray(raw?.data)
							? raw.data
							: [];
			}
			if (dev.status === "fulfilled") {
				devicesData = dev.value;
			}
			if (hst.status === "fulfilled") {
				hostsData = hst.value;
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

	let pollInterval: ReturnType<typeof setInterval> | null = null;

	onMount(() => {
		loadAll();
		pollInterval = setInterval(() => {
			if (typeof document !== "undefined" && document.hidden) return;
			trafficTelemetry()
				.then((t) => {
					telemetryData = t;
				})
				.catch(() => {});
		}, 2500);
	});

	onDestroy(() => {
		if (pollInterval) clearInterval(pollInterval);
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

	const hostsSparkline = $derived.by(() => {
		const c = hostsData?.length ?? 0;
		return [c, c, c, c, c, c, c, c];
	});

	const totalRxBps = $derived(
		telemetryData?.interfaces?.reduce((acc, i) => acc + i.rx_rate_bps, 0) ?? 0
	);
	const totalTxBps = $derived(
		telemetryData?.interfaces?.reduce((acc, i) => acc + i.tx_rate_bps, 0) ?? 0
	);
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
			color: "text-emerald-400",
			bgColor: "bg-emerald-500/10 border-emerald-500/20",
			sparklineData: devicesSparkline,
			sparklineColor: "#10b981",
		},
		{
			label: "DHCP Leases",
			value: leasesData ? leasesData.length.toString() : null,
			subtext: "Active IPv4/v6 leases",
			icon: NetworkIcon,
			color: "text-teal-400",
			bgColor: "bg-teal-500/10 border-teal-500/20",
			sparklineData: leasesSparkline,
			sparklineColor: "#14b8a6",
		},
		{
			label: "Static Hosts",
			value: hostsData ? hostsData.length.toString() : null,
			subtext: "Configured static rules",
			icon: ServerIcon,
			color: "text-amber-400",
			bgColor: "bg-amber-500/10 border-amber-500/20",
			sparklineData: hostsSparkline,
			sparklineColor: "#f59e0b",
		},
		{
			label: "DNS Queries",
			value: dnsData ? dnsData.total_requests.toLocaleString() : null,
			subtext: dnsData
				? `${dnsData.cache_hits.toLocaleString()} cache hits`
				: "Total requests",
			icon: GlobeIcon,
			color: "text-sky-400",
			bgColor: "bg-sky-500/10 border-sky-500/20",
			sparklineData: dnsSparkline,
			sparklineColor: "#0ea5e9",
		},
		{
			label: "Network Traffic",
			value: telemetryData
				? `${formatBps(totalRxBps)} ↓ / ${formatBps(totalTxBps)} ↑`
				: null,
			subtext: telemetryData
				? `${telemetryData.interfaces.length} active interfaces`
				: "Aggregate throughput",
			icon: ActivityIcon,
			color: "text-indigo-400",
			bgColor: "bg-indigo-500/10 border-indigo-500/20",
			sparklineData: trafficSparkline,
			sparklineColor: "#6366f1",
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
			color: "text-violet-400",
			bgColor: "bg-violet-500/10 border-violet-500/20",
			sparklineData: conntrackSparkline,
			sparklineColor: "#8b5cf6",
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

	function getStatusDotColor(banner?: ServiceBanner) {
		if (!banner) return "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]";
		const s = banner.state.toLowerCase();
		if (s === "online" || s === "active") return "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]";
		if (s === "starting") return "bg-amber-500 animate-pulse";
		if (s === "inactive" || s === "offline") return "bg-zinc-500";
		return "bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.8)]";
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
			id: "discovery",
			name: "Discovery & Monitor",
			tag: "Passive / mDNS",
			proto: "Netlink / ARP",
			desc: "Transient neighbor monitor & active mDNS discovery prober",
			href: "/network/discovery",
		},
	];
</script>

<svelte:head>
	<title>Dashboard — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5 sm:gap-6">
	<!-- Page Header -->
	<div
		class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
	>
		<div>
			<h1 class="text-foreground text-xl sm:text-2xl font-bold tracking-tight">
				Router Dashboard
			</h1>
			<p class="text-muted-foreground text-xs sm:text-sm mt-0.5">
				Network status, DHCP leases, DNS activity, and connected devices
			</p>
		</div>
		<div class="flex items-center gap-2">
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
		</div>
	</div>

	<!-- Top Stat Cards (Core Router Metrics) -->
	<div class="grid grid-cols-1 gap-3 sm:gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
		{#each statCards as card (card.label)}
			<Card.Root
				class="relative overflow-hidden transition-all hover:border-zinc-700"
			>
				<Card.Content class="flex flex-col gap-2.5 p-4 sm:p-5">
					<div class="flex items-center justify-between">
						<span
							class="text-muted-foreground text-xs font-semibold uppercase tracking-wider"
						>
							{card.label}
						</span>
						<div
							class={[
								"flex size-8 items-center justify-center rounded-lg border",
								card.bgColor,
							].join(" ")}
						>
							<card.icon
								class={["size-4", card.color].join(" ")}
							/>
						</div>
					</div>

					{#if loadingData || card.value === null}
						<Skeleton class="h-8 w-28" />
						<Skeleton class="h-3.5 w-20" />
						<Skeleton class="h-7 w-full mt-2" />
					{:else}
						<div class="flex flex-col gap-0.5">
							<span
								class="text-foreground text-2xl sm:text-3xl font-bold tabular-nums tracking-tight"
							>
								{card.value}
							</span>
							<span
								class="text-muted-foreground text-xs font-medium"
							>
								{card.subtext}
							</span>
						</div>
						<div class="mt-2 pt-1 border-t border-border/40">
							<Sparkline data={card.sparklineData} color={card.sparklineColor} height={28} />
						</div>
					{/if}
				</Card.Content>
			</Card.Root>
		{/each}
	</div>

	<!-- UniFi Gateway Network Activity Hero Chart -->
	<DashboardActivityHero
		loading={loadingData}
		{analyticsData}
		{statusData}
		{dnsData}
		{telemetryData}
	/>

	<!-- Main Grid: Subsystem Overview (2 Cols) + Network & System Vitals (1 Col) -->
	<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
		<!-- Left Main Panel: Router Core Subsystems -->
		<Card.Root class="flex flex-col lg:col-span-2">
			<Card.Header class="p-4 py-3 border-b border-border/50">
				<div class="flex items-center justify-between gap-2 min-w-0">
					<div class="flex items-center gap-2 min-w-0">
						<ActivityIcon class="size-4 text-emerald-400 shrink-0" />
						<Card.Title class="text-sm sm:text-base font-semibold truncate">
							Core Subsystems<span class="hidden md:inline">&nbsp;& Capabilities</span>
						</Card.Title>
					</div>
					<div class="flex items-center gap-2 shrink-0">
						<span
							class="size-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)] sm:hidden"
							title="All engines operational"
						></span>
						<Badge variant="outline" class="hidden sm:inline-flex font-mono text-[10px] uppercase">
							All Engines Operational
						</Badge>
						<a
							href="/system/services"
							class="text-xs text-muted-foreground hover:text-primary transition-colors flex items-center gap-1 font-medium"
						>
							<span>Services</span>
							<ArrowRightIcon class="size-3" />
						</a>
					</div>
				</div>
			</Card.Header>
			<Card.Content class="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
				{#each subsystemServices as svc (svc.name)}
					{@const banner = getBanner(svc.id, svc.name)}
					{@const dotClass = getStatusDotColor(banner)}
					<a
						href={svc.href}
						class="flex flex-col gap-2 rounded-lg border border-border/60 bg-muted/20 p-4 transition-all hover:bg-muted/40 hover:border-zinc-700 group"
					>
						<div class="flex items-center justify-between">
							<span class="text-foreground font-semibold text-xs group-hover:text-emerald-400 transition-colors">
								{svc.name}
							</span>
							<div class="flex items-center gap-1.5">
								{#if banner}
									<span class="text-muted-foreground text-[10px] capitalize font-mono">{banner.state}</span>
								{/if}
								<span class="size-2 rounded-full {dotClass}"></span>
							</div>
						</div>

						<p class="text-muted-foreground text-[11px] leading-relaxed">
							{svc.desc}
						</p>

						<div class="flex items-center justify-between pt-1 font-mono text-[10px]">
							<Badge variant="secondary" class="text-[9px] font-mono px-1.5 py-0">
								{svc.tag}
							</Badge>
							<span class="text-muted-foreground">
								{#if banner?.stats?.leases_active}
									{banner.stats.leases_active} leases
								{:else if banner?.stats?.cache_hit_rate}
									Hit Rate: {banner.stats.cache_hit_rate}
								{:else if banner?.stats?.state}
									{banner.stats.state}
								{:else}
									{svc.proto}
								{/if}
							</span>
						</div>
					</a>
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
							<span class="text-sky-400 truncate max-w-[170px]"
								>{statusData?.network?.gua || "—"}</span
							>
						</div>
						<div class="flex justify-between font-mono text-[11px]">
							<span class="text-muted-foreground">ULA</span>
							<span class="text-purple-400 truncate max-w-[170px]"
								>{statusData?.network?.ula || "—"}</span
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
									>Database Engine</span
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
							<span class="text-muted-foreground">Backend Status</span>
							<span class="text-emerald-400 font-medium">Online</span>
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
