<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import {
		status,
		dnsStats,
		leases,
		listDevices,
		hostList,
		scan,
	} from "$lib/api/client";
	import {
		normalizeServices,
		type StatusResponse,
		type DnsStatsResponse,
		type DhcpLease,
		type DeviceEntry,
		type HostConfigEntry,
		type ServiceBanner,
	} from "$lib/api/types";
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
	import ServerIcon from "@lucide/svelte/icons/server";

	let statusData = $state<StatusResponse | null>(null);
	let dnsData = $state<DnsStatsResponse | null>(null);
	let leasesData = $state<DhcpLease[] | null>(null);
	let devicesData = $state<{
		devices: DeviceEntry[];
		meta?: { total: number; online: number; last_scan_secs_ago: number };
	} | null>(null);
	let hostsData = $state<HostConfigEntry[] | null>(null);
	let loadingData = $state(true);
	let scanning = $state(false);

	async function loadAll() {
		loadingData = true;
		try {
			const [s, dns, ls, dev, hst] = await Promise.allSettled([
				status(),
				dnsStats(),
				leases(),
				listDevices(),
				hostList(),
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
				const raw: any = dev.value;
				const devList = Array.isArray(raw)
					? raw
					: Array.isArray(raw?.devices)
						? raw.devices
						: Array.isArray(raw?.data)
							? raw.data
							: [];
				devicesData = {
					devices: devList,
					meta: {
						total: raw?.meta?.total ?? devList.length,
						online:
							raw?.meta?.online ??
							devList.filter((d: any) => d.online).length,
						last_scan_secs_ago: 0,
					},
				};
			}
			if (hst.status === "fulfilled") {
				const raw: any = hst.value;
				hostsData = Array.isArray(raw)
					? raw
					: Array.isArray(raw?.hosts)
						? raw.hosts
						: Array.isArray(raw?.data)
							? raw.data
							: [];
			}
		} finally {
			loadingData = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await scan();
			toast.success("Network ARP & NDP active scan initiated");
			await loadAll();
		} catch {
			toast.error("Failed to initiate network scan");
		} finally {
			scanning = false;
		}
	}

	onMount(loadAll);

	function formatBytes(bytes: number): string {
		if (!bytes || bytes === 0) return "0 B";
		const k = 1024;
		const sizes = ["B", "KB", "MB", "GB"];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
	}

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
		},
		{
			label: "DHCP Leases",
			value: leasesData ? leasesData.length.toString() : null,
			subtext: "Active IPv4/v6 leases",
			icon: NetworkIcon,
			color: "text-teal-400",
			bgColor: "bg-teal-500/10 border-teal-500/20",
		},
		{
			label: "Static Hosts",
			value: hostsData ? hostsData.length.toString() : null,
			subtext: "Configured static rules",
			icon: ServerIcon,
			color: "text-amber-400",
			bgColor: "bg-amber-500/10 border-amber-500/20",
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
			href: "/network",
		},
		{
			id: "dhcpv4",
			name: "DHCPv4 Server",
			tag: "Dynamic Leases",
			proto: "UDP Port 67",
			desc: "IPv4 address allocation with option 3 (gateway) & 6 (DNS)",
			href: "/dhcp",
		},
		{
			id: "dhcpv6",
			name: "DHCPv6 Server",
			tag: "Stateful / Stateless",
			proto: "UDP Port 547",
			desc: "IPv6 stateful address & prefix delegation",
			href: "/dhcp",
		},
		{
			id: "dns",
			name: "DNS Resolver & Engine",
			tag: "DNS Cache & Block",
			proto: "UDP/TCP Port 53",
			desc: "Upstream recursive forwarding, cache, & adblock filtering",
			href: "/dns",
		},
		{
			id: "tftp",
			name: "Bootstrapping TFTP",
			tag: "PXE Boot",
			proto: "UDP Port 69",
			desc: "Network boot firmware & image distribution server",
			href: "/system",
		},
		{
			id: "pppoe",
			name: "PPPoE Concentrator",
			tag: "Relay / Tunnel",
			proto: "PPPoverEthernet",
			desc: "DSL/FTTH encapsulation & point-to-point tunneling",
			href: "/system",
		},
	];
</script>

<svelte:head>
	<title>Dashboard — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Page Header -->
	<div
		class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
	>
		<div>
			<h1 class="text-foreground text-2xl font-bold tracking-tight">
				Router Dashboard
			</h1>
			<p class="text-muted-foreground text-sm">
				Domestic homelab LAN orchestration, DHCP, DNS, & network discovery
			</p>
		</div>
		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={loadAll}
				disabled={loadingData}
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={loadingData ? "animate-spin" : ""}
				/>
				Refresh
			</Button>
			<Button size="sm" onclick={triggerScan} disabled={scanning}>
				{#if scanning}
					<span
						class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
						data-icon="inline-start"
					></span>
				{:else}
					<ZapIcon data-icon="inline-start" />
				{/if}
				Scan Network
			</Button>
		</div>
	</div>

	<!-- Top Stat Cards (4 Core Router Metrics) -->
	<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
		{#each statCards as card (card.label)}
			<Card.Root
				class="relative overflow-hidden transition-all hover:border-zinc-700"
			>
				<Card.Content class="flex flex-col gap-3 p-5">
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
					{:else}
						<div class="flex flex-col gap-0.5">
							<span
								class="text-foreground text-3xl font-bold tabular-nums tracking-tight"
							>
								{card.value}
							</span>
							<span
								class="text-muted-foreground text-xs font-medium"
							>
								{card.subtext}
							</span>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>
		{/each}
	</div>

	<!-- Main Grid: Subsystem Overview (2 Cols) + Network & System Vitals (1 Col) -->
	<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
		<!-- Left Main Panel: Router Core Subsystems -->
		<Card.Root class="flex flex-col lg:col-span-2">
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<ActivityIcon class="size-4 text-emerald-400" />
						<Card.Title class="text-base"
							>Core Subsystems & Capabilities</Card.Title
						>
					</div>
					<Badge variant="outline" class="font-mono text-[10px] uppercase">
						All Engines Operational
					</Badge>
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
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center gap-2">
					<CpuIcon class="size-4 text-purple-400" />
					<Card.Title class="text-base">Network & Vitals</Card.Title>
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
								PostgreSQL
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
