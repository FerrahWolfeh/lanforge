<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { eventFeed } from "$lib/stores/events.svelte";
	import {
		status,
		dnsStats,
		leases,
		listDevices,
		hostList,
		scan,
	} from "$lib/api/client";
	import {
		formatEventPayload,
		type StatusResponse,
		type DnsStatsResponse,
		type DhcpLease,
		type DevicesResponse,
		type HostConfigEntry,
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
	let devicesData = $state<DevicesResponse | null>(null);
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
			if (ls.status === "fulfilled")
				leasesData = Array.isArray(ls.value) ? ls.value : [];
			if (dev.status === "fulfilled") devicesData = dev.value;
			if (hst.status === "fulfilled")
				hostsData = Array.isArray(hst.value) ? hst.value : [];
		} finally {
			loadingData = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await scan();
			toast.success("Network scan triggered");
		} catch {
			toast.error("Failed to trigger scan");
		} finally {
			scanning = false;
		}
	}

	onMount(loadAll);

	function formatUptime(secs: number): string {
		const d = Math.floor(secs / 86400);
		const h = Math.floor((secs % 86400) / 3600);
		const m = Math.floor((secs % 3600) / 60);
		if (d > 0) return `${d}d ${h}h`;
		if (h > 0) return `${h}h ${m}m`;
		return `${m}m`;
	}

	function formatBytes(bytes: number): string {
		if (!bytes || bytes === 0) return "0 B";
		const k = 1024;
		const sizes = ["B", "KB", "MB", "GB"];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
	}

	const recentEvents = $derived(eventFeed.events.slice(0, 12));

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

	const kindBadgeStyles: Record<string, string> = {
		DeviceOnline:
			"bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
		DeviceOffline: "bg-rose-500/15 text-rose-400 border-rose-500/30",
		DhcpLeaseGranted: "bg-teal-500/15 text-teal-400 border-teal-500/30",
		DhcpLeaseReleased: "bg-amber-500/15 text-amber-400 border-amber-500/30",
		DnsBlocked: "bg-rose-500/15 text-rose-400 border-rose-500/30",
		AdblockToggled: "bg-purple-500/15 text-purple-400 border-purple-500/30",
		ScanCompleted: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
		NetworkActivity: "bg-blue-500/15 text-blue-400 border-blue-500/30",
		NeighborBatchSummary:
			"bg-slate-500/15 text-slate-400 border-slate-500/30",
		KeepaliveRestored:
			"bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
	};

	function kindBadgeClass(kind: string): string {
		return (
			kindBadgeStyles[kind] ?? "bg-zinc-800 text-zinc-300 border-zinc-700"
		);
	}

	function formatTs(ts: number): string {
		return new Date(ts).toLocaleTimeString(undefined, {
			hour12: false,
			timeStyle: "medium",
		});
	}

	const routerSubsystems = [
		"IPv6 RA",
		"DHCPv4",
		"DHCPv6",
		"DNS",
		"TFTP",
		"PPPoE",
	];
</script>

<svelte:head>
	<title>Dashboard — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Page Header -->
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-foreground text-2xl font-bold tracking-tight">
				Dashboard
			</h1>
			<p class="text-muted-foreground text-sm">
				Router Orchestration Engine
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

	<!-- Main Grid: Live Events & Subsystems (2 Cols) + Network & System Vitals (1 Col) -->
	<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
		<!-- Left Main Panel: Live Events & Router Subsystems Stream -->
		<Card.Root class="flex flex-col lg:col-span-2">
			<Card.Header class="pb-3 border-b border-border/50">
				<div
					class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
				>
					<div class="flex items-center gap-2">
						<ActivityIcon class="size-4 text-emerald-400" />
						<Card.Title class="text-base"
							>Live Network Events</Card.Title
						>
					</div>

					<!-- Subsystem Badges Bar -->
					<div class="flex flex-wrap items-center gap-1.5">
						{#each routerSubsystems as sub (sub)}
							<div
								class="flex items-center gap-1.5 rounded-full border border-border/60 bg-muted/30 px-2 py-0.5 text-[10px] font-mono text-muted-foreground"
							>
								<span
									class="size-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
								></span>
								<span>{sub}</span>
							</div>
						{/each}
					</div>
				</div>
			</Card.Header>
			<Card.Content class="flex flex-1 flex-col gap-0 p-0">
				{#if recentEvents.length === 0}
					<div
						class="text-muted-foreground flex flex-col items-center justify-center gap-2 py-16 text-sm"
					>
						<MonitorIcon class="size-8 opacity-30" />
						<span>No live events received</span>
					</div>
				{:else}
					<div class="divide-border/50 divide-y overflow-hidden">
						{#each recentEvents as ev (ev.id + ev.ts)}
							<div
								class="flex items-start gap-3 px-5 py-3 text-xs transition-colors hover:bg-muted/30"
							>
								<span
									class={[
										"mt-0.5 inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider shrink-0",
										kindBadgeClass(ev.kind),
									].join(" ")}
								>
									{ev.kind.replace(/([A-Z])/g, " $1").trim()}
								</span>
								<div
									class="flex flex-1 flex-col gap-0.5 min-w-0"
								>
									<span
										class="text-foreground/90 font-medium leading-tight truncate"
									>
										{formatEventPayload(ev.data, ev.kind)}
									</span>
									<span
										class="text-muted-foreground text-[10px] tabular-nums"
									>
										{formatTs(ev.ts)}
									</span>
								</div>
							</div>
						{/each}
					</div>
				{/if}
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
						<div
							class="flex items-center justify-between text-muted-foreground text-[11px] font-medium uppercase tracking-wider"
						>
							<span>Primary LAN Interface</span>
							<Badge
								variant="outline"
								class="font-mono text-[10px]"
							>
								{statusData?.network?.lan_iface || "eth0"}
							</Badge>
						</div>
						<div
							class="flex items-center justify-between font-mono text-sm font-semibold text-foreground"
						>
							<span>IPv4 Address</span>
							<span class="text-emerald-400"
								>{statusData?.network?.lan_ipv4 ||
									"192.168.1.1"}</span
							>
						</div>
					</div>

					<!-- IPv6 Details -->
					{#if statusData?.network?.gua || statusData?.network?.ula || statusData?.network?.lan_ipv6}
						<div
							class="flex flex-col gap-2 rounded-lg border border-border/60 bg-muted/20 p-3"
						>
							<span
								class="text-muted-foreground text-[11px] font-medium uppercase tracking-wider"
							>
								IPv6 Configurations
							</span>
							{#if statusData.network.gua}
								<div class="flex flex-col">
									<span
										class="text-muted-foreground text-[10px]"
										>Global Unicast (GUA)</span
									>
									<span
										class="font-mono text-xs text-sky-400 truncate"
										>{statusData.network.gua}</span
									>
								</div>
							{/if}
							{#if statusData.network.ula}
								<div class="flex flex-col">
									<span
										class="text-muted-foreground text-[10px]"
										>Unique Local (ULA)</span
									>
									<span
										class="font-mono text-xs text-teal-400 truncate"
										>{statusData.network.ula}</span
									>
								</div>
							{/if}
						</div>
					{/if}

					<!-- Database & Process Vitals -->
					<div class="mt-auto grid grid-cols-2 gap-3">
						<div
							class="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/20 p-3"
						>
							<div
								class="flex items-center justify-between text-muted-foreground text-[11px] font-medium"
							>
								<div class="flex items-center gap-1.5">
									<DatabaseIcon
										class="size-3.5 text-amber-400"
									/>
									<span>Database</span>
								</div>
								<span
									class="size-1.5 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
								></span>
							</div>
							<span
								class="font-mono text-xs font-semibold text-foreground"
							>
								PostgreSQL
							</span>
							<span class="text-muted-foreground text-[10px]">
								{statusData?.db?.last_flush_secs_ago !==
								undefined
									? `Flushed ${statusData.db.last_flush_secs_ago}s ago`
									: "Connected"}
							</span>
						</div>

						<div
							class="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/20 p-3"
						>
							<div
								class="flex items-center justify-between text-muted-foreground text-[11px] font-medium"
							>
								<div class="flex items-center gap-1.5">
									<CpuIcon class="size-3.5 text-indigo-400" />
									<span>Process Memory</span>
								</div>
							</div>
							<span
								class="font-mono text-xs font-semibold text-foreground"
							>
								{rssBytes > 0 ? formatBytes(rssBytes) : "—"}
							</span>
							<span class="text-muted-foreground text-[10px]">
								{vmsBytes > 0
									? `VMS ${formatBytes(vmsBytes)}`
									: "RSS Memory"}
							</span>
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
</div>
