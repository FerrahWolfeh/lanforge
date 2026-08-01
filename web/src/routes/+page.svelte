<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { eventFeed } from "$lib/stores/events.svelte";
	import { status, dnsStats, leases, scan } from "$lib/api/client";
	import {
		normalizeServices,
		formatEventPayload,
		type StatusResponse,
		type DnsStatsResponse,
		type DhcpLease,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ActivityIcon from "@lucide/svelte/icons/activity";

	let statusData = $state<StatusResponse | null>(null);
	let dnsData = $state<DnsStatsResponse | null>(null);
	let leasesData = $state<DhcpLease[] | null>(null);
	let loadingData = $state(true);
	let scanning = $state(false);

	async function loadAll() {
		loadingData = true;
		try {
			const [s, dns, ls] = await Promise.allSettled([
				status(),
				dnsStats(),
				leases(),
			]);
			if (s.status === "fulfilled") statusData = s.value;
			if (dns.status === "fulfilled") dnsData = dns.value;
			if (ls.status === "fulfilled")
				leasesData = Array.isArray(ls.value) ? ls.value : [];
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

	const serviceList = $derived(normalizeServices(statusData));

	const recentEvents = $derived(eventFeed.events.slice(0, 10));

	const blockedPct = $derived.by(() => {
		if (!dnsData || dnsData.total_requests === 0) return "0%";
		const pct = (dnsData.blocked_queries / dnsData.total_requests) * 100;
		return `${pct.toFixed(1)}%`;
	});

	const statCards = $derived([
		{
			label: "Uptime",
			value: statusData ? formatUptime(statusData.uptime_secs) : null,
			subtext: statusData?.network?.lan_iface
				? `Iface: ${statusData.network.lan_iface}`
				: "System active",
			icon: ZapIcon,
			color: "text-emerald-400",
			bgColor: "bg-emerald-500/10 border-emerald-500/20",
		},
		{
			label: "DNS Queries",
			value: dnsData ? dnsData.total_requests.toLocaleString() : null,
			subtext: dnsData
				? `${dnsData.cache_hits.toLocaleString()} cache hits`
				: "Total queries",
			icon: GlobeIcon,
			color: "text-sky-400",
			bgColor: "bg-sky-500/10 border-sky-500/20",
		},
		{
			label: "Blocked",
			value: dnsData ? dnsData.blocked_queries.toLocaleString() : null,
			subtext: `${blockedPct} block rate`,
			icon: ShieldIcon,
			color: "text-rose-400",
			bgColor: "bg-rose-500/10 border-rose-500/20",
		},
		{
			label: "DHCP Leases",
			value: leasesData ? leasesData.length.toString() : null,
			subtext: "Active network leases",
			icon: NetworkIcon,
			color: "text-teal-400",
			bgColor: "bg-teal-500/10 border-teal-500/20",
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
			<p class="text-muted-foreground text-sm">Network at a glance</p>
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

	<!-- Top Stat Cards -->
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

	<!-- Main Grid: Recent Events, Services & Network Vitals -->
	<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
		<!-- Panel 1: Recent Events Feed -->
		<Card.Root class="flex flex-col lg:col-span-1">
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<ActivityIcon class="size-4 text-emerald-400" />
						<Card.Title class="text-base">Recent Events</Card.Title>
					</div>
					<div class="flex items-center gap-1.5">
						<span
							class={[
								"size-2 rounded-full",
								eventFeed.connected
									? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.7)] animate-pulse"
									: "bg-zinc-600",
							].join(" ")}
						></span>
						<span class="text-muted-foreground text-xs">
							{eventFeed.connected ? "Live" : "Disconnected"}
						</span>
					</div>
				</div>
			</Card.Header>
			<Card.Content class="flex flex-1 flex-col gap-0 p-0">
				{#if recentEvents.length === 0}
					<div
						class="text-muted-foreground flex flex-col items-center justify-center gap-2 py-14 text-sm"
					>
						<MonitorIcon class="size-8 opacity-30" />
						<span>No live events received</span>
					</div>
				{:else}
					<div class="divide-border/50 divide-y overflow-hidden">
						{#each recentEvents as ev (ev.id + ev.ts)}
							<div
								class="flex items-start gap-2.5 px-4 py-3 text-xs transition-colors hover:bg-muted/30"
							>
								<span
									class={[
										"mt-0.5 inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider shrink-0",
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

		<!-- Panel 2: Services Status -->
		<Card.Root class="flex flex-col lg:col-span-1">
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<RadioIcon class="size-4 text-sky-400" />
						<Card.Title class="text-base"
							>Daemon Services</Card.Title
						>
					</div>
					{#if serviceList.length > 0}
						<Badge
							variant="outline"
							class="text-[10px] uppercase font-mono"
						>
							{serviceList.filter((s) => s.state === "active")
								.length}/{serviceList.length} Online
						</Badge>
					{/if}
				</div>
			</Card.Header>
			<Card.Content class="flex flex-1 flex-col p-0">
				{#if loadingData}
					<div class="flex flex-col gap-2 p-4">
						{#each { length: 5 } as _, i (i)}
							<div class="flex items-center justify-between">
								<Skeleton class="h-4 w-28" />
								<Skeleton class="h-5 w-16 rounded-full" />
							</div>
						{/each}
					</div>
				{:else if serviceList.length === 0}
					<div
						class="text-muted-foreground py-14 text-center text-sm"
					>
						No service status available
					</div>
				{:else}
					<div class="divide-border/50 divide-y">
						{#each serviceList as svc (svc.name)}
							<div
								class="flex items-center justify-between px-4 py-3 text-xs transition-colors hover:bg-muted/30"
							>
								<div class="flex items-center gap-2.5">
									<span
										class={[
											"size-2 rounded-full shrink-0",
											svc.state === "active"
												? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
												: svc.state === "starting"
													? "bg-amber-500 shadow-[0_0_6px_rgba(245,158,11,0.8)] animate-pulse"
													: "bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.8)]",
										].join(" ")}
									></span>
									<div class="flex flex-col">
										<span
											class="text-foreground font-medium capitalize"
										>
											{svc.name.replace(/_/g, " ")}
										</span>
										{#if svc.uptime_secs > 0}
											<span
												class="text-muted-foreground text-[10px]"
											>
												up {formatUptime(
													svc.uptime_secs,
												)}
											</span>
										{/if}
									</div>
								</div>

								<Badge
									variant={svc.state === "active"
										? "default"
										: svc.state === "starting"
											? "secondary"
											: "destructive"}
									class="capitalize text-[10px] px-2 py-0.5 font-medium"
								>
									{svc.state}
								</Badge>
							</div>
						{/each}
					</div>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Panel 3: Network Vitals & Host Overview -->
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

					<!-- Storage & Process Vitals -->
					<div class="mt-auto grid grid-cols-2 gap-3">
						<div
							class="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/20 p-3"
						>
							<div
								class="flex items-center gap-1.5 text-muted-foreground text-[11px] font-medium"
							>
								<DatabaseIcon class="size-3.5 text-amber-400" />
								<span>Database</span>
							</div>
							<span
								class="font-mono font-semibold text-foreground"
							>
								{statusData?.db
									? formatBytes(statusData.db.size_bytes)
									: "—"}
							</span>
						</div>

						<div
							class="flex flex-col gap-1 rounded-lg border border-border/60 bg-muted/20 p-3"
						>
							<div
								class="flex items-center gap-1.5 text-muted-foreground text-[11px] font-medium"
							>
								<CpuIcon class="size-3.5 text-indigo-400" />
								<span>Process Memory</span>
							</div>
							<span
								class="font-mono font-semibold text-foreground"
							>
								{statusData?.resources
									? formatBytes(
											statusData.resources.rss_bytes,
										)
									: "—"}
							</span>
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
</div>
