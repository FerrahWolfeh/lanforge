<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { formatBytes, formatBuild, formatIpv6Prefix, formatUptime, createPolling } from "$lib/utils";
	import {
		status,
		dhcpPools,
		listDevices,
		scan,
		dnsAnalytics,
		trafficTelemetryFeed,
	} from "$lib/api/client";
	import {
		normalizeServices,
		type StatusResponse,
		type DnsAnalyticsResponse,
		type DhcpPoolsResponse,
		type DeviceEntry,
		type ServiceBanner,
		type TrafficTelemetryResponse,
	} from "$lib/api/types";
	import TrafficActivityChart from "$lib/components/TrafficActivityChart.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatStrip, { type StatStripItem } from "$lib/components/StatStrip.svelte";
	import StatusLine, { type StatusTone } from "$lib/components/StatusLine.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";
	import StatusDot from "$lib/components/StatusDot.svelte";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import { degradedReason, getServiceMeta } from "$lib/services";
	import ShieldBanIcon from "@lucide/svelte/icons/shield-ban";
	import ServerIcon from "@lucide/svelte/icons/server";

	const trafficTelemetry = trafficTelemetryFeed();

	let statusData = $state<StatusResponse | null>(null);
	let poolsData = $state<DhcpPoolsResponse | null>(null);
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
			const [s, pools, dev, aRes, telem] = await Promise.allSettled([
				status(),
				dhcpPools(),
				listDevices(),
				dnsAnalytics(10),
				trafficTelemetry(),
			]);
			// A failed call keeps the last good data for its panel.
			if (s.status === "fulfilled") statusData = s.value;
			if (pools.status === "fulfilled") poolsData = pools.value;
			if (dev.status === "fulfilled") {
				devicesData = dev.value;
			}
			if (aRes.status === "fulfilled") {
				analyticsData = aRes.value;
			}
			if (telem.status === "fulfilled") {
				telemetryData = telem.value;
			}
			const results = [s, pools, dev, aRes, telem];
			const failed = results.filter((r) => r.status === "rejected").length;
			if (failed === results.length) {
				toast.error("Failed to load dashboard data");
			} else if (failed > 0) {
				toast.error(`Failed to load ${failed} of ${results.length} dashboard sources`);
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

	const rssBytes = $derived(statusData?.resources?.memory_rss_bytes ?? null);

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

	const conntrack = $derived(telemetryData?.conntrack);

	// DHCPv4 pools together: the figure that runs out first on a home LAN.
	const poolV4 = $derived.by(() => {
		const pools = poolsData?.v4_pools ?? [];
		if (pools.length === 0) return null;
		return {
			used: pools.reduce((n, p) => n + (p.used || 0), 0),
			total: pools.reduce((n, p) => n + (p.total || 0), 0),
		};
	});

	// Last 24 hours, the same window the DNS pages use.
	const dns24h = $derived.by(() => {
		const rates = analyticsData?.query_rate ?? [];
		if (rates.length === 0) return null;
		return {
			total: rates.reduce((n, r) => n + r.count, 0),
			blocked: rates.reduce((n, r) => n + (r.blocked ?? 0), 0),
		};
	});

	const stripItems = $derived.by((): StatStripItem[] => {
		const ratio = (a: number, b: number) => (b > 0 ? a / b : 0);
		const poolRatio = poolV4 ? ratio(poolV4.used, poolV4.total) : 0;
		return [
			{
				label: "devices online",
				value: devicesData ? onlineDevicesCount : loadingData ? null : "—",
				of: devicesData ? totalDevicesCount : undefined,
				icon: WifiIcon,
				href: "/network/devices",
			},
			{
				label: "DHCPv4 pool in use",
				value: poolV4 ? poolV4.used : loadingData ? null : "—",
				of: poolV4?.total,
				icon: ServerIcon,
				bar: poolV4 ? poolRatio : undefined,
				barTone: poolRatio >= 0.9 ? "danger" : poolRatio >= 0.75 ? "warning" : "brand",
				href: "/dhcp/pools",
			},
			{
				label: "queries blocked in 24h",
				value: dns24h ? dns24h.blocked : loadingData ? null : "—",
				of: dns24h?.total,
				icon: ShieldBanIcon,
				bar: dns24h ? ratio(dns24h.blocked, dns24h.total) : undefined,
				barTone: "danger",
				href: "/dns/adblock",
			},
			{
				label: "connections tracked",
				value: conntrack ? conntrack.active_connections : loadingData ? null : "—",
				of: conntrack?.max_connections,
				icon: ActivityIcon,
				bar: conntrack ? ratio(conntrack.active_connections, conntrack.max_connections) : undefined,
				href: "/firewall",
			},
		];
	});

	const banners = $derived(normalizeServices(statusData));

	const PROBLEM_STATES = ["degraded", "error", "paused"];
	const isProblem = (b: ServiceBanner) => PROBLEM_STATES.includes(b.state);
	const isRunning = (b: ServiceBanner) => b.state === "online" || b.state === "active";

	/** Why a service is not fine, in one line: the degraded reason, else the daemon's own summary. */
	function reasonOf(b: ServiceBanner): string {
		return degradedReason(b.detail) ?? b.summary ?? b.state;
	}

	// Problems first, then running services, then the ones switched off.
	const sortedBanners = $derived(
		[...banners].sort((a, b) => {
			const rank = (x: ServiceBanner) => (isProblem(x) ? 0 : isRunning(x) ? 1 : 2);
			return rank(a) - rank(b);
		})
	);

	const statusLine = $derived.by((): { tone: StatusTone; title: string; text: string; href?: string } | null => {
		if (!statusData) return null;
		const problems = banners.filter(isProblem);
		const issues = statusData.config_issues ?? [];
		if (problems.length === 0 && issues.length === 0) return null;
		const parts = problems.map((b) => `${getServiceMeta(b.id, b.name).name}: ${reasonOf(b)}`);
		if (issues.length > 0) parts.push(`${issues.length} configuration ${issues.length === 1 ? "issue" : "issues"} (listed above)`);
		const count = parts.length;
		return {
			tone: problems.some((b) => b.state === "error") ? "danger" : "warning",
			title: count === 1 ? "Needs attention: " : `${count} things need attention: `,
			text: parts.join(" · "),
			href: problems.length === 1 ? getServiceMeta(problems[0].id, problems[0].name).configHref : problems.length > 1 ? "/system/services" : undefined,
		};
	});

	function stateVariant(state: string): string {
		if (state === "online" || state === "active") return "online";
		if (state === "degraded" || state === "paused" || state === "starting" || state === "waiting") return "warning";
		if (state === "error") return "error";
		return "dormant";
	}
</script>

<svelte:head>
	<title>Dashboard — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5 sm:gap-6">
	<!-- Page Header -->
	<PageHeader
		title="Dashboard"
		description="What the router and the LAN are doing right now."
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
			{#if auth.can("admin")}
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
			{/if}
		{/snippet}
	</PageHeader>

	{#if statusLine}
		<StatusLine tone={statusLine.tone} title={statusLine.title} text={statusLine.text} href={statusLine.href} />
	{/if}

	<StatStrip items={stripItems} />

	<TrafficActivityChart
		loading={loadingData}
		showDnsToggle={true}
		title="Real-Time Bandwidth & Throughput"
		{analyticsData}
		{statusData}
		{telemetryData}
	/>

	<div class="grid grid-cols-1 gap-5 lg:grid-cols-3">
		<!-- Every service the daemon reports, problems first -->
		<Card.Root class="flex flex-col gap-0 py-0 lg:col-span-2">
			<div class="flex items-center justify-between gap-2 border-b px-4 py-3">
				<div class="flex items-center gap-2 min-w-0">
					<ActivityIcon class="size-4 text-muted-foreground shrink-0" />
					<span class="text-sm font-semibold">Services</span>
					{#if banners.length > 0}
						<span class="text-xs text-muted-foreground tabular-nums">
							{banners.filter(isRunning).length} of {banners.length} running
						</span>
					{/if}
				</div>
				<a
					href="/system/services"
					class="text-xs text-muted-foreground hover:text-selected-foreground transition-colors flex items-center gap-1 font-medium"
				>
					Manage <ArrowRightIcon class="size-3" />
				</a>
			</div>
			<div class="flex flex-col divide-y divide-border">
				{#if loadingData && banners.length === 0}
					{#each { length: 6 } as _, i (i)}
						<div class="px-4 py-2.5"><Skeleton class="h-5 w-full" /></div>
					{/each}
				{:else}
					{#each sortedBanners as banner (banner.id ?? banner.name)}
						{@const meta = getServiceMeta(banner.id, banner.name)}
						{@const Icon = meta.icon}
						<a
							href={meta.configHref}
							class="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-accent/40 min-w-0"
						>
							<StatusDot state={stateVariant(banner.state)} size="sm" />
							<Icon class="size-4 shrink-0 text-muted-foreground" />
							<span class="text-sm font-medium text-foreground truncate min-w-0">{meta.name}</span>
							<span
								class="ml-auto truncate text-xs min-w-0 text-right {isProblem(banner)
									? 'text-warning'
									: 'text-muted-foreground font-mono'}"
								title={reasonOf(banner)}
							>
								{isProblem(banner) ? reasonOf(banner) : (banner.summary ?? "")}
							</span>
							<StatusBadge text={banner.state} variant={stateVariant(banner.state)} class="capitalize shrink-0" />
						</a>
					{/each}
				{/if}
			</div>
		</Card.Root>

		<!-- The router itself: only values the daemon reported, "—" otherwise -->
		<Card.Root class="flex flex-col gap-0 py-0 lg:col-span-1">
			<div class="flex items-center gap-2 border-b px-4 py-3">
				<CpuIcon class="size-4 text-muted-foreground shrink-0" />
				<span class="text-sm font-semibold">Router</span>
			</div>
			{#if loadingData && !statusData}
				<div class="flex flex-col gap-3 p-4">
					<Skeleton class="h-5 w-full" />
					<Skeleton class="h-5 w-full" />
					<Skeleton class="h-5 w-full" />
				</div>
			{:else}
				<dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2.5 p-4 text-sm">
					<dt class="text-muted-foreground">LAN interface</dt>
					<dd class="text-right font-mono text-foreground truncate">{statusData?.network?.lan_iface || "—"}</dd>
					<dt class="text-muted-foreground">IPv4</dt>
					<dd class="text-right font-mono text-foreground truncate">{statusData?.network?.lan_ipv4 || "—"}</dd>
					<dt class="text-muted-foreground">IPv6 GUA</dt>
					<dd class="text-right font-mono text-foreground truncate" title={formatIpv6Prefix(statusData?.network?.gua)}>{statusData?.network?.gua ? formatIpv6Prefix(statusData.network.gua) : "—"}</dd>
					<dt class="text-muted-foreground">IPv6 ULA</dt>
					<dd class="text-right font-mono text-muted-foreground truncate" title={formatIpv6Prefix(statusData?.network?.ula)}>{statusData?.network?.ula ? formatIpv6Prefix(statusData.network.ula) : "—"}</dd>
					<dt class="text-muted-foreground">Uptime</dt>
					<dd class="text-right tabular-nums text-foreground">{statusData ? formatUptime(statusData.uptime_secs) : "—"}</dd>
					<dt class="text-muted-foreground">Memory</dt>
					<dd class="text-right tabular-nums text-foreground">{rssBytes !== null ? formatBytes(rssBytes) : "—"}</dd>
					<dt class="text-muted-foreground">Version</dt>
					<dd class="text-right font-mono text-xs text-muted-foreground truncate self-center" title={statusData?.version ?? ""}>{statusData?.version ? formatBuild(statusData.version) : "—"}</dd>
				</dl>
			{/if}
		</Card.Root>
	</div>
</div>
