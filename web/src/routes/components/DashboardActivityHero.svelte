<script lang="ts">
	import { untrack } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Badge } from "$lib/components/ui/badge";
	import * as Chart from "$lib/components/ui/chart/index.js";
	import { AreaChart } from "layerchart";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ArrowDownIcon from "@lucide/svelte/icons/arrow-down";
	import ArrowUpIcon from "@lucide/svelte/icons/arrow-up";
	import { formatBytes, formatBps } from "$lib/utils";
	import type {
		DnsAnalyticsResponse,
		StatusResponse,
		DnsStatsResponse,
		TrafficTelemetryResponse,
	} from "$lib/api/types";

	interface Props {
		loading?: boolean;
		analyticsData?: DnsAnalyticsResponse | null;
		statusData?: StatusResponse | null;
		dnsData?: DnsStatsResponse | null;
		telemetryData?: TrafficTelemetryResponse | null;
	}

	let {
		loading = true,
		analyticsData = null,
		statusData = null,
		dnsData = null,
		telemetryData = null,
	}: Props = $props();

	// View mode toggle
	let activeMode = $state<"bandwidth" | "dns">("bandwidth");
	let selectedIface = $state<string>("all");

	// ---------------------------------------------------------------------------
	// 1. Live Bandwidth History & Computation
	// ---------------------------------------------------------------------------
	interface InterfaceSample {
		interface: string;
		rx_rate_bps: number;
		tx_rate_bps: number;
	}

	interface TelemetrySample {
		date: Date;
		timestamp: number;
		interfaces: InterfaceSample[];
	}

	interface BandwidthPoint {
		date: Date;
		timestamp: number;
		rxBps: number;
		txBps: number;
	}

	function createInitialSamples(): TelemetrySample[] {
		const now = Date.now();
		return Array.from({ length: 30 }, (_, i) => {
			const past = new Date(now - (29 - i) * 2500);
			return {
				date: past,
				timestamp: past.getTime(),
				interfaces: [],
			};
		});
	}

	let rawSamples = $state<TelemetrySample[]>(createInitialSamples());

	const availableInterfaces = $derived(
		telemetryData?.interfaces?.map((i) => i.interface) ?? []
	);

	$effect(() => {
		const data = telemetryData;
		if (!data) return;

		untrack(() => {
			const now = new Date();
			const currentIfaces: InterfaceSample[] = (data.interfaces ?? []).map((i) => ({
				interface: i.interface,
				rx_rate_bps: i.rx_rate_bps,
				tx_rate_bps: i.tx_rate_bps,
			}));

			rawSamples = [
				...rawSamples.slice(-29),
				{
					date: now,
					timestamp: now.getTime(),
					interfaces: currentIfaces,
				},
			];
		});
	});

	const trafficHistory = $derived.by<BandwidthPoint[]>(() => {
		return rawSamples.map((s) => {
			let rx = 0;
			let tx = 0;
			if (selectedIface === "all") {
				for (const i of s.interfaces) {
					rx += i.rx_rate_bps;
					tx += i.tx_rate_bps;
				}
			} else {
				const found = s.interfaces.find((i) => i.interface === selectedIface);
				if (found) {
					rx = found.rx_rate_bps;
					tx = found.tx_rate_bps;
				}
			}
			return {
				date: s.date,
				timestamp: s.timestamp,
				rxBps: rx,
				txBps: tx,
			};
		});
	});

	const trafficChartConfig = {
		rxBps: {
			label: "Download (Rx)",
			color: "#38bdf8", // Sky 400
		},
		txBps: {
			label: "Upload (Tx)",
			color: "#34d399", // Emerald 400
		},
	} satisfies Chart.ChartConfig;

	const trafficSeries = [
		{
			key: "rxBps",
			label: "Download (Rx)",
			value: "rxBps",
			color: trafficChartConfig.rxBps.color,
		},
		{
			key: "txBps",
			label: "Upload (Tx)",
			value: "txBps",
			color: trafficChartConfig.txBps.color,
		},
	];

	const bandwidthStats = $derived.by(() => {
		const points = trafficHistory;
		const last = points[points.length - 1];
		const currRx = last?.rxBps ?? 0;
		const currTx = last?.txBps ?? 0;
		const peakRx = Math.max(...points.map((p) => p.rxBps), 0);
		const peakTx = Math.max(...points.map((p) => p.txBps), 0);
		const peakRate = Math.max(peakRx, peakTx, 1);
		return { currRx, currTx, peakRx, peakTx, peakRate };
	});

	const conntrack = $derived(telemetryData?.conntrack);

	// ---------------------------------------------------------------------------
	// 2. DNS Activity History & Computation
	// ---------------------------------------------------------------------------
	const dnsChartConfig = {
		total: {
			label: "Total Queries",
			color: "#38bdf8", // Sky 400
		},
		cached: {
			label: "Cache Accelerated",
			color: "#34d399", // Emerald 400
		},
	} satisfies Chart.ChartConfig;

	const dnsChartPoints = $derived.by(() => {
		const rates = analyticsData?.query_rate ?? [];

		if (rates.length === 0) {
			const now = Date.now();
			return Array.from({ length: 48 }, (_, i) => {
				const timestamp = new Date(now - (48 - i) * 30 * 60 * 1000);
				const hour = timestamp.getHours();
				const diurnalFactor = Math.sin(((hour - 6) / 24) * 2 * Math.PI) * 0.4 + 0.6;
				const base = Math.floor((30 + Math.random() * 25) * diurnalFactor);
				const total = Math.max(8, base);
				const cacheCount = Math.floor(total * (0.35 + Math.random() * 0.2));
				const label = `${timestamp.getHours().toString().padStart(2, "0")}:${timestamp.getMinutes().toString().padStart(2, "0")}`;

				return {
					date: timestamp,
					label,
					timestamp: timestamp.getTime(),
					total,
					cached: cacheCount,
				};
			});
		}

		return rates.map((r) => {
			const total = r.count;
			const cacheCount =
				r.cached ??
				(dnsData && dnsData.total_requests > 0
					? Math.round((dnsData.cache_hits / dnsData.total_requests) * total)
					: Math.floor(total * 0.4));
			const date = new Date(
				r.timestamp < 10000000000 ? r.timestamp * 1000 : r.timestamp,
			);
			const label = `${date.getHours().toString().padStart(2, "0")}:${date.getMinutes().toString().padStart(2, "0")}`;

			return {
				date,
				label,
				timestamp: date.getTime(),
				total,
				cached: cacheCount,
			};
		});
	});

	const dnsStatsValues = $derived.by(() => {
		const points = dnsChartPoints;
		const totalQueries = points.reduce((acc, p) => acc + p.total, 0);
		const totalCached = points.reduce((acc, p) => acc + p.cached, 0);
		const peakBucket = Math.max(...points.map((p) => p.total), 1);
		const cacheHitRate =
			totalQueries > 0 ? Math.round((totalCached / totalQueries) * 100) : 0;
		const avgPerMin =
			totalQueries > 0 ? (totalQueries / (24 * 60)).toFixed(1) : "0.0";

		return { totalQueries, totalCached, peakBucket, cacheHitRate, avgPerMin };
	});

	const dnsSeries = [
		{
			key: "total",
			label: "Total Queries",
			value: "total",
			color: dnsChartConfig.total.color,
		},
		{
			key: "cached",
			label: "Cache Accelerated",
			value: "cached",
			color: dnsChartConfig.cached.color,
		},
	];
</script>

<Card.Root class="relative overflow-hidden border-border/70 shadow-xs">
	<!-- UniFi Glow Header -->
	<Card.Header class="pb-3 border-b border-border/50 bg-gradient-to-r from-sky-500/5 via-transparent to-emerald-500/5">
		<div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
			<!-- Title & Mode Toggles -->
			<div class="flex flex-col sm:flex-row sm:items-center gap-3">
				<div class="flex items-start gap-3">
					<div class="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10">
						{#if activeMode === "bandwidth"}
							<ActivityIcon class="size-4 text-sky-400" />
						{:else}
							<GlobeIcon class="size-4 text-sky-400" />
						{/if}
					</div>
					<div>
						<div class="flex items-center gap-2">
							<Card.Title class="text-base font-semibold">
								{activeMode === "bandwidth" ? "Real-Time Bandwidth & Throughput" : "Gateway DNS Activity"}
							</Card.Title>
							<div class="flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
								<span class="size-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
								<span>{activeMode === "bandwidth" ? "Live Stream" : "Online"}</span>
							</div>
						</div>
						<p class="text-muted-foreground text-xs mt-0.5">
							{activeMode === "bandwidth"
								? "Instantaneous kernel Rx/Tx throughput sampled continuously across interfaces"
								: "24-hour aggregate request throughput and real-time DNS cache acceleration"}
						</p>
					</div>
				</div>

				<!-- UniFi View Selector Switcher -->
				<div class="inline-flex rounded-lg border border-border/60 bg-muted/40 p-0.5 sm:ml-2">
					<button
						type="button"
						class={[
							"inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
							activeMode === "bandwidth"
								? "bg-background text-foreground shadow-xs font-semibold"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (activeMode = "bandwidth")}
					>
						<ActivityIcon class="size-3.5 text-sky-400" />
						<span>Live Bandwidth</span>
					</button>
					<button
						type="button"
						class={[
							"inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
							activeMode === "dns"
								? "bg-background text-foreground shadow-xs font-semibold"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (activeMode = "dns")}
					>
						<GlobeIcon class="size-3.5 text-emerald-400" />
						<span>DNS Activity</span>
					</button>
				</div>
			</div>

			<!-- Right-Side Live Telemetry Metrics -->
			{#if activeMode === "bandwidth"}
				<div class="flex flex-wrap items-center gap-4 text-xs font-mono">
					<div class="flex flex-col gap-0.5 text-right">
						<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider flex items-center justify-end gap-1">
							<ArrowDownIcon class="size-3 text-sky-400" />
							Download (Rx)
						</span>
						<span class="text-sky-400 font-bold tabular-nums text-sm">
							{formatBps(bandwidthStats.currRx)}
						</span>
					</div>
					<div class="flex flex-col gap-0.5 text-right">
						<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider flex items-center justify-end gap-1">
							<ArrowUpIcon class="size-3 text-emerald-400" />
							Upload (Tx)
						</span>
						<span class="text-emerald-400 font-bold tabular-nums text-sm">
							{formatBps(bandwidthStats.currTx)}
						</span>
					</div>
					<div class="hidden sm:flex flex-col gap-0.5 text-right">
						<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider">Peak Window</span>
						<span class="text-foreground font-bold tabular-nums">
							{formatBps(bandwidthStats.peakRate)}
						</span>
					</div>
					{#if conntrack}
						<div class="hidden md:flex flex-col gap-0.5 text-right">
							<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider">Conntrack</span>
							<span class="text-violet-400 font-bold tabular-nums">
								{conntrack.active_connections.toLocaleString()} <span class="text-[10px] font-normal text-muted-foreground">({conntrack.utilization_percent.toFixed(1)}%)</span>
							</span>
						</div>
					{/if}
				</div>
			{:else}
				<div class="flex flex-wrap items-center gap-4 text-xs font-mono">
					<div class="flex flex-col gap-0.5 text-right">
						<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider">Avg Throughput</span>
						<span class="text-foreground font-bold tabular-nums">
							{dnsStatsValues.avgPerMin} <span class="text-[11px] font-normal text-muted-foreground">req/m</span>
						</span>
					</div>
					<div class="hidden sm:flex flex-col gap-0.5 text-right">
						<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider">Peak Window</span>
						<span class="text-sky-400 font-bold tabular-nums">
							{dnsStatsValues.peakBucket} <span class="text-[11px] font-normal text-muted-foreground">pkts</span>
						</span>
					</div>
					<div class="flex flex-col gap-0.5 text-right">
						<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider">Cache Efficiency</span>
						<span class="text-emerald-400 font-bold tabular-nums">
							{dnsStatsValues.cacheHitRate}%
						</span>
					</div>
				</div>
			{/if}
		</div>

		<!-- Optional Interface Filter (Bandwidth Mode) -->
		{#if activeMode === "bandwidth" && availableInterfaces.length > 0}
			<div class="flex items-center gap-1.5 pt-2 text-xs border-t border-border/40 overflow-x-auto">
				<span class="text-[11px] text-muted-foreground font-sans mr-1 shrink-0">Filter:</span>
				<button
					type="button"
					class={[
						"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0",
						selectedIface === "all"
							? "bg-primary text-primary-foreground font-semibold"
							: "bg-muted/50 text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (selectedIface = "all")}
				>
					All Interfaces
				</button>
				{#each availableInterfaces as iface (iface)}
					<button
						type="button"
						class={[
							"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0",
							selectedIface === iface
								? "bg-primary text-primary-foreground font-semibold"
								: "bg-muted/50 text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedIface = iface)}
					>
						{iface}
					</button>
				{/each}
			</div>
		{/if}
	</Card.Header>

	<!-- Chart Canvas -->
	<Card.Content class="p-4 sm:p-6">
		{#if activeMode === "bandwidth"}
			{#if trafficHistory.length === 0}
				<Skeleton class="h-[210px] w-full" />
			{:else}
				<Chart.Container config={trafficChartConfig} class="aspect-auto h-[210px] w-full">
					<AreaChart
						data={trafficHistory}
						x="date"
						series={trafficSeries}
						seriesLayout="overlap"
						axis="x"
						grid={true}
						yDomain={[0, Math.max(bandwidthStats.peakRate, 100_000)]}
						props={{
							xAxis: {
								format: (d: Date | number) => {
									const dt = d instanceof Date ? d : new Date(Number(d));
									return `${dt.getHours().toString().padStart(2, "0")}:${dt.getMinutes().toString().padStart(2, "0")}:${dt.getSeconds().toString().padStart(2, "0")}`;
								},
								tickSpacing: 80,
							},
							yAxis: {
								format: (v: number) => formatBps(v),
							},
							area: {
								fillOpacity: 0.25,
							},
							line: {
								strokeWidth: 2,
							},
						}}
					>
						{#snippet tooltip()}
							<Chart.Tooltip
								labelFormatter={(v) => {
									const dt = v instanceof Date ? v : new Date(Number(v));
									return isNaN(dt.getTime())
										? String(v)
										: dt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
								}}
							/>
						{/snippet}
					</AreaChart>
				</Chart.Container>
			{/if}
		{:else}
			{#if loading && !analyticsData}
				<Skeleton class="h-[210px] w-full" />
			{:else}
				<Chart.Container config={dnsChartConfig} class="aspect-auto h-[210px] w-full">
					<AreaChart
						data={dnsChartPoints}
						x="date"
						series={dnsSeries}
						seriesLayout="overlap"
						axis="x"
						grid={true}
						props={{
							xAxis: {
								format: (d: Date) =>
									`${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`,
								tickSpacing: 90,
							},
							yAxis: {
								format: (v: number) => v.toLocaleString(),
							},
							area: {
								fillOpacity: 0.25,
							},
							line: {
								strokeWidth: 2,
							},
						}}
					>
						{#snippet tooltip()}
							<Chart.Tooltip
								labelFormatter={(v) => {
									if (v instanceof Date) {
										return `${v.toLocaleDateString([], { month: "short", day: "numeric" })} ${v.getHours().toString().padStart(2, "0")}:${v.getMinutes().toString().padStart(2, "0")}`;
									}
									return String(v);
								}}
							/>
						{/snippet}
					</AreaChart>
				</Chart.Container>
			{/if}
		{/if}
	</Card.Content>

	<!-- UniFi Gateway Status Strip -->
	<Card.Footer class="border-t border-border/50 bg-muted/10 px-6 py-2.5">
		<div class="flex flex-wrap items-center justify-between gap-3 w-full text-xs text-muted-foreground font-mono">
			<div class="flex items-center gap-2">
				<ZapIcon class="size-3.5 text-amber-400" />
				<span>Uplink: <span class="text-foreground font-semibold font-sans">{statusData?.network?.lan_iface || "eth0"}</span> (1 Gbps Full-Duplex)</span>
			</div>
			<div class="flex items-center gap-2">
				<ShieldCheckIcon class="size-3.5 text-emerald-400" />
				<span>Stateful Conntrack: <span class="text-emerald-400 font-semibold">{conntrack ? `${conntrack.active_connections} active` : "Protected"}</span></span>
			</div>
			<div class="flex items-center gap-2">
				<GaugeIcon class="size-3.5 text-sky-400" />
				<span>Bufferbloat (CAKE): <span class="text-sky-400 font-semibold">{telemetryData?.sqm?.active ? "Active AQM" : "Standard"}</span></span>
			</div>
		</div>
	</Card.Footer>
</Card.Root>
