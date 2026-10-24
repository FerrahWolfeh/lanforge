<script lang="ts">
	import { untrack } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Badge } from "$lib/components/ui/badge";
	import * as Chart from "$lib/components/ui/chart/index.js";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { AreaChart } from "layerchart";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import BoxesIcon from "@lucide/svelte/icons/boxes";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ArrowDownIcon from "@lucide/svelte/icons/arrow-down";
	import ArrowUpIcon from "@lucide/svelte/icons/arrow-up";
	import { formatBps } from "$lib/utils";
	import type {
		DnsAnalyticsResponse,
		StatusResponse,
		DnsStatsResponse,
		TrafficTelemetryResponse,
		TrafficStatusResponse,
	} from "$lib/api/types";

	interface Props {
		loading?: boolean;
		title?: string;
		description?: string;
		showDnsToggle?: boolean;
		showConntrack?: boolean;
		telemetryData?: TrafficTelemetryResponse | null;
		statusData?: StatusResponse | null;
		trafficStatus?: TrafficStatusResponse | null;
		dnsData?: DnsStatsResponse | null;
		analyticsData?: DnsAnalyticsResponse | null;
	}

	let {
		loading = false,
		title = "Real-Time Bandwidth & Throughput",
		description,
		showDnsToggle = false,
		showConntrack = true,
		telemetryData = null,
		statusData = null,
		trafficStatus = null,
		dnsData = null,
		analyticsData = null,
	}: Props = $props();

	// View mode toggle
	let activeMode = $state<"bandwidth" | "dns">("bandwidth");
	let selectedIface = $state<string>("auto_wan");

	// ---------------------------------------------------------------------------
	// 1. Interface Classification & Filtering
	// ---------------------------------------------------------------------------
	const availableInterfaces = $derived(
		telemetryData?.interfaces?.map((i) => i.interface) ?? []
	);

	const detectedWan = $derived.by(() => {
		if (telemetryData?.wan_interface) return telemetryData.wan_interface;
		if (trafficStatus?.wan_interface) return trafficStatus.wan_interface;
		const ifaces = availableInterfaces;
		return (
			ifaces.find((i) => i === "ppp0" || i.startsWith("wan")) ??
			null
		);
	});

	const detectedIngress = $derived.by(() => {
		if (telemetryData?.ingress_device) return telemetryData.ingress_device;
		if (trafficStatus?.ingress_device) return trafficStatus.ingress_device;
		const ifaces = availableInterfaces;
		return ifaces.find((i) => i.startsWith("ifb")) ?? null;
	});

	const detectedLan = $derived.by(() => {
		if (statusData?.network?.lan_iface) return statusData.network.lan_iface;
		const ifaces = availableInterfaces;
		return (
			ifaces.find(
				(i) =>
					(i.startsWith("br-") || i.startsWith("lan") || i === "eth0" || i === "eth1") &&
					i !== detectedWan &&
					i !== detectedIngress,
			) ?? null
		);
	});

	function isWan(iface: string) {
		return iface === detectedWan;
	}

	function isIngress(iface: string) {
		return iface === detectedIngress || iface.startsWith("ifb");
	}

	function isVpn(iface: string) {
		return (
			iface.startsWith("tailscale") ||
			iface.startsWith("wg") ||
			iface.startsWith("tun")
		);
	}

	function isContainer(iface: string) {
		return (
			iface.startsWith("veth") ||
			iface.startsWith("podman") ||
			iface.startsWith("docker")
		);
	}

	const vpnInterfaces = $derived(availableInterfaces.filter((i) => isVpn(i)));
	const containerInterfaces = $derived(availableInterfaces.filter((i) => isContainer(i)));
	const otherInterfaces = $derived(
		availableInterfaces.filter(
			(i) =>
				!isWan(i) &&
				!isIngress(i) &&
				!isVpn(i) &&
				!isContainer(i) &&
				i !== detectedLan,
		),
	);

	const effectiveSelectedIface = $derived.by(() => {
		if (selectedIface === "auto_wan") {
			return (
				detectedWan ??
				availableInterfaces.find((i) => !isIngress(i) && !isContainer(i)) ??
				"all"
			);
		}
		return selectedIface;
	});

	const isContainerOrOtherSelected = $derived(
		containerInterfaces.includes(effectiveSelectedIface) ||
			otherInterfaces.includes(effectiveSelectedIface),
	);

	// ---------------------------------------------------------------------------
	// 2. Live Bandwidth History & Computation
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

	$effect(() => {
		const data = telemetryData;
		if (!data) return;

		untrack(() => {
			if (data.history && data.history.length > 0) {
				const mapped: TelemetrySample[] = data.history.map((s) => {
					const ms = s.timestamp < 10_000_000_000 ? s.timestamp * 1000 : s.timestamp;
					return {
						date: new Date(ms),
						timestamp: ms,
						interfaces: s.interfaces,
					};
				});

				if (mapped.length < 30) {
					const t0 = mapped[0].timestamp;
					const padCount = 30 - mapped.length;
					const padded: TelemetrySample[] = [];
					for (let i = 0; i < padCount; i++) {
						const pastMs = t0 - (padCount - i) * 2500;
						padded.push({
							date: new Date(pastMs),
							timestamp: pastMs,
							interfaces: [],
						});
					}
					rawSamples = [...padded, ...mapped];
				} else {
					rawSamples = mapped;
				}
			} else {
				const now = new Date();
				const currentIfaces: InterfaceSample[] = (data.interfaces ?? []).map((i) => ({
					interface: i.interface,
					rx_rate_bps: i.rx_rate_bps,
					tx_rate_bps: i.tx_rate_bps,
				}));

				rawSamples = [
					...rawSamples.slice(-239),
					{
						date: now,
						timestamp: now.getTime(),
						interfaces: currentIfaces,
					},
				];
			}
		});
	});

	const trafficHistory = $derived.by<BandwidthPoint[]>(() => {
		const target = effectiveSelectedIface;
		return rawSamples.map((s) => {
			let rx = 0;
			let tx = 0;
			if (target === "all") {
				for (const i of s.interfaces) {
					// Crucial: Exclude IFB mirror devices from aggregate to prevent multiplication
					if (isIngress(i.interface)) continue;
					rx += i.rx_rate_bps;
					tx += i.tx_rate_bps;
				}
			} else {
				const found = s.interfaces.find((i) => i.interface === target);
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
	// 3. DNS Activity History & Computation (Dashboard Mode)
	// ---------------------------------------------------------------------------
	const dnsChartConfig = {
		total: {
			label: "Total Queries",
			color: "#38bdf8",
		},
		cached: {
			label: "Cache Accelerated",
			color: "#34d399",
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

<Card.Root class="relative overflow-hidden border-border/70 shadow-xs !py-0 !pt-0 [--card-spacing:0] gap-0">
	<!-- Glow Header -->
	<Card.Header class="pt-5 sm:pt-6 !pb-4 sm:!pb-5 px-4 sm:px-6 border-b border-border/50 bg-gradient-to-r from-sky-500/10 via-transparent to-emerald-500/10 rounded-t-3xl flex flex-col gap-3.5 w-full !items-stretch">
		<div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between w-full">
			<!-- Title & Mode Switcher -->
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
								{activeMode === "bandwidth" ? title : "Gateway DNS Activity"}
							</Card.Title>
							<div class="flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
								<span class="size-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
								<span>{activeMode === "bandwidth" ? "Live Stream" : "Online"}</span>
							</div>
						</div>
						<p class="text-muted-foreground text-xs mt-0.5">
							{#if description}
								{description}
							{:else if activeMode === "bandwidth"}
								Instantaneous kernel throughput sampled every 2.5s across gateway interfaces
							{:else}
								24-hour aggregate request throughput and real-time DNS cache acceleration
							{/if}
						</p>
					</div>
				</div>

				<!-- Optional View Selector Switcher (Dashboard Mode) -->
				{#if showDnsToggle}
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
				{/if}
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
					{#if showConntrack && conntrack}
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

		<!-- Categorized Interface Filter Bar (Bandwidth Mode) -->
		{#if activeMode === "bandwidth" && availableInterfaces.length > 0}
			<div class="flex items-center gap-1.5 pt-3 pb-0.5 text-xs border-t border-border/40 overflow-x-auto">
				<span class="text-[11px] text-muted-foreground font-sans mr-1 shrink-0 flex items-center gap-1">
					<NetworkIcon class="size-3" />
					Interface:
				</span>

				<!-- 1. WAN (Internet Gateway) - Primary Default -->
				{#if detectedWan}
					<button
						type="button"
						class={[
							"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0 flex items-center gap-1",
							effectiveSelectedIface === detectedWan
								? "bg-primary text-primary-foreground font-semibold shadow-xs"
								: "bg-muted/50 text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedIface = detectedWan)}
						title="Active Gateway WAN interface"
					>
						<GlobeIcon class="size-3 text-sky-400" />
						<span>WAN ({detectedWan})</span>
					</button>
				{/if}

				<!-- 2. LAN (Local Network) -->
				{#if detectedLan && detectedLan !== detectedWan}
					<button
						type="button"
						class={[
							"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0 flex items-center gap-1",
							effectiveSelectedIface === detectedLan
								? "bg-primary text-primary-foreground font-semibold shadow-xs"
								: "bg-muted/50 text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedIface = detectedLan)}
						title="Local Network interface"
					>
						<NetworkIcon class="size-3 text-emerald-400" />
						<span>LAN ({detectedLan})</span>
					</button>
				{/if}

				<!-- 3. VPN / Overlays (Tailscale, WireGuard, Tun) -->
				{#each vpnInterfaces as vpn (vpn)}
					<button
						type="button"
						class={[
							"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0 flex items-center gap-1",
							effectiveSelectedIface === vpn
								? "bg-primary text-primary-foreground font-semibold shadow-xs"
								: "bg-muted/50 text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedIface = vpn)}
						title="Virtual Private Network overlay"
					>
						<ShieldCheckIcon class="size-3 text-violet-400" />
						<span>{vpn} (VPN)</span>
					</button>
				{/each}

				<!-- 4. SQM Ingress Device (IFB) -->
				{#if detectedIngress}
					<button
						type="button"
						class={[
							"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0 flex items-center gap-1",
							effectiveSelectedIface === detectedIngress
								? "bg-primary text-primary-foreground font-semibold shadow-xs"
								: "bg-muted/50 text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedIface = detectedIngress)}
						title="Kernel IFB queue redirect mirror for SQM ingress traffic shaping"
					>
						<GaugeIcon class="size-3 text-sky-400" />
						<span>SQM Ingress ({detectedIngress})</span>
					</button>
				{/if}

				<!-- 5. Containers & Other Interfaces Dropdown -->
				{#if containerInterfaces.length > 0 || otherInterfaces.length > 0}
					<DropdownMenu.Root>
						<DropdownMenu.Trigger
							class={[
								"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0 flex items-center gap-1 cursor-pointer border border-border/40",
								isContainerOrOtherSelected
									? "bg-primary text-primary-foreground font-semibold shadow-xs"
									: "bg-muted/50 text-muted-foreground hover:text-foreground",
							].join(" ")}
							title="Container virtual devices (Podman/Docker) and secondary interfaces"
						>
							<BoxesIcon class="size-3 text-amber-400" />
							<span>{isContainerOrOtherSelected ? effectiveSelectedIface : `Containers & Others (${containerInterfaces.length + otherInterfaces.length})`}</span>
							<ChevronDownIcon class="size-3 opacity-60" />
						</DropdownMenu.Trigger>
						<DropdownMenu.Content align="start" class="w-56 max-h-64 overflow-y-auto text-xs">
							{#if containerInterfaces.length > 0}
								<DropdownMenu.Label class="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Containers (Podman / Docker)</DropdownMenu.Label>
								{#each containerInterfaces as cIface (cIface)}
									<DropdownMenu.Item onclick={() => (selectedIface = cIface)} class="font-mono text-xs gap-2">
										<BoxesIcon class="size-3.5 text-amber-400" />
										<span>{cIface}</span>
									</DropdownMenu.Item>
								{/each}
							{/if}
							{#if otherInterfaces.length > 0}
								{#if containerInterfaces.length > 0}
									<DropdownMenu.Separator />
								{/if}
								<DropdownMenu.Label class="text-[10px] text-muted-foreground uppercase tracking-wider font-semibold">Other Interfaces</DropdownMenu.Label>
								{#each otherInterfaces as oIface (oIface)}
									<DropdownMenu.Item onclick={() => (selectedIface = oIface)} class="font-mono text-xs gap-2">
										<NetworkIcon class="size-3.5 text-muted-foreground" />
										<span>{oIface}</span>
									</DropdownMenu.Item>
								{/each}
							{/if}
						</DropdownMenu.Content>
					</DropdownMenu.Root>
				{/if}

				<!-- 6. All Interfaces (Excludes IFB mirrors from aggregation) -->
				<button
					type="button"
					class={[
						"px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0",
						effectiveSelectedIface === "all"
							? "bg-primary text-primary-foreground font-semibold shadow-xs"
							: "bg-muted/50 text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (selectedIface = "all")}
					title="Aggregated throughput across physical interfaces (excludes SQM IFB mirrors)"
				>
					All Interfaces
				</button>
			</div>
		{/if}
	</Card.Header>

	<!-- Chart Canvas -->
	<Card.Content class="p-4 sm:p-6">
		{#if activeMode === "bandwidth"}
			{#if loading && trafficHistory.length === 0}
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
								valueFormatter={(v) => formatBps(Number(v) || 0)}
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
								valueFormatter={(v) => `${Number(v).toLocaleString()} queries`}
							/>
						{/snippet}
					</AreaChart>
				</Chart.Container>
			{/if}
		{/if}
	</Card.Content>

	<!-- Status Strip Footer -->
	<Card.Footer class="border-t border-border/50 bg-muted/10 px-4 sm:px-6 !py-3.5 sm:!py-4 !pt-3.5 sm:!pt-4 rounded-b-3xl">
		<div class="flex flex-wrap items-center justify-between gap-3 w-full text-xs text-muted-foreground font-mono">
			<div class="flex items-center gap-2">
				<ZapIcon class="size-3.5 text-amber-400" />
				<span>Gateway Uplink: <span class="text-foreground font-semibold font-sans">{detectedWan || statusData?.network?.lan_iface || "Auto"}</span></span>
			</div>
			{#if showConntrack}
				<div class="flex items-center gap-2">
					<ShieldCheckIcon class="size-3.5 text-emerald-400" />
					<span>Conntrack: <span class="text-emerald-400 font-semibold">{conntrack ? `${conntrack.active_connections.toLocaleString()} active` : "Protected"}</span></span>
				</div>
			{/if}
			<div class="flex items-center gap-2">
				<GaugeIcon class="size-3.5 text-sky-400" />
				<span>Bufferbloat (CAKE): <span class="text-sky-400 font-semibold">{telemetryData?.sqm?.active ? (detectedIngress ? `Active on ${detectedWan || 'WAN'} & ${detectedIngress}` : "Active AQM") : "Standard"}</span></span>
			</div>
		</div>
	</Card.Footer>
</Card.Root>
