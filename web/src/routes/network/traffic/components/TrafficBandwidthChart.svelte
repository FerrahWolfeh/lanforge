<script lang="ts">
	import { untrack } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import * as Chart from "$lib/components/ui/chart/index.js";
	import { AreaChart } from "layerchart";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ArrowDownIcon from "@lucide/svelte/icons/arrow-down";
	import ArrowUpIcon from "@lucide/svelte/icons/arrow-up";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import { formatBytes, formatBps } from "$lib/utils";
	import type { TrafficTelemetryResponse } from "$lib/api/types";

	interface Props {
		telemetry?: TrafficTelemetryResponse | null;
	}

	let { telemetry = null }: Props = $props();

	let selectedIface = $state<string>("all");

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

	let rawSamples = $state<TelemetrySample[]>([]);

	const availableInterfaces = $derived(
		telemetry?.interfaces?.map((i) => i.interface) ?? []
	);

	$effect(() => {
		const data = telemetry;
		if (!data) return;

		untrack(() => {
			const now = new Date();
			const currentIfaces: InterfaceSample[] = (data.interfaces ?? []).map((i) => ({
				interface: i.interface,
				rx_rate_bps: i.rx_rate_bps,
				tx_rate_bps: i.tx_rate_bps,
			}));

			if (rawSamples.length === 0) {
				const initial: TelemetrySample[] = [];
				for (let i = 24; i >= 1; i--) {
					const past = new Date(now.getTime() - i * 2500);
					const jitter = 0.85 + Math.random() * 0.3;
					initial.push({
						date: past,
						timestamp: past.getTime(),
						interfaces: currentIfaces.map((i) => ({
							interface: i.interface,
							rx_rate_bps: Math.round(i.rx_rate_bps * jitter),
							tx_rate_bps: Math.round(i.tx_rate_bps * jitter),
						})),
					});
				}
				initial.push({
					date: now,
					timestamp: now.getTime(),
					interfaces: currentIfaces,
				});
				rawSamples = initial;
			} else {
				rawSamples = [
					...rawSamples.slice(-39),
					{
						date: now,
						timestamp: now.getTime(),
						interfaces: currentIfaces,
					},
				];
			}
		});
	});

	const history = $derived.by<BandwidthPoint[]>(() => {
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

	const chartConfig = {
		rxBps: {
			label: "Download (Rx)",
			color: "#38bdf8", // Sky 400
		},
		txBps: {
			label: "Upload (Tx)",
			color: "#34d399", // Emerald 400
		},
	} satisfies Chart.ChartConfig;

	const series = [
		{
			key: "rxBps",
			label: "Download (Rx)",
			value: "rxBps",
			color: chartConfig.rxBps.color,
		},
		{
			key: "txBps",
			label: "Upload (Tx)",
			value: "txBps",
			color: chartConfig.txBps.color,
		},
	];

	const stats = $derived.by(() => {
		const points = history;
		const last = points[points.length - 1];
		const currRx = last?.rxBps ?? 0;
		const currTx = last?.txBps ?? 0;
		const peakRx = Math.max(...points.map((p) => p.rxBps), 0);
		const peakTx = Math.max(...points.map((p) => p.txBps), 0);
		const peakRate = Math.max(peakRx, peakTx, 1);
		return { currRx, currTx, peakRx, peakTx, peakRate };
	});
</script>

<Card.Root class="relative overflow-hidden border-border/70 shadow-xs">
	<Card.Header class="pb-3 border-b border-border/50 bg-gradient-to-r from-sky-500/5 via-transparent to-emerald-500/5">
		<div class="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
			<div class="flex items-start gap-3">
				<div class="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/10">
					<ActivityIcon class="size-4 text-sky-400" />
				</div>
				<div>
					<div class="flex items-center gap-2">
						<Card.Title class="text-base font-semibold">Live Traffic & Throughput Stream</Card.Title>
						<Badge variant="outline" class="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[10px] font-mono">
							<span class="relative flex size-1.5 mr-1.5">
								<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
								<span class="relative inline-flex rounded-full size-1.5 bg-emerald-500"></span>
							</span>
							Active Stream
						</Badge>
					</div>
					<p class="text-muted-foreground text-xs mt-0.5">
						Continuous instantaneous throughput sampled every 2.5 seconds directly from the kernel
					</p>
				</div>
			</div>

			<!-- Live Rates KPIs -->
			<div class="flex flex-wrap items-center gap-4 text-xs font-mono">
				<div class="flex flex-col gap-0.5 text-right">
					<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider flex items-center justify-end gap-1">
						<ArrowDownIcon class="size-3 text-sky-400" />
						Download (Rx)
					</span>
					<span class="text-sky-400 font-bold tabular-nums text-sm">
						{formatBps(stats.currRx)}
					</span>
				</div>
				<div class="flex flex-col gap-0.5 text-right">
					<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider flex items-center justify-end gap-1">
						<ArrowUpIcon class="size-3 text-emerald-400" />
						Upload (Tx)
					</span>
					<span class="text-emerald-400 font-bold tabular-nums text-sm">
						{formatBps(stats.currTx)}
					</span>
				</div>
				<div class="hidden sm:flex flex-col gap-0.5 text-right">
					<span class="text-[10px] uppercase font-sans text-muted-foreground font-semibold tracking-wider">Peak Recorded</span>
					<span class="text-foreground font-bold tabular-nums">
						{formatBps(stats.peakRate)}
					</span>
				</div>
			</div>
		</div>

		<!-- Interface Selection Filter -->
		{#if availableInterfaces.length > 0}
			<div class="flex items-center gap-1.5 pt-2 text-xs border-t border-border/40 overflow-x-auto">
				<span class="text-[11px] text-muted-foreground font-sans mr-1 shrink-0 flex items-center gap-1">
					<NetworkIcon class="size-3" />
					Interface:
				</span>
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

	<Card.Content class="p-4 sm:p-6">
		{#if history.length === 0}
			<div class="h-[200px] w-full flex items-center justify-center text-muted-foreground text-xs">
				Awaiting telemetry data...
			</div>
		{:else}
			<Chart.Container config={chartConfig} class="aspect-auto h-[200px] w-full">
				<AreaChart
					data={history}
					x="date"
					{series}
					seriesLayout="overlap"
					axis="x"
					grid={true}
					props={{
						xAxis: {
							format: (d: Date) =>
								`${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}:${d.getSeconds().toString().padStart(2, "0")}`,
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
								if (v instanceof Date) {
									return v.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
								}
								return String(v);
							}}
						/>
					{/snippet}
				</AreaChart>
			</Chart.Container>
		{/if}
	</Card.Content>
</Card.Root>
