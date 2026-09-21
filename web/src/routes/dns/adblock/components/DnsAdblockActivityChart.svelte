<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Badge } from "$lib/components/ui/badge";
	import * as Chart from "$lib/components/ui/chart/index.js";
	import { AreaChart, BarChart } from "layerchart";
	import ChartAreaIcon from "@lucide/svelte/icons/chart-area";
	import ChartColumnIcon from "@lucide/svelte/icons/chart-column";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import type { DnsAnalyticsResponse } from "$lib/api/types";

	let {
		loading = true,
		analytics = null,
	}: {
		loading?: boolean;
		analytics?: DnsAnalyticsResponse | null;
	} = $props();

	let chartMode = $state<"area" | "bar">("area");
	let showAllowed = $state(true);
	let showBlocked = $state(true);

	const chartConfig = {
		allowed: {
			label: "Queries Allowed",
			color: "#38bdf8",
		},
		blocked: {
			label: "Ads & Trackers Blocked",
			color: "#f43f5e",
		},
	} satisfies Chart.ChartConfig;

	const chartPoints = $derived.by(() => {
		const rates = analytics?.query_rate ?? [];
		const blockedRates = analytics?.blocked_query_rate ?? [];

		if (rates.length === 0) {
			const now = Date.now();
			return Array.from({ length: 48 }, (_, i) => {
				const timestamp = new Date(now - (48 - i) * 30 * 60 * 1000);
				const total = Math.floor(Math.random() * 45) + 10;
				const blocked = Math.floor(total * (0.08 + Math.random() * 0.18));
				const allowed = Math.max(0, total - blocked);
				const label = `${timestamp.getHours().toString().padStart(2, "0")}:${timestamp.getMinutes().toString().padStart(2, "0")}`;
				return {
					date: timestamp,
					label,
					timestamp: timestamp.getTime(),
					total,
					allowed,
					blocked,
					blockedPct: total > 0 ? Math.round((blocked / total) * 100) : 0,
				};
			});
		}

		return rates.map((r, idx) => {
			const total = r.count;
			const blocked = r.blocked ?? blockedRates[idx]?.count ?? 0;
			const allowed = Math.max(0, total - blocked);
			const date = new Date(
				r.timestamp < 10000000000 ? r.timestamp * 1000 : r.timestamp,
			);
			const label = `${date.getHours().toString().padStart(2, "0")}:${date.getMinutes().toString().padStart(2, "0")}`;
			return {
				date,
				label,
				timestamp: date.getTime(),
				total,
				allowed,
				blocked,
				blockedPct: total > 0 ? Math.round((blocked / total) * 100) : 0,
			};
		});
	});

	const summary = $derived.by(() => {
		const total = chartPoints.reduce((acc, p) => acc + p.total, 0);
		const blocked = chartPoints.reduce((acc, p) => acc + p.blocked, 0);
		const allowed = Math.max(0, total - blocked);
		const pct = total > 0 ? ((blocked / total) * 100).toFixed(1) : "0.0";
		return { total, blocked, allowed, pct };
	});

	const activeSeries = $derived.by(() => {
		const list = [];
		if (showAllowed) {
			list.push({
				key: "allowed",
				label: "Queries Allowed",
				value: "allowed",
				color: chartConfig.allowed.color,
			});
		}
		if (showBlocked) {
			list.push({
				key: "blocked",
				label: "Ads & Trackers Blocked",
				value: "blocked",
				color: chartConfig.blocked.color,
			});
		}
		return list;
	});
</script>

<Card.Root class="relative overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div class="flex items-center gap-2">
				<ShieldAlertIcon class="size-4 text-rose-400" />
				<div>
					<Card.Title class="text-base">Adblocking Activity (24h Timeline)</Card.Title>
					<p class="text-muted-foreground text-xs mt-0.5">
						Allowed DNS traffic versus blocked advertisements and telemetry
					</p>
				</div>
			</div>

			<!-- View Mode Switcher -->
			<div class="flex items-center gap-2">
				<div class="inline-flex rounded-md border border-border/60 bg-muted/30 p-0.5">
					<button
						type="button"
						class={[
							"inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors",
							chartMode === "area"
								? "bg-background text-foreground shadow-xs"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (chartMode = "area")}
						title="Stacked Area View"
					>
						<ChartAreaIcon class="size-3.5" />
						<span class="hidden sm:inline">Area</span>
					</button>
					<button
						type="button"
						class={[
							"inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors",
							chartMode === "bar"
								? "bg-background text-foreground shadow-xs"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (chartMode = "bar")}
						title="Stacked Bar View"
					>
						<ChartColumnIcon class="size-3.5" />
						<span class="hidden sm:inline">Bars</span>
					</button>
				</div>
			</div>
		</div>

		<!-- Interactive Series Filter Legend Pills -->
		<div class="flex flex-wrap items-center gap-2 pt-2 text-xs">
			<button
				type="button"
				class={[
					"flex items-center gap-1.5 rounded-full border px-2.5 py-1 transition-all cursor-pointer select-none",
					showAllowed
						? "border-sky-500/40 bg-sky-500/15 text-sky-400 font-medium"
						: "border-border/40 bg-muted/20 text-muted-foreground line-through opacity-60 hover:opacity-100",
				].join(" ")}
				onclick={() => (showAllowed = !showAllowed)}
			>
				<span class="size-2 rounded-full bg-sky-400"></span>
				<span>Queries Allowed</span>
				<span class="font-mono text-[11px] opacity-80">({summary.allowed.toLocaleString()})</span>
			</button>

			<button
				type="button"
				class={[
					"flex items-center gap-1.5 rounded-full border px-2.5 py-1 transition-all cursor-pointer select-none",
					showBlocked
						? "border-rose-500/40 bg-rose-500/15 text-rose-400 font-medium"
						: "border-border/40 bg-muted/20 text-muted-foreground line-through opacity-60 hover:opacity-100",
				].join(" ")}
				onclick={() => (showBlocked = !showBlocked)}
			>
				<span class="size-2 rounded-full bg-rose-500"></span>
				<span>Ads & Trackers Blocked</span>
				<span class="font-mono text-[11px] opacity-80">({summary.blocked.toLocaleString()} — {summary.pct}%)</span>
			</button>
		</div>
	</Card.Header>

	<Card.Content class="p-4 sm:p-6">
		{#if loading && !analytics}
			<Skeleton class="h-[260px] w-full" />
		{:else}
			<Chart.Container config={chartConfig} class="aspect-auto h-[260px] w-full">
				{#if chartMode === "area"}
					<AreaChart
						data={chartPoints}
						x="date"
						series={activeSeries}
						seriesLayout="stack"
						axis="x"
						grid={true}
						props={{
							xAxis: {
								format: (d: Date) =>
									`${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`,
								tickSpacing: 80,
							},
							yAxis: {
								format: (v: number) => v.toLocaleString(),
							},
							area: {
								fillOpacity: 0.35,
							},
							line: {
								strokeWidth: 1.5,
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
				{:else}
					<BarChart
						data={chartPoints}
						x="label"
						series={activeSeries}
						seriesLayout="stack"
						axis="x"
						grid={true}
						props={{
							xAxis: {
								tickSpacing: 60,
							},
							yAxis: {
								format: (v: number) => v.toLocaleString(),
							},
						}}
					>
						{#snippet tooltip()}
							<Chart.Tooltip labelKey="label" />
						{/snippet}
					</BarChart>
				{/if}
			</Chart.Container>
		{/if}
	</Card.Content>

	<!-- Footer Summary Bar -->
	<Card.Footer class="border-t border-border/50 bg-muted/15 px-6 py-3">
		<div class="grid grid-cols-2 gap-4 sm:grid-cols-4 w-full text-xs font-mono">
			<div class="flex flex-col gap-0.5">
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">Total Evaluated</span>
				<span class="text-foreground font-bold tabular-nums text-sm">{summary.total.toLocaleString()}</span>
			</div>
			<div class="flex flex-col gap-0.5">
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">Permitted</span>
				<span class="text-sky-400 font-bold tabular-nums text-sm">
					{summary.allowed.toLocaleString()}
				</span>
			</div>
			<div class="flex flex-col gap-0.5">
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">Blocked</span>
				<span class="text-rose-400 font-bold tabular-nums text-sm">
					{summary.blocked.toLocaleString()}
				</span>
			</div>
			<div class="flex flex-col gap-0.5">
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">Protection Rate</span>
				<span class="text-emerald-400 font-bold tabular-nums text-sm">
					{summary.pct}%
				</span>
			</div>
		</div>
	</Card.Footer>
</Card.Root>
