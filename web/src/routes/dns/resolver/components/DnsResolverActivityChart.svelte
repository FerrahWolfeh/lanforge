<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Chart from "$lib/components/ui/chart/index.js";
	import { AreaChart, BarChart } from "layerchart";
	import ChartAreaIcon from "@lucide/svelte/icons/chart-area";
	import ChartColumnIcon from "@lucide/svelte/icons/chart-column";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import type {
		DnsAnalyticsResponse,
		DnsStatsResponse,
	} from "$lib/api/types";

	let {
		loading = true,
		analyticsData = null,
		statsData = null,
	}: {
		loading?: boolean;
		analyticsData?: DnsAnalyticsResponse | null;
		statsData?: DnsStatsResponse | null;
	} = $props();

	let chartMode = $state<"area" | "bar">("area");
	let showForwarded = $state(true);
	let showLocal = $state(true);
	let showCached = $state(true);
	let showRewritten = $state(true);
	let showBlocked = $state(true);

	const chartConfig = {
		forwarded: {
			label: "Forwarded",
			color: "#38bdf8",
		},
		local: {
			label: "Local",
			color: "#2dd4bf",
		},
		cached: {
			label: "Cached",
			color: "#34d399",
		},
		rewritten: {
			label: "Rewritten",
			color: "#c084fc",
		},
		blocked: {
			label: "Blocked",
			color: "#f43f5e",
		},
	} satisfies Chart.ChartConfig;

	const chartPoints = $derived.by(() => {
		const rates = analyticsData?.query_rate ?? [];
		const blocked = analyticsData?.blocked_query_rate ?? [];

		const now = Date.now();
		const BUCKET_MS = 15 * 60 * 1000; // 15-minute intervals matching backend aggregation
		const BUCKET_COUNT = 96; // 96 * 15m = 24 hours
		const currentBucketMs = Math.floor(now / BUCKET_MS) * BUCKET_MS;

		// Index incoming query rates by 15-minute rounded timestamp
		const ratesMap = new Map<number, (typeof rates)[0]>();
		for (const r of rates) {
			const ms = r.timestamp < 10_000_000_000 ? r.timestamp * 1000 : r.timestamp;
			const bucketKey = Math.floor(ms / BUCKET_MS) * BUCKET_MS;
			ratesMap.set(bucketKey, r);
		}

		const blockedMap = new Map<number, number>();
		for (const b of blocked) {
			const ms = b.timestamp < 10_000_000_000 ? b.timestamp * 1000 : b.timestamp;
			const bucketKey = Math.floor(ms / BUCKET_MS) * BUCKET_MS;
			blockedMap.set(bucketKey, b.count);
		}

		return Array.from({ length: BUCKET_COUNT }, (_, i) => {
			const bucketMs = currentBucketMs - (BUCKET_COUNT - 1 - i) * BUCKET_MS;
			const date = new Date(bucketMs);
			const label = `${date.getHours().toString().padStart(2, "0")}:${date.getMinutes().toString().padStart(2, "0")}`;

			const r = ratesMap.get(bucketMs);
			if (!r) {
				return {
					date,
					label,
					timestamp: bucketMs,
					total: 0,
					forwarded: 0,
					cached: 0,
					local: 0,
					rewritten: 0,
					blocked: 0,
				};
			}

			const total = r.count;
			const blkCount = r.blocked ?? blockedMap.get(bucketMs) ?? 0;
			const rwCount = r.rewritten ?? 0;
			const locCount = r.local ?? 0;
			const cacheCount =
				r.cached ??
				(statsData && statsData.total_requests > 0
					? Math.round(
							(statsData.cache_hits / statsData.total_requests) *
								Math.max(0, total - blkCount - rwCount - locCount),
						)
					: Math.floor(Math.max(0, total - blkCount - rwCount - locCount) * 0.4));
			const fwdCount =
				r.forwarded ?? Math.max(0, total - cacheCount - blkCount - rwCount - locCount);

			return {
				date,
				label,
				timestamp: bucketMs,
				total,
				forwarded: fwdCount,
				cached: cacheCount,
				local: locCount,
				rewritten: rwCount,
				blocked: blkCount,
			};
		});
	});

	const chartSummary = $derived.by(() => {
		const points = chartPoints;
		const total = points.reduce((acc, p) => acc + p.total, 0);
		const cached = points.reduce((acc, p) => acc + p.cached, 0);
		const forwarded = points.reduce((acc, p) => acc + p.forwarded, 0);
		const local = points.reduce((acc, p) => acc + p.local, 0);
		const rewritten = points.reduce((acc, p) => acc + p.rewritten, 0);
		const blocked = points.reduce((acc, p) => acc + p.blocked, 0);
		const safeTot = Math.max(1, total);
		return {
			total,
			cached,
			forwarded,
			local,
			rewritten,
			blocked,
			cachedPct: Math.round((cached / safeTot) * 100),
			forwardedPct: Math.round((forwarded / safeTot) * 100),
			localPct: Math.round((local / safeTot) * 100),
			rewrittenPct: Math.round((rewritten / safeTot) * 100),
			blockedPct: Math.round((blocked / safeTot) * 100),
		};
	});

	const activeSeries = $derived.by(() => {
		const list = [];
		if (showForwarded) {
			list.push({
				key: "forwarded",
				label: "Forwarded",
				value: "forwarded",
				color: chartConfig.forwarded.color,
			});
		}
		if (showCached) {
			list.push({
				key: "cached",
				label: "Cached",
				value: "cached",
				color: chartConfig.cached.color,
			});
		}
		if (showLocal) {
			list.push({
				key: "local",
				label: "Local",
				value: "local",
				color: chartConfig.local.color,
			});
		}
		if (showRewritten && chartSummary.rewritten > 0) {
			list.push({
				key: "rewritten",
				label: "Rewritten",
				value: "rewritten",
				color: chartConfig.rewritten.color,
			});
		}
		if (showBlocked) {
			list.push({
				key: "blocked",
				label: "Blocked",
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
				<ActivityIcon class="size-4 text-sky-400" />
				<div>
					<Card.Title class="text-base">DNS Query Activity (24h Window)</Card.Title>
					<p class="text-muted-foreground text-xs mt-0.5">
						Interactive Pi-hole style timeline categorized by resolution destination
					</p>
				</div>
			</div>

			<!-- Chart Controls & Mode Switcher -->
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
					showForwarded
						? "border-sky-500/40 bg-sky-500/15 text-sky-400 font-medium"
						: "border-border/40 bg-muted/20 text-muted-foreground line-through opacity-60 hover:opacity-100",
				].join(" ")}
				onclick={() => (showForwarded = !showForwarded)}
			>
				<span class="size-2 rounded-full bg-sky-400"></span>
				<span>Forwarded</span>
				<span class="font-mono text-[11px] opacity-80">({chartSummary.forwardedPct}%)</span>
			</button>

			<button
				type="button"
				class={[
					"flex items-center gap-1.5 rounded-full border px-2.5 py-1 transition-all cursor-pointer select-none",
					showCached
						? "border-emerald-500/40 bg-emerald-500/15 text-emerald-400 font-medium"
						: "border-border/40 bg-muted/20 text-muted-foreground line-through opacity-60 hover:opacity-100",
				].join(" ")}
				onclick={() => (showCached = !showCached)}
			>
				<span class="size-2 rounded-full bg-emerald-400"></span>
				<span>Cached</span>
				<span class="font-mono text-[11px] opacity-80">({chartSummary.cachedPct}%)</span>
			</button>

			<button
				type="button"
				class={[
					"flex items-center gap-1.5 rounded-full border px-2.5 py-1 transition-all cursor-pointer select-none",
					showLocal
						? "border-teal-500/40 bg-teal-500/15 text-teal-400 font-medium"
						: "border-border/40 bg-muted/20 text-muted-foreground line-through opacity-60 hover:opacity-100",
				].join(" ")}
				onclick={() => (showLocal = !showLocal)}
			>
				<span class="size-2 rounded-full bg-teal-400"></span>
				<span>Local</span>
				<span class="font-mono text-[11px] opacity-80">({chartSummary.localPct}%)</span>
			</button>

			{#if chartSummary.rewritten > 0}
				<button
					type="button"
					class={[
						"flex items-center gap-1.5 rounded-full border px-2.5 py-1 transition-all cursor-pointer select-none",
						showRewritten
							? "border-purple-500/40 bg-purple-500/15 text-purple-400 font-medium"
							: "border-border/40 bg-muted/20 text-muted-foreground line-through opacity-60 hover:opacity-100",
					].join(" ")}
					onclick={() => (showRewritten = !showRewritten)}
				>
					<span class="size-2 rounded-full bg-purple-400"></span>
					<span>Rewritten</span>
					<span class="font-mono text-[11px] opacity-80">({chartSummary.rewrittenPct}%)</span>
				</button>
			{/if}

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
				<span class="size-2 rounded-full bg-rose-400"></span>
				<span>Blocked</span>
				<span class="font-mono text-[11px] opacity-80">({chartSummary.blockedPct}%)</span>
			</button>
		</div>
	</Card.Header>

	<Card.Content class="p-4 sm:p-6">
		{#if loading && !analyticsData}
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
										return `${v.toLocaleDateString("en-US", { month: "short", day: "numeric" })} ${v.getHours().toString().padStart(2, "0")}:${v.getMinutes().toString().padStart(2, "0")}`;
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
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">24h Queries</span>
				<span class="text-foreground font-bold tabular-nums text-sm">{chartSummary.total.toLocaleString()}</span>
			</div>
			<div class="flex flex-col gap-0.5">
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">Cache Hits</span>
				<span class="text-emerald-400 font-bold tabular-nums text-sm">
					{chartSummary.cached.toLocaleString()} <span class="text-xs font-normal text-muted-foreground">({chartSummary.cachedPct}%)</span>
				</span>
			</div>
			<div class="flex flex-col gap-0.5">
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">Forwarded</span>
				<span class="text-sky-400 font-bold tabular-nums text-sm">
					{chartSummary.forwarded.toLocaleString()} <span class="text-xs font-normal text-muted-foreground">({chartSummary.forwardedPct}%)</span>
				</span>
			</div>
			<div class="flex flex-col gap-0.5">
				<span class="text-muted-foreground text-[10px] uppercase font-sans font-semibold tracking-wider">Blocked (Adblock)</span>
				<span class="text-rose-400 font-bold tabular-nums text-sm">
					{chartSummary.blocked.toLocaleString()} <span class="text-xs font-normal text-muted-foreground">({chartSummary.blockedPct}%)</span>
				</span>
			</div>
		</div>
	</Card.Footer>
</Card.Root>
