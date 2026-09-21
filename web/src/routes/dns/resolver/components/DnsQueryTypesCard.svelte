<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Badge } from "$lib/components/ui/badge";
	import * as Chart from "$lib/components/ui/chart/index.js";
	import { PieChart } from "layerchart";
	import ChartPieIcon from "@lucide/svelte/icons/chart-pie";
	import type { DnsAnalyticsResponse } from "$lib/api/types";

	let {
		loading = true,
		analyticsData = null,
	}: {
		loading?: boolean;
		analyticsData?: DnsAnalyticsResponse | null;
	} = $props();

	const typeColors: Record<string, string> = {
		A: "#38bdf8", // Sky 400
		AAAA: "#c084fc", // Purple 400
		HTTPS: "#818cf8", // Indigo 400
		PTR: "#34d399", // Emerald 400
		CNAME: "#fbbf24", // Amber 400
		TXT: "#94a3b8", // Slate 400
		SRV: "#2dd4bf", // Teal 400
		MX: "#f43f5e", // Rose 400
		SOA: "#a78bfa", // Violet 400
		NS: "#22d3ee", // Cyan 400
	};

	const chartConfig = {
		A: { label: "A (IPv4)", color: "#38bdf8" },
		AAAA: { label: "AAAA (IPv6)", color: "#c084fc" },
		HTTPS: { label: "HTTPS", color: "#818cf8" },
		PTR: { label: "PTR (Reverse)", color: "#34d399" },
		CNAME: { label: "CNAME", color: "#fbbf24" },
		TXT: { label: "TXT", color: "#94a3b8" },
		SRV: { label: "SRV", color: "#2dd4bf" },
		MX: { label: "MX", color: "#f43f5e" },
		SOA: { label: "SOA", color: "#a78bfa" },
		NS: { label: "NS", color: "#22d3ee" },
		other: { label: "Other", color: "#64748b" },
	} satisfies Chart.ChartConfig;

	const queryTypesList = $derived.by(() => {
		const raw = analyticsData?.query_types ?? [];
		if (raw.length > 0) {
			const total = raw.reduce((sum, item) => sum + item.count, 0) || 1;
			return raw
				.map((item) => ({
					qtype: item.qtype,
					count: item.count,
					pct: Math.round((item.count / total) * 100),
					color: typeColors[item.qtype] || "#64748b",
				}))
				.sort((a, b) => b.count - a.count);
		}

		// Fallback Pi-hole standard distribution mock
		return [
			{ qtype: "A", count: 1842, pct: 57, color: typeColors.A },
			{ qtype: "AAAA", count: 760, pct: 23, color: typeColors.AAAA },
			{ qtype: "HTTPS", count: 395, pct: 12, color: typeColors.HTTPS },
			{ qtype: "PTR", count: 198, pct: 6, color: typeColors.PTR },
			{ qtype: "TXT", count: 48, pct: 2, color: typeColors.TXT },
		];
	});

	const totalQueries = $derived.by(() => {
		return queryTypesList.reduce((sum, item) => sum + item.count, 0);
	});
</script>

<Card.Root class="flex flex-col h-full overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<ChartPieIcon class="size-4 text-purple-400" />
				<div>
					<Card.Title class="text-base">Query Types</Card.Title>
					<p class="text-muted-foreground text-xs mt-0.5">Distribution of requested record types</p>
				</div>
			</div>
			<Badge variant="outline" class="font-mono text-[10px]">
				{queryTypesList.length} types
			</Badge>
		</div>
	</Card.Header>

	<Card.Content class="p-4 sm:p-5 flex flex-col justify-between flex-1 gap-4">
		{#if loading && !analyticsData}
			<Skeleton class="h-44 w-full" />
			<div class="flex flex-col gap-2">
				<Skeleton class="h-4 w-full" />
				<Skeleton class="h-4 w-full" />
				<Skeleton class="h-4 w-full" />
			</div>
		{:else}
			<!-- Donut Chart with Centered Total -->
			<div class="relative flex items-center justify-center py-1">
				<Chart.Container config={chartConfig} class="h-[175px] w-full max-w-[210px] aspect-square">
					<PieChart
						data={queryTypesList}
						key="qtype"
						value="count"
						c="color"
						innerRadius={0.65}
						cornerRadius={3}
						padAngle={0.02}
					>
						{#snippet tooltip()}
							<Chart.Tooltip labelKey="qtype" />
						{/snippet}
					</PieChart>
				</Chart.Container>

				<!-- Center Label -->
				<div class="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
					<span class="text-xl font-bold font-mono tracking-tight text-foreground">
						{totalQueries.toLocaleString()}
					</span>
					<span class="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">
						Queries
					</span>
				</div>
			</div>

			<!-- Compact Type Breakdown List -->
			<div class="flex flex-col gap-1.5 border-t border-border/50 pt-3">
				{#each queryTypesList.slice(0, 5) as item (item.qtype)}
					<div class="flex items-center justify-between text-xs font-mono">
						<div class="flex items-center gap-2">
							<span class="size-2 rounded-full" style="background-color: {item.color}"></span>
							<span class="text-foreground font-semibold font-sans">{item.qtype}</span>
						</div>
						<div class="flex items-center gap-2">
							<span class="text-muted-foreground">{item.count.toLocaleString()}</span>
							<Badge variant="secondary" class="font-mono text-[10px] px-1.5 py-0">
								{item.pct}%
							</Badge>
						</div>
					</div>
				{/each}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
