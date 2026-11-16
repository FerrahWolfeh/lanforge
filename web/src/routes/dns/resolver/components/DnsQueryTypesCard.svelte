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
		A: "var(--chart-1)",
		AAAA: "var(--chart-3)",
		HTTPS: "var(--chart-3)",
		PTR: "var(--chart-2)",
		CNAME: "var(--chart-4)",
		TXT: "var(--muted-foreground)",
		SRV: "var(--chart-2)",
		MX: "var(--chart-5)",
		SOA: "var(--chart-3)",
		NS: "var(--chart-1)",
	};

	const chartConfig = {
		A: { label: "A (IPv4)", color: "var(--chart-1)" },
		AAAA: { label: "AAAA (IPv6)", color: "var(--chart-3)" },
		HTTPS: { label: "HTTPS", color: "var(--chart-3)" },
		PTR: { label: "PTR (Reverse)", color: "var(--chart-2)" },
		CNAME: { label: "CNAME", color: "var(--chart-4)" },
		TXT: { label: "TXT", color: "var(--muted-foreground)" },
		SRV: { label: "SRV", color: "var(--chart-2)" },
		MX: { label: "MX", color: "var(--chart-5)" },
		SOA: { label: "SOA", color: "var(--chart-3)" },
		NS: { label: "NS", color: "var(--chart-1)" },
		other: { label: "Other", color: "var(--muted-foreground)" },
	} satisfies Chart.ChartConfig;

	const queryTypesList = $derived.by(() => {
		const raw = analyticsData?.query_types ?? [];
		const total = raw.reduce((sum, item) => sum + item.count, 0) || 1;
		return raw
			.map((item) => ({
				qtype: item.qtype,
				count: item.count,
				pct: Math.round((item.count / total) * 100),
				color: typeColors[item.qtype] || "var(--muted-foreground)",
			}))
			.sort((a, b) => b.count - a.count);
	});

	const totalQueries = $derived.by(() => {
		return queryTypesList.reduce((sum, item) => sum + item.count, 0);
	});
</script>

<Card.Root class="flex flex-col h-full overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<ChartPieIcon class="size-4 text-muted-foreground" />
				<div>
					<Card.Title class="text-base">Query Types</Card.Title>
					<p class="text-muted-foreground text-xs mt-0.5">Distribution of requested record types</p>
				</div>
			</div>
			<Badge variant="outline" class="font-mono text-xs">
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
		{:else if queryTypesList.length === 0}
			<div class="flex flex-1 flex-col items-center justify-center gap-2 py-10 text-center">
				<ChartPieIcon class="size-8 text-muted-foreground/40" />
				<p class="text-sm text-muted-foreground">No queries recorded yet</p>
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
					<span class="text-xs font-medium text-muted-foreground">
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
							<Badge variant="secondary" class="font-mono text-xs px-1.5 py-0">
								{item.pct}%
							</Badge>
						</div>
					</div>
				{/each}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
