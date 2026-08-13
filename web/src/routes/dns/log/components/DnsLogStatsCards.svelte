<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import type { DnsQueryLogEntry, DnsStatsResponse } from "$lib/api/types";

	let {
		loading = false,
		isLive = true,
		entries = [],
		total = 0,
		stats = null,
	}: {
		loading?: boolean;
		isLive?: boolean;
		entries?: DnsQueryLogEntry[];
		total?: number;
		stats?: DnsStatsResponse | null;
	} = $props();

	const totalQueries = $derived(stats?.total_requests ?? total);

	const blockedCount = $derived.by(() => {
		if (
			stats &&
			typeof stats.blocked_queries === "number" &&
			stats.total_requests > 0
		) {
			return stats.blocked_queries;
		}
		return entries.filter(
			(e) =>
				e.result.toLowerCase().includes("block") ||
				e.result.toLowerCase().includes("deny"),
		).length;
	});

	const blockRatio = $derived.by(() => {
		if (stats && stats.total_requests > 0) {
			return Math.round(
				(stats.blocked_queries / stats.total_requests) * 100,
			);
		}
		return entries.length > 0
			? Math.round((blockedCount / entries.length) * 100)
			: 0;
	});

	const avgLatencyUs = $derived.by(() => {
		const valid = entries.filter((e) => e.upstream_us > 0);
		if (valid.length === 0) return 0;
		const sum = valid.reduce((acc, curr) => acc + curr.upstream_us, 0);
		return Math.round(sum / valid.length);
	});

	function formatLatency(us: number): string {
		if (us === 0) return "0 ms";
		if (us < 1000) return `${us} µs`;
		return `${(us / 1000).toFixed(1)} ms`;
	}
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Total Logged Queries -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium font-medium"
				>Logged Queries</Card.Title
			>
			<ListFilterIcon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading && entries.length === 0}
				<Skeleton class="h-8 w-28 mb-1" />
				<Skeleton class="h-3 w-36" />
			{:else}
				<div class="text-2xl font-bold">
					{totalQueries.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					{entries.length} queries loaded in view
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Live Stream Status -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Stream Status</Card.Title>
			<RadioIcon
				class="h-4 w-4 {isLive
					? 'text-emerald-500 animate-pulse'
					: 'text-muted-foreground'}"
			/>
		</Card.Header>
		<Card.Content>
			{#if loading && entries.length === 0}
				<Skeleton class="h-8 w-24 mb-1" />
				<Skeleton class="h-3 w-32" />
			{:else}
				<div class="flex items-center gap-2">
					<div class="text-2xl font-bold">
						{isLive ? "Live Feed" : "Paused"}
					</div>
					<span
						class="h-2.5 w-2.5 rounded-full {isLive
							? 'bg-emerald-500 animate-ping'
							: 'bg-amber-500'}"
					></span>
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					{isLive
						? "Streaming incoming events via SSE"
						: "Real-time updates suspended"}
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Block Ratio -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Blocked Ratio</Card.Title>
			<ShieldAlertIcon class="h-4 w-4 text-rose-500" />
		</Card.Header>
		<Card.Content>
			{#if loading && entries.length === 0}
				<Skeleton class="h-8 w-20 mb-1" />
				<Skeleton class="h-3 w-28" />
			{:else}
				<div class="text-2xl font-bold">
					{blockRatio}%
					<span class="text-xs text-muted-foreground font-normal">
						({blockedCount} blocked)
					</span>
				</div>
				<div
					class="mt-2 h-1.5 w-full bg-secondary rounded-full overflow-hidden"
				>
					<div
						class="h-full bg-rose-500 transition-all duration-300"
						style="width: {blockRatio}%"
					></div>
				</div>
				<p class="text-xs text-muted-foreground mt-1.5">
					Filtered by adblock rules or blacklists
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Avg Upstream Latency -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium"
				>Avg Upstream Latency</Card.Title
			>
			<GaugeIcon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading && entries.length === 0}
				<Skeleton class="h-8 w-24 mb-1" />
				<Skeleton class="h-3 w-32" />
			{:else}
				<div class="text-2xl font-bold font-mono">
					{formatLatency(avgLatencyUs)}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Microsecond resolution per query
				</p>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
