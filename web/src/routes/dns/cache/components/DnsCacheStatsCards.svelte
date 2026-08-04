<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import type { DnsCacheStatsExtResponse } from "$lib/api/types";

	let {
		loading = true,
		stats = null,
	}: {
		loading?: boolean;
		stats?: DnsCacheStatsExtResponse | null;
	} = $props();

	function formatBytes(bytes: number): string {
		if (bytes === 0) return "0 B";
		const k = 1024;
		const sizes = ["B", "KB", "MB", "GB"];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
	}

	function formatTtl(secs: number): string {
		if (secs <= 0) return "0s";
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		if (m === 0) return `${s}s`;
		return `${m}m ${s}s`;
	}

	const usagePct = $derived.by(() => {
		if (!stats || !stats.capacity || stats.capacity === 0) return 0;
		return Math.min(
			100,
			Math.round((stats.total_entries / stats.capacity) * 100),
		);
	});
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Occupancy -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Cache Occupancy</Card.Title>
			<DatabaseIcon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-28 mb-1" />
				<Skeleton class="h-3 w-36" />
			{:else}
				<div class="text-2xl font-bold">
					{(stats?.total_entries ?? 0).toLocaleString()}
					<span class="text-xs text-muted-foreground font-normal">
						/ {(stats?.capacity ?? 10000).toLocaleString()}
					</span>
				</div>
				<div
					class="mt-2 h-1.5 w-full bg-secondary rounded-full overflow-hidden"
				>
					<div
						class="h-full bg-primary transition-all duration-300"
						style="width: {usagePct}%"
					></div>
				</div>
				<p class="text-xs text-muted-foreground mt-1.5">
					{usagePct}% max capacity utilized
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Memory Footprint -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Memory Footprint</Card.Title
			>
			<CpuIcon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-24 mb-1" />
				<Skeleton class="h-3 w-32" />
			{:else}
				<div class="text-2xl font-bold">
					{formatBytes(stats?.memory_usage_bytes ?? 0)}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					In-memory hash index overhead
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Average TTL -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium"
				>Average Remaining TTL</Card.Title
			>
			<ClockIcon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-24 mb-1" />
				<Skeleton class="h-3 w-32" />
			{:else}
				<div class="text-2xl font-bold">
					{formatTtl(stats?.average_ttl_secs ?? 0)}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Min TTL enforced: {stats?.min_ttl ?? 0}s
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Evictions -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Cache Evictions</Card.Title>
			<Trash2Icon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-20 mb-1" />
				<Skeleton class="h-3 w-28" />
			{:else}
				<div class="text-2xl font-bold">
					{(stats?.evictions ?? 0).toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Entries cleared due to capacity pressure
				</p>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
