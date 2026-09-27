<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import ServerIcon from "@lucide/svelte/icons/server";
	import { formatUptime } from "$lib/utils";
	import type { SseEvent, StatusResponse } from "$lib/api/types";

	let {
		loading = false,
		isLive = true,
		reconnecting = false,
		events = [],
		bufferLimit = 500,
		status = null,
	}: {
		loading?: boolean;
		isLive?: boolean;
		reconnecting?: boolean;
		events?: SseEvent[];
		bufferLimit?: number;
		status?: StatusResponse | null;
	} = $props();

	const bufferUsagePct = $derived(
		bufferLimit > 0 ? Math.min(100, Math.round((events.length / bufferLimit) * 100)) : 0
	);

	const topicCounts = $derived.by(() => {
		const counts: Record<string, number> = {};
		for (const ev of events) {
			const topic = ev.topic || "system";
			counts[topic] = (counts[topic] || 0) + 1;
		}
		return counts;
	});

	const topTopic = $derived.by(() => {
		const entries = Object.entries(topicCounts);
		if (entries.length === 0) return { name: "None", count: 0 };
		entries.sort((a, b) => b[1] - a[1]);
		return { name: entries[0][0], count: entries[0][1] };
	});
</script>

<div class="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
	<!-- Stream Status Card -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2 space-y-0">
			<Card.Title class="text-sm font-medium">Stream Status</Card.Title>
			<RadioIcon
				class="h-4 w-4 {reconnecting
					? 'text-amber-500 animate-spin'
					: isLive
						? 'text-emerald-500 animate-pulse'
						: 'text-muted-foreground'}"
			/>
		</Card.Header>
		<Card.Content>
			{#if loading && events.length === 0}
				<Skeleton class="h-8 w-24 mb-1" />
				<Skeleton class="h-3 w-32" />
			{:else}
				<div class="flex items-center gap-2">
					<div class="text-2xl font-bold">
						{#if reconnecting}
							Reconnecting...
						{:else if isLive}
							Live Stream
						{:else}
							Paused
						{/if}
					</div>
					<span
						class="h-2.5 w-2.5 rounded-full {reconnecting
							? 'bg-amber-500 animate-ping'
							: isLive
								? 'bg-emerald-500 animate-ping'
								: 'bg-amber-500'}"
					></span>
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					{#if reconnecting}
						Retrying SSE bus connection
					{:else if isLive}
						Connected to internal event bus
					{:else}
						Incoming stream updates paused
					{/if}
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Buffer & Events Count Card -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2 space-y-0">
			<Card.Title class="text-sm font-medium">Buffer Utilization</Card.Title>
			<ActivityIcon class="h-4 w-4 text-primary" />
		</Card.Header>
		<Card.Content>
			{#if loading && events.length === 0}
				<Skeleton class="h-8 w-28 mb-1" />
				<Skeleton class="h-3 w-32" />
			{:else}
				<div class="text-2xl font-bold">
					{events.length}
					<span class="text-xs text-muted-foreground font-normal">
						/ {bufferLimit} max
					</span>
				</div>
				<div class="mt-2 h-1.5 w-full bg-secondary rounded-full overflow-hidden">
					<div
						class="h-full bg-primary transition-all duration-300"
						style="width: {bufferUsagePct}%"
					></div>
				</div>
				<p class="text-xs text-muted-foreground mt-1.5">
					{bufferUsagePct}% memory capacity used
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Top Subsystem Activity Card -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2 space-y-0">
			<Card.Title class="text-sm font-medium">Active Subsystems</Card.Title>
			<LayersIcon class="h-4 w-4 text-sky-500" />
		</Card.Header>
		<Card.Content>
			{#if loading && events.length === 0}
				<Skeleton class="h-8 w-24 mb-1" />
				<Skeleton class="h-3 w-36" />
			{:else}
				<div class="text-2xl font-bold capitalize">
					{topTopic.name}
					<span class="text-xs text-muted-foreground font-normal">
						({topTopic.count} events)
					</span>
				</div>
				<p class="text-xs text-muted-foreground mt-1.5 truncate">
					{#if Object.keys(topicCounts).length > 0}
						{Object.entries(topicCounts)
							.slice(0, 3)
							.map(([k, v]) => `${k}: ${v}`)
							.join(" · ")}
					{:else}
						No events in buffer
					{/if}
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Daemon Health Card -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2 space-y-0">
			<Card.Title class="text-sm font-medium">Daemon Health</Card.Title>
			<ServerIcon class="h-4 w-4 text-emerald-500" />
		</Card.Header>
		<Card.Content>
			{#if status}
				<div class="text-2xl font-bold text-emerald-600 dark:text-emerald-400">
					Healthy
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Uptime: {formatUptime(status.uptime_secs)} · v{status.version}
				</p>
			{:else if loading}
				<Skeleton class="h-8 w-20 mb-1" />
				<Skeleton class="h-3 w-28" />
			{:else}
				<div class="text-2xl font-bold text-muted-foreground">Online</div>
				<p class="text-xs text-muted-foreground mt-1">Status details loaded</p>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
