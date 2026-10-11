<script lang="ts">
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import { formatBytes } from "$lib/utils";
	import type { DnsCacheStatsExtResponse } from "$lib/api/types";

	let {
		loading = true,
		stats = null,
	}: {
		loading?: boolean;
		stats?: DnsCacheStatsExtResponse | null;
	} = $props();

	function formatTtl(secs: number): string {
		if (secs <= 0) return "0s";
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		if (m === 0) return `${s}s`;
		return `${m}m ${s}s`;
	}

	const usagePct = $derived.by(() => {
		if (!stats || !stats.capacity || stats.capacity === 0) return 0;
		return Math.min(100, Math.round((stats.total_entries / stats.capacity) * 100));
	});
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Occupancy -->
	<StatCard
		label="Cache Occupancy"
		value={stats ? `${stats.total_entries.toLocaleString()} / ${stats.capacity.toLocaleString()}` : null}
		subtext={`${usagePct}% capacity utilized`}
		icon={DatabaseIcon}
		color="indigo"
		{loading}
		popover={{
			title: "Cache Entry Table",
			description: "Active record entries cached in memory with remaining time-to-live values.",
		}}
		badge={{
			text: `${usagePct}% Full`,
			variant: usagePct > 85 ? "warning" : "indigo",
		}}
	>
		<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted mt-2">
			<div
				class="h-full bg-indigo-500 transition-all duration-500"
				style={`width: ${usagePct}%`}
			></div>
		</div>

		{#snippet footer()}
			<StatCardFooterItem label="Active Entries" value={stats?.total_entries.toLocaleString() ?? "—"} />
			<StatCardFooterItem label="Total Capacity" value={stats?.capacity.toLocaleString() ?? "10,000"} />
		{/snippet}
	</StatCard>

	<!-- Card 2: Memory Footprint -->
	<StatCard
		label="Memory Footprint"
		value={stats ? formatBytes(stats.memory_usage_bytes) : null}
		subtext="In-memory hash index and wire buffers"
		icon={CpuIcon}
		color="sky"
		{loading}
		popover={{
			title: "RAM Utilization",
			description: "Real-time RAM consumed by cached DNS response buffers and index lookups.",
		}}
		badge={{
			text: "RAM Allocation",
			variant: "sky",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Index Storage" value="Zero-copy Wire" />
			<StatCardFooterItem label="Allocated" value={formatBytes(stats?.memory_usage_bytes ?? 0)} color="text-sky-400" />
		{/snippet}
	</StatCard>

	<!-- Card 3: Average TTL -->
	<StatCard
		label="Average TTL"
		value={stats ? formatTtl(stats.average_ttl_secs) : null}
		subtext={`Enforced minimum: ${stats?.min_ttl ?? 0}s`}
		icon={ClockIcon}
		color="amber"
		{loading}
		popover={{
			title: "TTL Lifespan",
			description: "Average remaining time before cached records expire and require upstream revalidation.",
		}}
		badge={{
			text: `Min ${stats?.min_ttl ?? 0}s`,
			variant: "warning",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Remaining Avg" value={formatTtl(stats?.average_ttl_secs ?? 0)} color="text-amber-400" />
			<StatCardFooterItem label="Min Clamped" value={`${stats?.min_ttl ?? 0}s`} />
		{/snippet}
	</StatCard>

	<!-- Card 4: Evictions -->
	<StatCard
		label="Cache Evictions"
		value={stats ? stats.evictions.toLocaleString() : null}
		subtext="Cleared under capacity pressure"
		icon={Trash2Icon}
		color={(stats?.evictions ?? 0) > 0 ? "rose" : "emerald"}
		{loading}
		popover={{
			title: "Cache Eviction Policy",
			description: "Records purged early using least-recently-used (LRU) policy when max capacity is reached.",
		}}
		badge={{
			text: (stats?.evictions ?? 0) === 0 ? "0 Clean" : "Evicting",
			variant: (stats?.evictions ?? 0) === 0 ? "online" : "error",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Eviction Pressure"
				value={(stats?.evictions ?? 0) === 0 ? "None" : "Capacity Limit"}
				color={(stats?.evictions ?? 0) === 0 ? "text-emerald-400" : "text-rose-400"}
			/>
			<StatCardFooterItem label="Policy" value="Adaptive LRU" />
		{/snippet}
	</StatCard>
</StatCardGrid>
