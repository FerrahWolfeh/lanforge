<script lang="ts">
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ServerIcon from "@lucide/svelte/icons/server";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { StatusResponse, DbMetrics } from "$lib/api/types";

	let {
		systemStatus = null,
		metrics = null,
		totalStoredEntities = 0,
		loading = false,
		isInMemory = false,
		engineLabel = "Persistent (redb)",
		isHealthy = true,
		formatBytes = (b: number) => `${b} B`,
		formatTimeAgo = () => "Never",
	}: {
		systemStatus?: StatusResponse | null;
		metrics?: DbMetrics | null;
		totalStoredEntities?: number;
		loading?: boolean;
		isInMemory?: boolean;
		engineLabel?: string;
		isHealthy?: boolean;
		formatBytes?: (b: number) => string;
		formatTimeAgo?: (secs: number | null | undefined) => string;
	} = $props();
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Storage Engine -->
	<StatCard
		label="Storage Engine"
		value={engineLabel}
		icon={HardDriveIcon}
		color={isInMemory ? "amber" : "indigo"}
		badge={{
			text: isInMemory ? "In-Memory" : "redb",
			variant: isInMemory ? "warning" : "online",
			showDot: true
		}}
		subtext={systemStatus?.db?.path || (isInMemory ? "Volatile RAM store" : "redb (embedded)")}
		loading={loading && !systemStatus}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Backend Mode"
				value={isInMemory ? "In-Memory (RAM)" : "redb (Disk)"}
			/>
			<StatCardFooterItem
				label="Persistence"
				value={isInMemory ? "Volatile" : "Persistent"}
				color={isInMemory ? "text-amber-500" : "text-emerald-500"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Persistence Cadence -->
	<StatCard
		label="Persistence Cadence"
		value={(metrics?.flush_count ?? 0).toLocaleString()}
		icon={ActivityIcon}
		color="emerald"
		subtext="Completed disk sync flushes"
		loading={loading && !metrics}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Last Sync"
				value={formatTimeAgo(systemStatus?.db?.last_flush_secs_ago)}
			/>
			<StatCardFooterItem label="Flush Interval" value="60s tick" />
		{/snippet}
	</StatCard>

	<!-- Card 3: Stored Records & Inventory -->
	<StatCard
		label="Stored Records"
		value={totalStoredEntities.toLocaleString()}
		icon={ServerIcon}
		color="sky"
		subtext="Total managed state entities"
		loading={loading && !metrics}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Devices Written"
				value={(metrics?.devices_written ?? 0).toLocaleString()}
			/>
			<StatCardFooterItem
				label="Disk Footprint"
				value={formatBytes(systemStatus?.db?.size_bytes ?? 0)}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 4: Engine Health -->
	<StatCard
		label="Engine Health"
		value={isHealthy ? "Optimal" : "Attention"}
		icon={isHealthy ? CheckCircleIcon : AlertTriangleIcon}
		color={isHealthy ? "emerald" : "amber"}
		badge={{
			text: isHealthy ? "0 Errors" : "Degraded",
			variant: isHealthy ? "online" : "warning",
			showDot: true
		}}
		subtext={isHealthy ? "Clean persistent write lock" : "Write error detected"}
		loading={loading && !metrics}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Write Errors"
				value={isHealthy ? "0 errors" : (metrics?.last_error ? "Detected" : "0 errors")}
				color={isHealthy ? "text-emerald-500" : "text-destructive"}
			/>
			<StatCardFooterItem
				label="Lock Status"
				value={isHealthy ? "Acquired" : "Check Logs"}
				color={isHealthy ? "text-emerald-500" : "text-amber-500"}
			/>
		{/snippet}
	</StatCard>
</StatCardGrid>
