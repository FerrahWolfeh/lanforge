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

<StatCardGrid cols={3}>
	<!-- Card 1: Storage & Footprint -->
	<StatCard
		label="Database Footprint"
		value={formatBytes(systemStatus?.db?.size_bytes ?? 0)}
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
				label="Backend"
				value={isInMemory ? "RAM (Volatile)" : "Embedded redb"}
			/>
			<StatCardFooterItem
				label="Health"
				value={isHealthy ? "Optimal" : "Write error"}
				color={isHealthy ? "text-emerald-500" : "text-destructive"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Persistence Cadence -->
	<StatCard
		label="Last Disk Sync"
		value={formatTimeAgo(systemStatus?.db?.last_flush_secs_ago)}
		icon={ActivityIcon}
		color="emerald"
		badge={{
			text: `${(metrics?.flush_count ?? 0).toLocaleString()} flushes`,
			variant: "zinc"
		}}
		subtext="Periodic batch disk synchronization"
		loading={loading && !metrics}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Total Flushes"
				value={(metrics?.flush_count ?? 0).toLocaleString()}
			/>
			<StatCardFooterItem label="Interval" value="60s tick" />
		{/snippet}
	</StatCard>

	<!-- Card 3: Stored Records & Inventory -->
	<StatCard
		label="Managed Records"
		value={totalStoredEntities.toLocaleString()}
		icon={ServerIcon}
		color="sky"
		subtext="Persisted state entities across tables"
		loading={loading && !metrics}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Devices Stored"
				value={(metrics?.devices_written ?? 0).toLocaleString()}
			/>
			<StatCardFooterItem
				label="Write Errors"
				value={metrics?.last_error ? "Detected" : "0 errors"}
				color={metrics?.last_error ? "text-destructive" : "text-emerald-500"}
			/>
		{/snippet}
	</StatCard>
</StatCardGrid>
