<script lang="ts">
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { StatusResponse, DbMetrics } from "$lib/api/types";

	let {
		systemStatus = null,
		metrics = null,
		loading = false,
		isInMemory = false,
		isHealthy = true,
		formatBytes = (b: number) => `${b} B`,
		formatTimeAgo = () => "Never",
	}: {
		systemStatus?: StatusResponse | null;
		metrics?: DbMetrics | null;
		loading?: boolean;
		isInMemory?: boolean;
		isHealthy?: boolean;
		formatBytes?: (b: number) => string;
		formatTimeAgo?: (epochSecs: number | null | undefined) => string;
	} = $props();
</script>

<StatCardGrid cols={2}>
	<!-- Card 1: Storage & Footprint -->
	<StatCard
		label="Size"
		value={formatBytes(systemStatus?.db?.size_bytes ?? 0)}
		icon={HardDriveIcon}
		color={isInMemory ? "amber" : "indigo"}
		badge={isInMemory ? { text: "In memory: lost on restart", variant: "warning", showDot: true } : undefined}
		subtext={isInMemory ? "Nothing is written to disk" : systemStatus?.db?.path ?? ""}
		loading={loading && !systemStatus}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Devices Stored"
				value={(metrics?.devices_written ?? 0).toLocaleString()}
			/>
			<StatCardFooterItem
				label="Writes"
				value={isHealthy ? "OK" : "Failing"}
				color={isHealthy ? "text-emerald-500" : "text-destructive"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Persistence Cadence -->
	<StatCard
		label="Last Write"
		value={systemStatus?.db ? formatTimeAgo(Math.floor(Date.now() / 1000) - systemStatus.db.last_flush_secs_ago) : "—"}
		icon={ActivityIcon}
		color="emerald"
		subtext="State in memory is written to disk in batches"
		loading={loading && !metrics}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Writes Since Start"
				value={(metrics?.flush_count ?? 0).toLocaleString()}
			/>
		{/snippet}
	</StatCard>

</StatCardGrid>
