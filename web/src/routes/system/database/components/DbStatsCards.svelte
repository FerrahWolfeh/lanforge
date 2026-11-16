<script lang="ts">
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import StatStrip from "$lib/components/StatStrip.svelte";
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

<StatStrip
	items={[
		{
			label: isInMemory ? "size, in memory: lost on restart" : "size",
			value: loading && !systemStatus ? null : formatBytes(systemStatus?.db?.size_bytes ?? 0),
			icon: HardDriveIcon,
			tone: isInMemory ? "warning" : undefined,
		},
		{ label: "devices stored", value: (metrics?.devices_written ?? 0).toLocaleString() },
		{ label: "writes", value: isHealthy ? "OK" : "Failing", tone: isHealthy ? undefined : "danger" },
		{
			label: "last write",
			value: loading && !metrics ? null : systemStatus?.db ? formatTimeAgo(Math.floor(Date.now() / 1000) - systemStatus.db.last_flush_secs_ago) : "—",
			icon: ActivityIcon,
		},
		{ label: "writes since start", value: (metrics?.flush_count ?? 0).toLocaleString() },
	]}
/>
