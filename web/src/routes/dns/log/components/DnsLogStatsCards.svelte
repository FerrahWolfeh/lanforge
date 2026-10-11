<script lang="ts">
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
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

<StatCardGrid cols={4}>
	<!-- Card 1: Total Logged Queries -->
	<StatCard
		label="Logged Queries"
		value={totalQueries.toLocaleString()}
		icon={ListFilterIcon}
		color="sky"
		subtext={`${entries.length} queries loaded in view`}
		loading={loading && entries.length === 0}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Audit Storage" value="Ring Buffer" />
			<StatCardFooterItem label="Telemetry" value="Audit Trail" />
		{/snippet}
	</StatCard>

	<!-- Card 2: Live Stream Status -->
	<StatCard
		label="Stream Status"
		value={isLive ? "Live Stream" : "Paused"}
		icon={RadioIcon}
		color={isLive ? "emerald" : "zinc"}
		badge={{
			text: isLive ? "Active SSE" : "Paused",
			variant: isLive ? "online" : "dormant",
			showDot: true
		}}
		subtext={isLive ? "Streaming incoming events via SSE" : "Real-time updates suspended"}
		loading={loading && entries.length === 0}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Transport" value="SSE Stream" />
			<StatCardFooterItem
				label="Feed Status"
				value={isLive ? "Online" : "Paused"}
				color={isLive ? "text-emerald-500" : "text-amber-500"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 3: Block Ratio -->
	<StatCard
		label="Blocked Ratio"
		value={`${blockRatio}%`}
		icon={ShieldAlertIcon}
		color="rose"
		subtext={`${blockedCount.toLocaleString()} blocked requests`}
		loading={loading && entries.length === 0}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Protection" value="Adblock / Blacklist" />
			<StatCardFooterItem
				label="Drop Rate"
				value={`${blockRatio}%`}
				color={blockRatio > 0 ? "text-rose-500" : "text-emerald-500"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 4: Avg Upstream Latency -->
	<StatCard
		label="Upstream Latency"
		value={formatLatency(avgLatencyUs)}
		icon={GaugeIcon}
		color="violet"
		subtext="Average upstream response time"
		loading={loading && entries.length === 0}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Sample Size" value={`${entries.length} queries`} />
			<StatCardFooterItem label="Resolution" value="µs Precision" />
		{/snippet}
	</StatCard>
</StatCardGrid>
