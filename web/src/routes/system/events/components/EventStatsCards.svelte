<script lang="ts">
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import ServerIcon from "@lucide/svelte/icons/server";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
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

<StatCardGrid cols={4}>
	<!-- Card 1: Stream Status -->
	<StatCard
		label="Stream Status"
		value={reconnecting ? "Reconnecting" : isLive ? "Live Stream" : "Paused"}
		icon={RadioIcon}
		color={reconnecting ? "amber" : isLive ? "emerald" : "zinc"}
		badge={{
			text: reconnecting ? "Connecting" : isLive ? "Active SSE" : "Paused",
			variant: reconnecting ? "warning" : isLive ? "online" : "dormant",
			showDot: true
		}}
		subtext={reconnecting ? "Retrying internal SSE connection" : isLive ? "Connected to internal event bus" : "Incoming stream updates paused"}
		loading={loading && events.length === 0}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Protocol" value="SSE / EventStream" />
			<StatCardFooterItem
				label="Feed State"
				value={isLive ? "Streaming" : "Halted"}
				color={isLive ? "text-emerald-500" : "text-amber-500"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Buffer Utilization -->
	<StatCard
		label="Buffer Utilization"
		value={events.length}
		icon={ActivityIcon}
		color="sky"
		subtext={`${bufferUsagePct}% capacity (${bufferLimit} max)`}
		loading={loading && events.length === 0}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Buffer Limit" value={`${bufferLimit} slots`} />
			<StatCardFooterItem
				label="Memory Ratio"
				value={`${bufferUsagePct}%`}
				color={bufferUsagePct > 80 ? "text-amber-500" : "text-sky-500"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 3: Top Subsystem Activity -->
	<StatCard
		label="Active Subsystems"
		value={topTopic.name ? topTopic.name.charAt(0).toUpperCase() + topTopic.name.slice(1) : "None"}
		icon={LayersIcon}
		color="violet"
		subtext={`${topTopic.count} recent events`}
		loading={loading && events.length === 0}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Unique Topics" value={Object.keys(topicCounts).length} />
			<StatCardFooterItem label="Primary Bus" value={topTopic.name} />
		{/snippet}
	</StatCard>

	<!-- Card 4: Daemon Health -->
	<StatCard
		label="Daemon Health"
		value={status ? "Healthy" : "Online"}
		icon={ServerIcon}
		color="emerald"
		badge={{
			text: "Operational",
			variant: "online",
			showDot: true
		}}
		subtext={status ? `v${status.version}` : "Status details loaded"}
		loading={loading && !status}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="System Uptime"
				value={status ? formatUptime(status.uptime_secs) : "—"}
			/>
			<StatCardFooterItem
				label="Build"
				value={status ? `v${status.version}` : "—"}
			/>
		{/snippet}
	</StatCard>
</StatCardGrid>
