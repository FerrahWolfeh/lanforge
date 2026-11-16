<script lang="ts">
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { RaStatusResponse } from "$lib/api/types";

	let {
		status = null,
	}: {
		status?: RaStatusResponse | null;
	} = $props();

	function formatSeconds(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "Never";
		if (sec < 60) return `${sec}s ago`;
		if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s ago`;
		const h = Math.floor(sec / 3600);
		const m = Math.floor((sec % 3600) / 60);
		return `${h}h ${m}m ago`;
	}

	function formatCountdown(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "—";
		if (sec === 0) return "Imminent";
		if (sec < 60) return `in ${sec}s`;
		const m = Math.floor(sec / 60);
		const s = sec % 60;
		return `in ${m}m ${s}s`;
	}

	function formatUptime(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "—";
		const days = Math.floor(sec / 86400);
		const hours = Math.floor((sec % 86400) / 3600);
		const minutes = Math.floor((sec % 3600) / 60);
		const seconds = sec % 60;
		if (days > 0) return `${days}d ${hours}h ${minutes}m`;
		if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
		if (minutes > 0) return `${minutes}m ${seconds}s`;
		return `${seconds}s`;
	}
</script>

<StatCardGrid cols={3}>
	<!-- Card 1: Operational Interface -->
	<StatCard
		label="Interface"
		value={status?.interface ?? "Not bound"}
		subtext={status?.enabled ? "Sending router advertisements" : "Not sending router advertisements"}
		icon={NetworkIcon}
		color="indigo"
		popover={{
			title: "Router advertisements",
			description: "Sent to every device on the LAN (ff02::1) on a timer, and in reply when a device asks.",
		}}
		badge={status?.enabled ? undefined : { text: "Off", variant: "dormant" }}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Link-Local" value={status?.link_local ?? "—"} />
		{/snippet}
	</StatCard>

	<!-- Card 3: Packet Telemetry -->
	<StatCard
		label="RAs Sent"
		value={(status?.sent_multicast_ras ?? 0) + (status?.sent_unicast_ras ?? 0)}
		subtext="Since the service started"
		icon={ActivityIcon}
		color="sky"
		popover={{
			title: "RAs sent",
			description: "Timed advertisements to the whole LAN (multicast), plus direct replies to devices that asked (router solicitations).",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Timed / Replies"
				value={`${status?.sent_multicast_ras ?? 0} / ${status?.sent_unicast_ras ?? 0}`}
			/>
			<StatCardFooterItem
				label="Requests Received"
				value={status?.received_solicitations ?? 0}
				color="text-sky-400"
			/>
		{/snippet}
	</StatCard>

	<!-- Card 4: Timing & Schedule -->
	<StatCard
		label="Next RA"
		value={formatCountdown(status?.next_ra_in_secs)}
		subtext={`Last sent ${formatSeconds(status?.last_ra_sent_secs_ago)}`}
		icon={ClockIcon}
		color="amber"
		popover={{
			title: "Next RA",
			description: "The next timed advertisement goes out at a random point between the minimum and maximum interval.",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Uptime" value={formatUptime(status?.uptime_secs)} />
			<StatCardFooterItem label="Last Request" value={formatSeconds(status?.last_rs_received_secs_ago)} />
		{/snippet}
	</StatCard>
</StatCardGrid>
