<script lang="ts">
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import { formatIpv6Prefix } from "$lib/utils";
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

<StatCardGrid cols={4}>
	<!-- Card 1: Operational Interface -->
	<StatCard
		label="Interface"
		value={status?.interface ?? "Not bound"}
		subtext={status?.enabled ? "Announcing autonomous SLAAC routes" : "Daemon idle or unbound"}
		icon={NetworkIcon}
		color="indigo"
		popover={{
			title: "IPv6 Router Advertisements",
			description: "Periodic multicast ICMPv6 router advertisements (RFC 4861) sent to ff02::1.",
		}}
		badge={{
			text: status?.enabled ? "Announcing" : "Idle",
			variant: status?.enabled ? "online" : "dormant",
			showDot: true,
			pulse: true,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Link-Local" value={status?.link_local ?? "—"} />
			<StatCardFooterItem label="State" value={status?.enabled ? "Active" : "Stopped"} color={status?.enabled ? "text-emerald-400" : "text-zinc-500"} />
		{/snippet}
	</StatCard>

	<!-- Card 2: Prefix Subnets -->
	<StatCard
		label="Prefix Subnets"
		value={`${(status?.prefixes ?? []).length} Announced`}
		subtext="SLAAC autoconfiguration prefixes"
		icon={GlobeIcon}
		color="emerald"
		popover={{
			title: "Announced IPv6 Prefixes",
			description: "GUA and ULA prefixes advertised for stateless client address generation.",
		}}
		badge={{
			text: status?.active_gua_prefix ? "GUA / ULA" : "Prefix Scope",
			variant: "online",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="GUA Delegated" value={formatIpv6Prefix(status?.active_gua_prefix)} color="text-emerald-400" />
			<StatCardFooterItem label="Active ULA" value={formatIpv6Prefix(status?.active_ula_prefix)} />
		{/snippet}
	</StatCard>

	<!-- Card 3: Packet Telemetry -->
	<StatCard
		label="Packet Telemetry"
		value={(status?.sent_multicast_ras ?? 0) + (status?.sent_unicast_ras ?? 0)}
		subtext="Total ICMPv6 RAs transmitted"
		icon={ActivityIcon}
		color="sky"
		popover={{
			title: "ICMPv6 Telemetry",
			description: "Counts of periodic unsolicited multicast RAs and unicast replies to client router solicitations (RS).",
		}}
		badge={{
			text: "ICMPv6",
			variant: "sky",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Multi / Unicast"
				value={`${status?.sent_multicast_ras ?? 0} / ${status?.sent_unicast_ras ?? 0}`}
			/>
			<StatCardFooterItem
				label="RS Solicitations"
				value={status?.received_solicitations ?? 0}
				color="text-sky-400"
			/>
		{/snippet}
	</StatCard>

	<!-- Card 4: Timing & Schedule -->
	<StatCard
		label="Convergence"
		value={formatCountdown(status?.next_ra_in_secs)}
		subtext={`Last sent ${formatSeconds(status?.last_ra_sent_secs_ago)}`}
		icon={ClockIcon}
		color="amber"
		popover={{
			title: "Cadence & Intervals",
			description: "Randomized timer scheduling between MinRtrAdvInterval and MaxRtrAdvInterval.",
		}}
		badge={{
			text: "Scheduled",
			variant: "warning",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Uptime" value={formatUptime(status?.uptime_secs)} />
			<StatCardFooterItem label="Last RS Recv" value={formatSeconds(status?.last_rs_received_secs_ago)} />
		{/snippet}
	</StatCard>
</StatCardGrid>
