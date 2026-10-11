<script lang="ts">
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";

	let {
		loading = false,
		totalCount = 0,
		v4Count = 0,
		v6Count = 0,
		expiringSoonCount = 0,
	}: {
		loading?: boolean;
		totalCount?: number;
		v4Count?: number;
		v6Count?: number;
		expiringSoonCount?: number;
	} = $props();

	const v4Pct = $derived(
		totalCount > 0 ? Math.round((v4Count / totalCount) * 100) : 0
	);
	const v6Pct = $derived(
		totalCount > 0 ? Math.round((v6Count / totalCount) * 100) : 0
	);
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Total Leases -->
	<StatCard
		label="Active Leases"
		value={totalCount}
		subtext="Dynamic allocations active on LAN"
		icon={NetworkIcon}
		color="indigo"
		{loading}
		popover={{
			title: "DHCP Lease Table",
			description: "Active IPv4 dynamic leases and IPv6 stateful allocations tracked in memory and persisted in redb.",
		}}
		badge={{
			text: "Live",
			variant: "indigo",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="IPv4 Leases" value={v4Count} color="text-emerald-400" />
			<StatCardFooterItem label="IPv6 Leases" value={v6Count} color="text-sky-400" />
		{/snippet}
	</StatCard>

	<!-- Card 2: IPv4 Dynamic Leases -->
	<StatCard
		label="IPv4 Leases"
		value={v4Count}
		subtext="Standard RFC 2131 dynamic allocations"
		icon={ShieldCheckIcon}
		color="emerald"
		{loading}
		popover={{
			title: "DHCPv4 Pool Allocation",
			description: "Dynamic addresses assigned to LAN clients with gateway (opt 3) and DNS (opt 6) configuration.",
		}}
		badge={{
			text: `${v4Pct}% of total`,
			variant: "online",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Protocol" value="UDP Port 67" />
			<StatCardFooterItem label="Allocation" value="RFC 2131" />
		{/snippet}
	</StatCard>

	<!-- Card 3: IPv6 & Prefix Delegation -->
	<StatCard
		label="DHCPv6 & PD"
		value={v6Count}
		subtext="IA_NA addresses & IA_PD delegated prefixes"
		icon={GlobeIcon}
		color="sky"
		{loading}
		popover={{
			title: "DHCPv6 Stateful Protocol",
			description: "RFC 8415 stateful address allocation and downstream router prefix delegation (IA_PD).",
		}}
		badge={{
			text: `${v6Pct}% of total`,
			variant: "sky",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Protocol" value="UDP Port 547" />
			<StatCardFooterItem label="Assignment" value="RFC 8415" />
		{/snippet}
	</StatCard>

	<!-- Card 4: Expiring Soon / Churn -->
	<StatCard
		label="Expiring Soon"
		value={expiringSoonCount}
		subtext="Leases pending T1/T2 client renewal"
		icon={ClockIcon}
		color={expiringSoonCount > 0 ? "amber" : "zinc"}
		{loading}
		popover={{
			title: "Lease Expiration & Churn",
			description: "Clients that have not renewed within the T1 half-life and are entering the T2 rebind window.",
		}}
		badge={{
			text: expiringSoonCount > 0 ? "< 1h Window" : "Healthy",
			variant: expiringSoonCount > 0 ? "warning" : "online",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Status"
				value={expiringSoonCount > 0 ? "Pending Renewal" : "Stable"}
				color={expiringSoonCount > 0 ? "text-amber-400" : "text-emerald-400"}
			/>
			<StatCardFooterItem label="T1 Half-life" value="50% Lease" />
		{/snippet}
	</StatCard>
</StatCardGrid>
