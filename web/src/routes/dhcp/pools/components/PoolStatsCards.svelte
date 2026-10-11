<script lang="ts">
	import LayersIcon from "@lucide/svelte/icons/layers";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ServerIcon from "@lucide/svelte/icons/server";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";

	let {
		loading = false,
		totalConfiguredCount = 0,
		v4PoolsCount = 0,
		v6PoolsCount = 0,
		totalManagedAddresses = 0,
		totalUsedAddresses = 0,
		totalAvailableAddresses = 0,
		aggregateUtilization = 0,
	}: {
		loading?: boolean;
		totalConfiguredCount?: number;
		v4PoolsCount?: number;
		v6PoolsCount?: number;
		totalManagedAddresses?: number;
		totalUsedAddresses?: number;
		totalAvailableAddresses?: number;
		aggregateUtilization?: number;
	} = $props();

	function getUtilizationStyles(pct: number) {
		if (pct >= 90) {
			return {
				bar: "bg-rose-500",
				badgeVariant: "error",
				label: "Critical",
			};
		}
		if (pct >= 75) {
			return {
				bar: "bg-amber-500",
				badgeVariant: "warning",
				label: "Elevated",
			};
		}
		return {
			bar: "bg-emerald-500",
			badgeVariant: "online",
			label: "Healthy",
		};
	}

	const utilStyle = $derived(getUtilizationStyles(aggregateUtilization));
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Configured Scopes -->
	<StatCard
		label="Configured Scopes"
		value={totalConfiguredCount}
		subtext={`${v4PoolsCount} IPv4 / ${v6PoolsCount} IPv6 scopes`}
		icon={LayersIcon}
		color="indigo"
		{loading}
		popover={{
			title: "Configured Address Scopes",
			description: "Active DHCP dynamic scopes configured across physical and VLAN interfaces.",
		}}
		badge={{
			text: "Active",
			variant: "indigo",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="IPv4 Scopes" value={v4PoolsCount} color="text-emerald-400" />
			<StatCardFooterItem label="IPv6 Scopes" value={v6PoolsCount} color="text-sky-400" />
		{/snippet}
	</StatCard>

	<!-- Card 2: Managed Capacity -->
	<StatCard
		label="Managed Capacity"
		value={`${totalManagedAddresses.toLocaleString()} IPs`}
		subtext="Total allocatable dynamic addresses"
		icon={NetworkIcon}
		color="emerald"
		{loading}
		popover={{
			title: "Managed Address Space",
			description: "Aggregate address capacity of all defined ranges excluding reserved host addresses.",
		}}
		badge={{
			text: "Pool Range",
			variant: "online",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Total Scope" value={totalManagedAddresses.toLocaleString()} />
			<StatCardFooterItem label="Allocatable" value={totalAvailableAddresses.toLocaleString()} color="text-emerald-400" />
		{/snippet}
	</StatCard>

	<!-- Card 3: Active Leases in Use -->
	<StatCard
		label="Active Leases"
		value={totalUsedAddresses}
		subtext={`${totalAvailableAddresses} addresses free for clients`}
		icon={ActivityIcon}
		color="sky"
		{loading}
		popover={{
			title: "Lease Occupancy",
			description: "Currently bound addresses against managed pool capacity.",
		}}
		badge={{
			text: "In Use",
			variant: "sky",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Bound Leases" value={totalUsedAddresses} color="text-sky-400" />
			<StatCardFooterItem label="Available" value={totalAvailableAddresses} color="text-emerald-400" />
		{/snippet}
	</StatCard>

	<!-- Card 4: Aggregate Utilization -->
	<StatCard
		label="Global Utilization"
		value={`${aggregateUtilization}%`}
		subtext="Aggregate capacity consumption"
		icon={ServerIcon}
		color={aggregateUtilization >= 90 ? "rose" : aggregateUtilization >= 75 ? "amber" : "emerald"}
		{loading}
		popover={{
			title: "Aggregate Pool Utilization",
			description: "Percentage of total address capacity currently leased to active network clients.",
		}}
		badge={{
			text: utilStyle.label,
			variant: utilStyle.badgeVariant,
		}}
	>
		<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted mt-2">
			<div
				class={`h-full ${utilStyle.bar} transition-all duration-500`}
				style={`width: ${Math.min(100, Math.max(0, aggregateUtilization))}%`}
			></div>
		</div>

		{#snippet footer()}
			<StatCardFooterItem label="Capacity Used" value={`${totalUsedAddresses} / ${totalManagedAddresses}`} />
			<StatCardFooterItem
				label="Headroom"
				value={`${Math.max(0, 100 - aggregateUtilization)}% Free`}
				color={aggregateUtilization >= 90 ? "text-rose-400" : "text-emerald-400"}
			/>
		{/snippet}
	</StatCard>
</StatCardGrid>
