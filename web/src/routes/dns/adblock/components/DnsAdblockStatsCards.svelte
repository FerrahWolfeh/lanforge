<script lang="ts">
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import PercentIcon from "@lucide/svelte/icons/percent";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { DnsAdblockStatusResponse, DnsStatsResponse } from "$lib/api/types";

	let {
		loading = false,
		status = null,
		stats = null,
		sourceCount = 0,
	}: {
		loading?: boolean;
		status?: DnsAdblockStatusResponse | null;
		stats?: DnsStatsResponse | null;
		sourceCount?: number;
	} = $props();

	const blocklistDomains = $derived(status?.blocklist_size ?? 0);
	const allowlistDomains = $derived(status?.allowlist_size ?? 0);
	const totalQueries = $derived(stats?.total_requests ?? 0);
	const blockedQueries = $derived(stats?.blocked_queries ?? 0);

	const blockPercentage = $derived.by(() => {
		if (totalQueries === 0) return "0.0";
		return ((blockedQueries / totalQueries) * 100).toFixed(1);
	});
	const exceptionsDomains = $derived(status?.exceptions_size ?? 0);
	const totalAllowedOrExceptions = $derived(allowlistDomains + exceptionsDomains);
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Blocklist Domains -->
	<StatCard
		label="Domains on Blocklist"
		value={status ? blocklistDomains.toLocaleString() : null}
		subtext={`Compiled in zero-copy FST (${sourceCount} sources)`}
		icon={DatabaseIcon}
		color="indigo"
		{loading}
		popover={{
			title: "Blocklist Domain Finite-State Transducer",
			description: "High-speed in-memory FST compiled from active remote blocklist sources and local adblock rules.",
		}}
		badge={{
			text: `${sourceCount} ${sourceCount === 1 ? 'Source' : 'Sources'}`,
			variant: "indigo",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Format" value="Zero-Copy FST" />
			<StatCardFooterItem label="Memory Mode" value="Immutable" />
		{/snippet}
	</StatCard>

	<!-- Card 2: Blocked Queries -->
	<StatCard
		label="Queries Blocked"
		value={stats ? blockedQueries.toLocaleString() : null}
		subtext={`Out of ${totalQueries.toLocaleString()} total DNS requests`}
		icon={ShieldAlertIcon}
		color="rose"
		{loading}
		popover={{
			title: "Blocked Ad & Tracker Queries",
			description: "Real-time query resolutions blocked by rule matches and returned as NXDOMAIN or 0.0.0.0.",
		}}
		badge={{
			text: "Filtered",
			variant: "error",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Blocked" value={blockedQueries.toLocaleString()} color="text-rose-400" />
			<StatCardFooterItem label="Total Processed" value={totalQueries.toLocaleString()} />
		{/snippet}
	</StatCard>

	<!-- Card 3: Block Percentage -->
	<StatCard
		label="Block Percentage"
		value={`${blockPercentage}%`}
		subtext="Ratio of blocked queries across all clients"
		icon={PercentIcon}
		color="amber"
		{loading}
		popover={{
			title: "Ad & Telemetry Ratio",
			description: "Percentage of total network DNS lookups intercepted by the adblocking engine.",
		}}
		badge={{
			text: `${blockPercentage}%`,
			variant: "warning",
		}}
	>
		<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted mt-2">
			<div
				class="h-full bg-rose-500 transition-all duration-500"
				style={`width: ${Math.min(100, Math.max(0, Number(blockPercentage)))}%`}
			></div>
		</div>

		{#snippet footer()}
			<StatCardFooterItem label="Block Rate" value={`${blockPercentage}%`} color="text-rose-400" />
			<StatCardFooterItem label="Allowed Rate" value={`${(100 - Number(blockPercentage)).toFixed(1)}%`} color="text-emerald-400" />
		{/snippet}
	</StatCard>

	<!-- Card 4: Exceptions & Allowlist -->
	<StatCard
		label="Allowlist & Exceptions"
		value={status ? totalAllowedOrExceptions.toLocaleString() : null}
		subtext={exceptionsDomains > 0 ? `${allowlistDomains} manual, ${exceptionsDomains} @@ rules` : "Whitelisted domains taking precedence"}
		icon={ShieldCheckIcon}
		color="emerald"
		{loading}
		popover={{
			title: "Allowlist & Override Rules",
			description: "Domains and Adblock Plus exception rules (@@) that bypass blocklists.",
		}}
		badge={{
			text: "Whitelisted",
			variant: "online",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Manual Whitelist" value={allowlistDomains} color="text-emerald-400" />
			<StatCardFooterItem label="Exception Rules" value={exceptionsDomains} />
		{/snippet}
	</StatCard>
</StatCardGrid>
