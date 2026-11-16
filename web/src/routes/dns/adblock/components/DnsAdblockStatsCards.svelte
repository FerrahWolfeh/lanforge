<script lang="ts">
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { DnsAdblockStatusResponse, DnsStatsResponse, DnsAnalyticsResponse } from "$lib/api/types";

	let {
		loading = false,
		status = null,
		stats = null,
		analytics = null,
		sourceCount = 0,
	}: {
		loading?: boolean;
		status?: DnsAdblockStatusResponse | null;
		stats?: DnsStatsResponse | null;
		analytics?: DnsAnalyticsResponse | null;
		sourceCount?: number;
	} = $props();

	const blocklistDomains = $derived(status?.blocklist_size ?? 0);
	const allowlistDomains = $derived(status?.allowlist_size ?? 0);
	const exceptionsDomains = $derived(status?.exceptions_size ?? 0);
	const totalAllowedOrExceptions = $derived(allowlistDomains + exceptionsDomains);

	const analytics24h = $derived.by(() => {
		const rates = analytics?.query_rate ?? [];
		if (rates.length === 0) return null;
		const total = rates.reduce((acc, r) => acc + r.count, 0);
		const blocked = rates.reduce((acc, r) => acc + (r.blocked ?? 0), 0);
		const allowed = Math.max(0, total - blocked);
		const safeTot = Math.max(1, total);
		return {
			total,
			blocked,
			allowed,
			blockPct: ((blocked / safeTot) * 100).toFixed(1),
			blockPctNum: (blocked / safeTot) * 100,
		};
	});

	const totalQueries = $derived(analytics24h ? analytics24h.total : (stats?.total_requests ?? 0));
	const blockedQueries = $derived(analytics24h ? analytics24h.blocked : (stats?.blocked_queries ?? 0));
	const allowedQueries = $derived(analytics24h ? analytics24h.allowed : Math.max(0, totalQueries - blockedQueries));

	const blockPercentage = $derived.by(() => {
		if (analytics24h) return `${analytics24h.blockPct}%`;
		if (totalQueries === 0) return "0.0%";
		return `${((blockedQueries / totalQueries) * 100).toFixed(1)}%`;
	});

	const blockPercentageNum = $derived.by(() => {
		if (analytics24h) return analytics24h.blockPctNum;
		if (totalQueries === 0) return 0;
		return (blockedQueries / totalQueries) * 100;
	});

	const allowedPercentage = $derived.by(() => {
		if (totalQueries === 0) return "100.0%";
		return `${((allowedQueries / totalQueries) * 100).toFixed(1)}%`;
	});

	function formatTimeAgo(timestamp?: number | null): string {
		if (!timestamp || timestamp <= 0) return "Up to date";
		const nowSecs = Math.floor(Date.now() / 1000);
		const diff = Math.max(0, nowSecs - timestamp);
		if (diff < 60) return "Just now";
		if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
		if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
		return `${Math.floor(diff / 86400)}d ago`;
	}

</script>

<StatCardGrid cols={3}>
	<!-- Card 1: Queries Blocked & Block Rate (Unified) -->
	<StatCard
		label="Blocked Queries (24h)"
		value={loading && !analytics && !stats ? null : blockedQueries.toLocaleString()}
		subtext={loading && !analytics && !stats
			? "Loading…"
			: `${blockPercentage} of ${totalQueries.toLocaleString()} queries in the last 24 hours`}
		icon={ShieldAlertIcon}
		color="rose"
		{loading}
		popover={{
			title: "Blocked queries (24h)",
			description: stats
				? `Blocked in last 24h: ${blockedQueries.toLocaleString()} (${blockPercentage}). Lifetime blocked since startup: ${stats.blocked_queries.toLocaleString()}.`
				: "Queries answered by adblock instead of an upstream server.",
		}}
	>
		<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted mt-2">
			<div
				class="h-full bg-rose-500 transition-all duration-500"
				style={`width: ${Math.min(100, Math.max(0, blockPercentageNum))}%`}
			></div>
		</div>

		{#snippet footer()}
			<StatCardFooterItem
				label="Allowed Lookups"
				value={loading && !analytics && !stats ? "—" : `${allowedQueries.toLocaleString()} (${allowedPercentage})`}
				color="text-emerald-400"
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Domains on Blocklist -->
	<StatCard
		label="Domains on Blocklist"
		value={status ? blocklistDomains.toLocaleString() : null}
		subtext={`From ${sourceCount} ${sourceCount === 1 ? "list" : "lists"} and your rules`}
		icon={DatabaseIcon}
		color="indigo"
		{loading}
		popover={{
			title: "Blocklist",
			description: "Domains blocked for every device, from the subscribed lists and the global rules file.",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Last Update"
				value={formatTimeAgo(status?.last_update)}
				color="text-foreground"
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Subscriptions</span>
				<a
					href="/dns/adblock/lists"
					class="text-[11px] text-primary hover:underline font-medium flex items-center gap-0.5 truncate"
				>
					<span>Lists</span>
					<ArrowRightIcon class="size-3 shrink-0" />
				</a>
			</div>
		{/snippet}
	</StatCard>

	<!-- Card 4: Custom Rules & Overrides -->
	<StatCard
		label="Allowed Domains"
		value={status ? totalAllowedOrExceptions.toLocaleString() : null}
		subtext={exceptionsDomains > 0
			? `${allowlistDomains} allowed, ${exceptionsDomains} @@ exceptions`
			: "Your rules that win over the lists"}
		icon={ShieldCheckIcon}
		color="emerald"
		{loading}
		popover={{
			title: "Allowed domains",
			description: "Allow rules and @@ exceptions: these domains resolve even when a list blocks them.",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Allowed"
				value={allowlistDomains.toLocaleString()}
				color="text-emerald-400"
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Custom Rules</span>
				<a
					href="/dns/adblock/rules"
					class="text-[11px] text-primary hover:underline font-medium flex items-center gap-0.5 truncate"
				>
					<span>Rules</span>
					<ArrowRightIcon class="size-3 shrink-0" />
				</a>
			</div>
		{/snippet}
	</StatCard>
</StatCardGrid>
