<script lang="ts">
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import BanIcon from "@lucide/svelte/icons/ban";
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

	function formatBlockingMode(mode?: string): { display: string; desc: string } {
		switch (mode) {
			case "null_ip":
				return { display: "0.0.0.0 / ::", desc: "Returns Null IP sinkhole" };
			case "custom_ip":
				return { display: "Custom IP", desc: "Redirects to local block page" };
			case "refused":
				return { display: "REFUSED", desc: "Responds with RCODE Refused" };
			case "nxdomain":
			default:
				return { display: "NXDOMAIN", desc: "Responds that domain does not exist" };
		}
	}

	const modeInfo = $derived(formatBlockingMode(status?.blocking_mode));
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Queries Blocked & Block Rate (Unified) -->
	<StatCard
		label="Blocked Queries (24h)"
		value={loading && !analytics && !stats ? null : blockedQueries.toLocaleString()}
		subtext={loading && !analytics && !stats
			? "Awaiting DNS telemetry..."
			: `Out of ${totalQueries.toLocaleString()} lookups in last 24h`}
		icon={ShieldAlertIcon}
		color="rose"
		{loading}
		popover={{
			title: "Blocked Ad & Tracker Queries (24h Window)",
			description: stats
				? `Blocked in last 24h: ${blockedQueries.toLocaleString()} (${blockPercentage}). Lifetime blocked since startup: ${stats.blocked_queries.toLocaleString()}.`
				: "Real-time DNS queries intercepted by the adblocking engine and sinkholed before reaching WAN upstreams.",
		}}
		badge={{
			text: `${blockPercentage} Blocked`,
			variant: blockedQueries > 0 ? "rose" : "zinc",
			showDot: blockedQueries > 0,
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
			<StatCardFooterItem
				label="Drop Rate"
				value={blockPercentage}
				color="text-rose-400"
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Domains on Blocklist -->
	<StatCard
		label="Domains on Blocklist"
		value={status ? blocklistDomains.toLocaleString() : null}
		subtext={`${sourceCount} subscription sources compiled`}
		icon={DatabaseIcon}
		color="indigo"
		{loading}
		popover={{
			title: "Compiled Blocklist Rules",
			description: "Active threat intelligence, ad, and tracker domains compiled into memory from remote subscriptions and local rules.",
		}}
		badge={{
			text: `${sourceCount} ${sourceCount === 1 ? 'Source' : 'Sources'}`,
			variant: sourceCount > 0 ? "indigo" : "zinc",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Last Sync"
				value={formatTimeAgo(status?.last_update)}
				color="text-foreground"
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Subscriptions</span>
				<a
					href="/dns/adblock/lists"
					class="text-[11px] text-primary hover:underline font-medium flex items-center gap-0.5 truncate"
				>
					<span>Manage Sources</span>
					<ArrowRightIcon class="size-3 shrink-0" />
				</a>
			</div>
		{/snippet}
	</StatCard>

	<!-- Card 3: Blocking Response Mode -->
	<StatCard
		label="Blocking Response Mode"
		value={status ? modeInfo.display : null}
		subtext={modeInfo.desc}
		icon={BanIcon}
		color="amber"
		{loading}
		popover={{
			title: "DNS Sinkhole Policy",
			description: "Controls how blocked queries are answered. NXDOMAIN reports domain doesn't exist, while Null IP returns 0.0.0.0.",
		}}
		badge={{
			text: status?.enabled ? "Active Shield" : "Paused",
			variant: status?.enabled ? "online" : "warning",
			showDot: true,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Policy"
				value={status?.blocking_mode ? status.blocking_mode.toUpperCase() : "NXDOMAIN"}
				color="text-amber-400"
			/>
			<StatCardFooterItem
				label="Enforcement"
				value={status?.enabled ? "Active" : "Paused"}
				color={status?.enabled ? "text-emerald-400" : "text-amber-400"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 4: Custom Rules & Overrides -->
	<StatCard
		label="Custom Rules & Overrides"
		value={status ? totalAllowedOrExceptions.toLocaleString() : null}
		subtext={exceptionsDomains > 0
			? `${allowlistDomains} whitelist, ${exceptionsDomains} @@ exceptions`
			: "User rules taking precedence over blocklists"}
		icon={ShieldCheckIcon}
		color="emerald"
		{loading}
		popover={{
			title: "Allowlist & Priority Overrides",
			description: "Local user rules, whitelisted domains, and Adblock Plus exception rules (@@) that bypass remote blocklists.",
		}}
		badge={{
			text: totalAllowedOrExceptions > 0 ? `${totalAllowedOrExceptions} Overrides` : "Default",
			variant: totalAllowedOrExceptions > 0 ? "emerald" : "zinc",
			showDot: totalAllowedOrExceptions > 0,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Whitelist Domains"
				value={allowlistDomains.toLocaleString()}
				color="text-emerald-400"
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Custom Rules</span>
				<a
					href="/dns/adblock/rules"
					class="text-[11px] text-primary hover:underline font-medium flex items-center gap-0.5 truncate"
				>
					<span>Filtering Rules</span>
					<ArrowRightIcon class="size-3 shrink-0" />
				</a>
			</div>
		{/snippet}
	</StatCard>
</StatCardGrid>
