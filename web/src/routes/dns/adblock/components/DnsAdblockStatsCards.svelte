<script lang="ts">
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import StatStrip, { type StatStripItem } from "$lib/components/StatStrip.svelte";
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

	const blockPercentageNum = $derived.by(() => {
		if (analytics24h) return analytics24h.blockPctNum;
		if (totalQueries === 0) return 0;
		return (blockedQueries / totalQueries) * 100;
	});

	const noData = $derived(loading && !analytics && !stats);

	const items = $derived<StatStripItem[]>([
		{
			label: "queries blocked in 24h",
			value: noData ? null : blockedQueries,
			of: totalQueries,
			icon: ShieldAlertIcon,
			bar: Math.min(1, Math.max(0, blockPercentageNum / 100)),
			barTone: "danger",
			href: "/dns/adblock",
		},
		{
			label: "domains on blocklist",
			value: status ? blocklistDomains : null,
			icon: DatabaseIcon,
			href: "/dns/adblock/lists",
		},
		{
			label: "allowed domains",
			value: status ? totalAllowedOrExceptions : null,
			icon: ShieldCheckIcon,
			href: "/dns/adblock/rules",
		},
	]);
</script>

<StatStrip {items} />
