<script lang="ts">
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ServerIcon from "@lucide/svelte/icons/server";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import StatStrip, { type StatStripItem } from "$lib/components/StatStrip.svelte";
	import type { DnsStatsResponse, DnsAnalyticsResponse, DnsUpstreamEntry } from "$lib/api/types";

	let {
		loading = true,
		statsData = null,
		analyticsData = null,
		upstreams = [],
	}: {
		loading?: boolean;
		statsData?: DnsStatsResponse | null;
		analyticsData?: DnsAnalyticsResponse | null;
		upstreams?: DnsUpstreamEntry[];
	} = $props();

	const analytics24h = $derived.by(() => {
		const rates = analyticsData?.query_rate ?? [];
		if (rates.length === 0) return null;
		const total = rates.reduce((acc, r) => acc + r.count, 0);
		const cached = rates.reduce((acc, r) => acc + (r.cached ?? 0), 0);
		const forwarded = rates.reduce((acc, r) => acc + (r.forwarded ?? 0), 0);
		const blocked = rates.reduce((acc, r) => acc + (r.blocked ?? 0), 0);
		const local = rates.reduce((acc, r) => acc + (r.local ?? 0), 0);
		const rewritten = rates.reduce((acc, r) => acc + (r.rewritten ?? 0), 0);
		const resolved = Math.max(0, total - blocked);
		const safeTot = Math.max(1, total);
		return {
			total,
			cached,
			forwarded,
			blocked,
			local,
			rewritten,
			resolved,
			cacheHitPct: Math.round((cached / safeTot) * 100),
			blockPct: ((blocked / safeTot) * 100).toFixed(1),
		};
	});

	const totalQueries = $derived.by(() => {
		if (analytics24h) return analytics24h.total;
		return statsData?.total_requests ?? 0;
	});

	const cacheHitPct = $derived.by(() => {
		if (analytics24h) return analytics24h.cacheHitPct;
		if (!statsData) return 0;
		const cacheTotal = statsData.cache_hits + (statsData.cache_misses ?? 0);
		if (cacheTotal === 0) return 0;
		return Math.round((statsData.cache_hits / cacheTotal) * 100);
	});

	const blockedCount = $derived.by(() => {
		if (analytics24h) return analytics24h.blocked;
		return statsData?.blocked_queries ?? 0;
	});

	const blockPct = $derived.by(() => {
		if (analytics24h) return `${analytics24h.blockPct}%`;
		if (!statsData || statsData.total_requests === 0) return "0.0%";
		return `${((statsData.blocked_queries / statsData.total_requests) * 100).toFixed(1)}%`;
	});

	const upstreamErrorsCount = $derived.by(() => {
		if (!statsData) return 0;
		if (typeof statsData.upstream_errors === "number" && statsData.upstream_errors > 0) {
			return statsData.upstream_errors;
		}
		return statsData.failed_total ?? 0;
	});

	const upstreamStats = $derived.by(() => {
		const list = upstreams ?? [];
		const total = list.length;
		if (total === 0) {
			return {
				display: "0 / 0",
				subtitle: "No upstream forwarders configured",
				healthy: 0,
				degraded: 0,
				total: 0,
			};
		}
		const healthy = list.filter((u) => u.status === "healthy").length;
		const degraded = list.filter((u) => u.status === "degraded").length;
		const unmeasured = list.filter((u) => u.status === "unknown").length;
		let subtitle = "All configured forwarders healthy";
		if (unmeasured === total) subtitle = "Not measured (DNS is not serving)";
		else if (degraded > 0) subtitle = `${degraded} of ${total} forwarders degraded`;
		else if (healthy < total) subtitle = `${total - healthy} of ${total} forwarders not in use`;
		return {
			display: `${healthy} / ${total}`,
			subtitle,
			healthy,
			degraded,
			total,
		};
	});

	const noData = $derived(loading && !analyticsData && !statsData);
	const blockedFraction = $derived(totalQueries > 0 ? Math.min(1, blockedCount / totalQueries) : 0);

	const items = $derived.by(() => {
		const list: StatStripItem[] = [
			{ label: "queries in 24h", value: noData ? null : totalQueries, icon: ActivityIcon },
			{
				label: "cache hit ratio",
				value: `${cacheHitPct}%`,
				icon: ZapIcon,
				bar: cacheHitPct / 100,
				href: "/dns/cache",
			},
			{
				label: "queries blocked in 24h",
				value: noData ? null : blockedCount,
				of: totalQueries,
				icon: ShieldIcon,
				bar: blockedFraction,
				barTone: "danger",
				href: "/dns/adblock",
			},
			{
				label: "upstream resolvers healthy",
				value: upstreamStats.healthy,
				of: upstreamStats.total,
				icon: ServerIcon,
				tone: upstreamStats.degraded > 0 ? "warning" : undefined,
			},
		];
		if (upstreamErrorsCount > 0) {
			list.push({
				label: "upstream failures",
				value: upstreamErrorsCount,
				icon: AlertTriangleIcon,
				tone: "danger",
				href: "/dns/log?result=error",
			});
		}
		return list;
	});
</script>

<StatStrip {items} />
