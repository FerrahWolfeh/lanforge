<script lang="ts">
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ServerIcon from "@lucide/svelte/icons/server";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { DnsStatsResponse, DnsUpstreamEntry } from "$lib/api/types";

	let {
		loading = true,
		statsData = null,
		upstreams = [],
	}: {
		loading?: boolean;
		statsData?: DnsStatsResponse | null;
		upstreams?: DnsUpstreamEntry[];
	} = $props();

	const cacheHitPct = $derived.by(() => {
		if (!statsData) return 0;
		const cacheTotal = statsData.cache_hits + (statsData.cache_misses ?? 0);
		if (cacheTotal === 0) return 0;
		return Math.round((statsData.cache_hits / cacheTotal) * 100);
	});

	const cacheMissesCount = $derived.by(() => {
		if (!statsData) return 0;
		return statsData.cache_misses ?? 0;
	});

	const blockPct = $derived.by(() => {
		if (!statsData || statsData.total_requests === 0) return "0.0%";
		return `${((statsData.blocked_queries / statsData.total_requests) * 100).toFixed(1)}%`;
	});

	const upstreamStats = $derived.by(() => {
		const list = upstreams ?? [];
		const total = list.length;
		if (total === 0) {
			return {
				display: "2 / 2",
				subtitle: "System default resolvers (1.1.1.1, 8.8.8.8)",
				healthy: 2,
				total: 2,
			};
		}
		const healthy = list.filter(
			(u) =>
				!u.status ||
				u.status.toLowerCase() === "healthy" ||
				u.status.toLowerCase() === "ok",
		).length;
		return {
			display: `${healthy} / ${total}`,
			subtitle: `${healthy} of ${total} upstreams operational`,
			healthy,
			total,
		};
	});
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Total DNS Queries -->
	<StatCard
		label="Total DNS Queries"
		value={statsData ? statsData.total_requests.toLocaleString() : null}
		subtext="Lifetime queries processed"
		icon={ActivityIcon}
		color="sky"
		{loading}
		popover={{
			title: "DNS Query Engine",
			description: "Total recursive, authoritative, and cached queries handled across UDP and TCP port 53.",
		}}
		badge={{
			text: "Port 53",
			variant: "sky",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Cache Hits"
				value={statsData?.cache_hits?.toLocaleString() ?? "—"}
				color="text-emerald-400"
			/>
			<StatCardFooterItem
				label="Upstream Resolves"
				value={(statsData?.recursions ?? cacheMissesCount).toLocaleString()}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Cache Hit Ratio -->
	<StatCard
		label="Cache Hit Ratio"
		value={`${cacheHitPct}%`}
		subtext={`${statsData?.cache_hits.toLocaleString() ?? 0} hits / ${cacheMissesCount.toLocaleString()} misses`}
		icon={ZapIcon}
		color="emerald"
		{loading}
		popover={{
			title: "Zero-Latency Memory Cache",
			description: "Queries resolved directly from memory without forwarding to upstream DNS resolvers.",
		}}
		badge={{
			text: cacheHitPct >= 70 ? "Optimal" : "Active",
			variant: "online",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Hits"
				value={statsData?.cache_hits?.toLocaleString() ?? "—"}
				color="text-emerald-400"
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Inspection</span>
				<a
					href="/dns/cache"
					class="text-[11px] text-primary hover:underline font-medium flex items-center gap-0.5 truncate"
				>
					<span>Cache Table</span>
					<ArrowRightIcon class="size-3 shrink-0" />
				</a>
			</div>
		{/snippet}
	</StatCard>

	<!-- Card 3: Blocked Queries -->
	<StatCard
		label="Blocked Queries"
		value={statsData ? statsData.blocked_queries.toLocaleString() : null}
		subtext="Lifetime adblock & rule matches"
		icon={ShieldIcon}
		color="rose"
		{loading}
		popover={{
			title: "DNS Domain Filtering",
			description: "Adware, tracking, telemetry, and custom rewrite domains blocked with NXDOMAIN or 0.0.0.0.",
		}}
		badge={{
			text: `${blockPct} Block Rate`,
			variant: "error",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Block Rate" value={blockPct} color="text-rose-400" />
			<StatCardFooterItem label="Filtering Mode" value="Zero-Copy FST" />
		{/snippet}
	</StatCard>

	<!-- Card 4: Upstreams Active -->
	<StatCard
		label="Upstreams Active"
		value={upstreamStats.display}
		subtext={upstreamStats.subtitle}
		icon={ServerIcon}
		color="indigo"
		{loading}
		popover={{
			title: "Upstream Resolvers",
			description: "Health-checked recursive resolvers configured for WAN domain resolution.",
		}}
		badge={{
			text: upstreamStats.healthy === upstreamStats.total ? "All Operational" : "Degraded",
			variant: upstreamStats.healthy === upstreamStats.total ? "online" : "warning",
			showDot: true,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Operational"
				value={`${upstreamStats.healthy} / ${upstreamStats.total}`}
				color="text-emerald-400"
			/>
			<StatCardFooterItem label="Failover" value="Concurrent" />
		{/snippet}
	</StatCard>
</StatCardGrid>
