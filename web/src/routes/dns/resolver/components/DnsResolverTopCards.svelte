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

	const cacheHitsCount = $derived.by(() => {
		if (!statsData) return 0;
		return statsData.cache_hits ?? 0;
	});

	const blockPct = $derived.by(() => {
		if (!statsData || statsData.total_requests === 0) return "0.0%";
		return `${((statsData.blocked_queries / statsData.total_requests) * 100).toFixed(1)}%`;
	});

	const resolvedCount = $derived.by(() => {
		if (!statsData) return 0;
		if (typeof statsData.resolved_total === "number" && statsData.resolved_total > 0) {
			return statsData.resolved_total;
		}
		return Math.max(0, statsData.total_requests - statsData.blocked_queries);
	});

	const forwardedCount = $derived.by(() => {
		if (!statsData) return 0;
		if (typeof statsData.recursions === "number" && statsData.recursions > 0) {
			return statsData.recursions;
		}
		return statsData.cache_misses ?? 0;
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
				total: 0,
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
			subtitle:
				healthy === total
					? "All configured forwarders healthy"
					: `${total - healthy} of ${total} forwarders degraded`,
			healthy,
			total,
		};
	});

	const avgUpstreamLatency = $derived.by(() => {
		const list = upstreams ?? [];
		const rtts = list
			.map((u) => {
				if (u.rtt_ewma_us !== undefined && u.rtt_ewma_us !== null && u.rtt_ewma_us > 0) {
					return u.rtt_ewma_us / 1000;
				}
				if (u.latency_ms !== undefined && u.latency_ms !== null && u.latency_ms > 0) {
					return u.latency_ms;
				}
				return null;
			})
			.filter((r): r is number => r !== null);

		if (rtts.length === 0) return null;
		const avg = rtts.reduce((a, b) => a + b, 0) / rtts.length;
		return `${avg.toFixed(1)} ms`;
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
				label="Resolved"
				value={statsData ? resolvedCount.toLocaleString() : "—"}
				color="text-emerald-400"
			/>
			<StatCardFooterItem
				label="Local / Rewrites"
				value={statsData?.auth_queries !== undefined ? statsData.auth_queries.toLocaleString() : "—"}
				color="text-sky-400"
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Cache Hit Ratio -->
	<StatCard
		label="Cache Hit Ratio"
		value={`${cacheHitPct}%`}
		subtext={`${cacheHitsCount.toLocaleString()} queries served from memory`}
		icon={ZapIcon}
		color="emerald"
		{loading}
		popover={{
			title: "Zero-Latency Memory Cache",
			description: "Queries resolved directly from memory without forwarding to upstream DNS resolvers.",
		}}
		badge={{
			text: cacheHitPct >= 70 ? "Optimal" : (cacheHitPct > 0 ? "Active" : "Standby"),
			variant: cacheHitPct >= 70 ? "online" : (cacheHitPct > 0 ? "emerald" : "zinc"),
			showDot: cacheHitPct > 0,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Active Records"
				value={statsData?.cache_entries !== undefined ? statsData.cache_entries.toLocaleString() : "—"}
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
		subtext="Ads, trackers & malicious domains"
		icon={ShieldIcon}
		color="rose"
		{loading}
		popover={{
			title: "DNS Domain Filtering",
			description: "Adware, tracking, telemetry, and custom rewrite domains blocked with NXDOMAIN or 0.0.0.0.",
		}}
		badge={{
			text: "Adblock Active",
			variant: "rose",
			showDot: true,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Block Rate"
				value={blockPct}
				color="text-rose-400"
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Rules & Lists</span>
				<a
					href="/dns/adblock"
					class="text-[11px] text-primary hover:underline font-medium flex items-center gap-0.5 truncate"
				>
					<span>Adblock Engine</span>
					<ArrowRightIcon class="size-3 shrink-0" />
				</a>
			</div>
		{/snippet}
	</StatCard>

	<!-- Card 4: Upstream Resolvers -->
	<StatCard
		label="Upstream Resolvers"
		value={upstreamStats.display}
		subtext={upstreamStats.subtitle}
		icon={ServerIcon}
		color="indigo"
		{loading}
		footerCols={3}
		popover={{
			title: "Upstream Resolvers",
			description: "Health-checked recursive resolvers configured for WAN domain resolution.",
		}}
		badge={{
			text: upstreamStats.total === 0 ? "None" : (upstreamStats.healthy === upstreamStats.total ? "Operational" : "Degraded"),
			variant: upstreamStats.total === 0 ? "zinc" : (upstreamStats.healthy === upstreamStats.total ? "online" : "warning"),
			showDot: upstreamStats.total > 0,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Forwarded"
				value={statsData ? forwardedCount.toLocaleString() : "—"}
				color="text-indigo-400"
			/>
			{#if upstreamErrorsCount > 0}
				<div class="flex flex-col gap-0.5 min-w-0">
					<span class="text-[11px] text-muted-foreground truncate">Failed</span>
					<a
						href="/dns/log?result=error"
						class="text-[11px] text-rose-400 hover:underline font-semibold flex items-center gap-0.5 truncate"
						title="View failed queries in query log"
					>
						<span>{upstreamErrorsCount.toLocaleString()}</span>
						<ArrowRightIcon class="size-2.5 shrink-0" />
					</a>
				</div>
			{:else}
				<StatCardFooterItem
					label="Failed"
					value={statsData ? "0" : "—"}
					color="text-muted-foreground"
				/>
			{/if}
			<StatCardFooterItem
				label="Avg Latency"
				value={avgUpstreamLatency ?? "—"}
				color="text-emerald-400"
			/>
		{/snippet}
	</StatCard>
</StatCardGrid>
