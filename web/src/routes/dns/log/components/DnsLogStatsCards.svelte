<script lang="ts">
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { DnsQueryLogEntry, DnsStatsResponse } from "$lib/api/types";

	let {
		loading = false,
		isLive = true,
		entries = [],
		total = 0,
		stats = null,
		selectedResult = "",
		onSelectResult = (res: string) => {},
	}: {
		loading?: boolean;
		isLive?: boolean;
		entries?: DnsQueryLogEntry[];
		total?: number;
		stats?: DnsStatsResponse | null;
		selectedResult?: string;
		onSelectResult?: (res: string) => void;
	} = $props();

	const totalQueries = $derived.by(() => {
		if (selectedResult && total > 0) return total;
		if (stats && typeof stats.total_requests === "number" && stats.total_requests > 0) {
			return stats.total_requests;
		}
		return total > 0 ? total : entries.length;
	});

	const cacheHitPct = $derived.by(() => {
		if (!stats || stats.total_requests === 0) return 0;
		return Math.round((stats.cache_hits / stats.total_requests) * 100);
	});

	const forwardedPct = $derived.by(() => {
		if (!stats || stats.total_requests === 0) return 0;
		const forwarded = stats.recursions ?? stats.cache_misses ?? 0;
		return Math.round((forwarded / stats.total_requests) * 100);
	});

	const blockedCount = $derived.by(() => {
		if (stats && typeof stats.blocked_queries === "number" && stats.total_requests > 0) {
			return stats.blocked_queries;
		}
		return entries.filter(
			(e) =>
				e.result.toLowerCase().includes("block") ||
				e.result.toLowerCase().includes("deny"),
		).length;
	});

	const blockPct = $derived.by(() => {
		if (stats && stats.total_requests > 0) {
			return `${((stats.blocked_queries / stats.total_requests) * 100).toFixed(1)}%`;
		}
		return entries.length > 0
			? `${((blockedCount / entries.length) * 100).toFixed(1)}%`
			: "0.0%";
	});

	const failedCount = $derived.by(() => {
		if (stats) {
			if (typeof stats.upstream_errors === "number" && stats.upstream_errors > 0) {
				return stats.upstream_errors;
			}
			if (typeof stats.failed_total === "number" && stats.failed_total > 0) {
				return stats.failed_total;
			}
		}
		return entries.filter((e) => e.result.toLowerCase().includes("error")).length;
	});

	const validEntries = $derived(entries.filter((e) => e.upstream_us > 0));
	const validEntriesCount = $derived(validEntries.length);

	const avgLatencyUs = $derived.by(() => {
		if (validEntries.length === 0) return 0;
		const sum = validEntries.reduce((acc, curr) => acc + curr.upstream_us, 0);
		return Math.round(sum / validEntries.length);
	});

	function formatLatency(us: number): string {
		if (us === 0) return "< 1 ms";
		if (us < 1000) return `${us} µs`;
		return `${(us / 1000).toFixed(1)} ms`;
	}
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Total Audited Queries -->
	<StatCard
		label="Total Audited Queries"
		value={totalQueries.toLocaleString()}
		icon={ListFilterIcon}
		color="sky"
		subtext={selectedResult
			? `${total.toLocaleString()} queries match "${selectedResult}"`
			: "All processed queries in audit buffer"}
		loading={loading && entries.length === 0 && !stats}
		popover={{
			title: "DNS Query Audit Log",
			description: "Cumulative DNS requests logged in the query audit ring buffer, capturing client IP, record type, latency, and disposition.",
		}}
		badge={{
			text: selectedResult ? "Filtered" : "Audit Trail",
			variant: selectedResult ? "sky" : "outline",
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Cache Hits"
				value={stats ? `${stats.cache_hits.toLocaleString()} (${cacheHitPct}%)` : "—"}
				color="text-emerald-400"
			/>
			<StatCardFooterItem
				label="Forwarded"
				value={stats
					? `${(stats.recursions ?? stats.cache_misses ?? 0).toLocaleString()} (${forwardedPct}%)`
					: "—"}
				color="text-indigo-400"
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Blocked & Filtered -->
	<StatCard
		label="Blocked & Filtered"
		value={blockedCount.toLocaleString()}
		icon={ShieldAlertIcon}
		color="rose"
		subtext={`${blockPct} of total queries blocked`}
		loading={loading && entries.length === 0 && !stats}
		popover={{
			title: "Adblock & Filtering",
			description: "Queries intercepted by adblock list subscriptions, custom domain blacklists, or malware shields.",
		}}
		badge={{
			text: blockedCount > 0 ? "Adblock Active" : "Standby",
			variant: blockedCount > 0 ? "rose" : "zinc",
			showDot: blockedCount > 0,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Block Rate"
				value={blockPct}
				color="text-rose-400"
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Audit Filter</span>
				<button
					type="button"
					onclick={() => onSelectResult?.(selectedResult === "blocked" ? "" : "blocked")}
					class="text-[11px] text-primary hover:underline font-medium flex items-center gap-0.5 truncate cursor-pointer text-left"
				>
					<span>{selectedResult === "blocked" ? "Clear Filter" : "Filter Blocked"}</span>
					<ArrowRightIcon class="size-3 shrink-0" />
				</button>
			</div>
		{/snippet}
	</StatCard>

	<!-- Card 3: Upstream Failures -->
	<StatCard
		label="Upstream Failures"
		value={failedCount.toLocaleString()}
		icon={failedCount > 0 ? AlertTriangleIcon : ShieldCheckIcon}
		color={failedCount > 0 ? "amber" : "emerald"}
		subtext={failedCount === 0
			? "Zero upstream resolution errors"
			: "Upstream timeouts & network errors"}
		loading={loading && entries.length === 0 && !stats}
		popover={{
			title: "Upstream Failures",
			description: "Queries that failed to receive a valid response from upstream forwarders or encountered network timeouts.",
		}}
		badge={{
			text: failedCount > 0 ? `${failedCount.toLocaleString()} Failed` : "Clean",
			variant: failedCount > 0 ? "rose" : "online",
			showDot: true,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Failure Rate"
				value={stats && stats.total_requests > 0
					? `${((failedCount / stats.total_requests) * 100).toFixed(2)}%`
					: "0.0%"}
				color={failedCount > 0 ? "text-rose-400" : "text-emerald-400"}
			/>
			<div class="flex flex-col gap-0.5 min-w-0">
				<span class="text-[11px] text-muted-foreground truncate">Troubleshooting</span>
				{#if failedCount > 0}
					<button
						type="button"
						onclick={() => onSelectResult?.(selectedResult === "error" ? "" : "error")}
						class="text-[11px] text-rose-400 hover:underline font-semibold flex items-center gap-0.5 truncate cursor-pointer text-left"
					>
						<span>{selectedResult === "error" ? "Clear Filter" : "Inspect Errors"}</span>
						<ArrowRightIcon class="size-2.5 shrink-0" />
					</button>
				{:else}
					<span class="text-[11px] text-muted-foreground font-medium truncate">No Failures</span>
				{/if}
			</div>
		{/snippet}
	</StatCard>

	<!-- Card 4: Upstream Latency -->
	<StatCard
		label="Upstream Latency"
		value={formatLatency(avgLatencyUs)}
		icon={GaugeIcon}
		color="violet"
		subtext={validEntriesCount > 0
			? `Average recursive time across ${validEntriesCount} lookups`
			: "Responses served from cache or local hosts"}
		loading={loading && entries.length === 0 && !stats}
		popover={{
			title: "Forwarding Latency",
			description: "Network round-trip response time for queries forwarded to external recursive DNS resolvers.",
		}}
		badge={{
			text: avgLatencyUs > 0 ? (avgLatencyUs < 50000 ? "Low Latency" : "Elevated") : "Sub-ms",
			variant: avgLatencyUs > 0 ? (avgLatencyUs < 50000 ? "emerald" : "warning") : "sky",
			showDot: avgLatencyUs > 0,
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Memory Cache"
				value="< 1 ms (Instant)"
				color="text-emerald-400"
			/>
			<StatCardFooterItem
				label="Sampled"
				value={validEntriesCount > 0 ? `${validEntriesCount} queries` : "Cached"}
			/>
		{/snippet}
	</StatCard>
</StatCardGrid>
