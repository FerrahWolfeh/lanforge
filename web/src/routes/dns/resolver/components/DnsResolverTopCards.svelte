<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ServerIcon from "@lucide/svelte/icons/server";
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
		return Math.round(
			(statsData.cache_hits / cacheTotal) * 100,
		);
	});

	const cacheMissesCount = $derived.by(() => {
		if (!statsData) return 0;
		return statsData.cache_misses ?? 0;
	});

	const upstreamStats = $derived.by(() => {
		const list: DnsUpstreamEntry[] = Array.isArray(upstreams)
			? upstreams
			: upstreams &&
				  typeof upstreams === "object" &&
				  Array.isArray((upstreams as any).upstreams)
				? (upstreams as any).upstreams
				: [];
		const total = list.length;
		if (total === 0) {
			return {
				display: "2 / 2",
				subtitle: "System default resolvers (1.1.1.1, 8.8.8.8)",
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
		};
	});
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Total Processed Queries -->
	<Card.Root
		class="relative overflow-hidden transition-all hover:border-zinc-700"
	>
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span
					class="text-muted-foreground text-xs font-semibold uppercase tracking-wider"
				>
					Total DNS Queries
				</span>
				<div
					class="flex size-8 items-center justify-center rounded-lg border bg-sky-500/10 border-sky-500/20"
				>
					<ActivityIcon class="size-4 text-sky-400" />
				</div>
			</div>
			{#if loading || !statsData}
				<Skeleton class="h-8 w-28" />
				<Skeleton class="h-3.5 w-36" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span
						class="text-foreground text-3xl font-bold tabular-nums tracking-tight"
					>
						{statsData.total_requests.toLocaleString()}
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						Lifetime queries processed
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Cache Hit Ratio -->
	<Card.Root
		class="relative overflow-hidden transition-all hover:border-zinc-700"
	>
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span
					class="text-muted-foreground text-xs font-semibold uppercase tracking-wider"
				>
					Cache Hit Ratio
				</span>
				<div
					class="flex size-8 items-center justify-center rounded-lg border bg-emerald-500/10 border-emerald-500/20"
				>
					<ZapIcon class="size-4 text-emerald-400" />
				</div>
			</div>
			{#if loading || !statsData}
				<Skeleton class="h-8 w-28" />
				<Skeleton class="h-3.5 w-20" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span
						class="text-emerald-400 text-3xl font-bold tabular-nums tracking-tight"
					>
						{cacheHitPct}%
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						{statsData.cache_hits.toLocaleString()} hits / {cacheMissesCount.toLocaleString()}
						misses (active session)
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Blocked Queries -->
	<Card.Root
		class="relative overflow-hidden transition-all hover:border-zinc-700"
	>
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span
					class="text-muted-foreground text-xs font-semibold uppercase tracking-wider"
				>
					Blocked Queries
				</span>
				<div
					class="flex size-8 items-center justify-center rounded-lg border bg-rose-500/10 border-rose-500/20"
				>
					<ShieldIcon class="size-4 text-rose-400" />
				</div>
			</div>
			{#if loading || !statsData}
				<Skeleton class="h-8 w-28" />
				<Skeleton class="h-3.5 w-20" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span
						class="text-rose-400 text-3xl font-bold tabular-nums tracking-tight"
					>
						{statsData.blocked_queries.toLocaleString()}
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						Lifetime adblock &amp; rule matches
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Upstream Health -->
	<Card.Root
		class="relative overflow-hidden transition-all hover:border-zinc-700"
	>
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span
					class="text-muted-foreground text-xs font-semibold uppercase tracking-wider"
				>
					Upstreams Active
				</span>
				<div
					class="flex size-8 items-center justify-center rounded-lg border bg-indigo-500/10 border-indigo-500/20"
				>
					<ServerIcon class="size-4 text-indigo-400" />
				</div>
			</div>
			{#if loading}
				<Skeleton class="h-8 w-20" />
				<Skeleton class="h-3.5 w-28" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span
						class="text-indigo-400 text-3xl font-bold tabular-nums tracking-tight"
					>
						{upstreamStats.display}
					</span>
					<span
						class="text-muted-foreground text-xs font-medium truncate"
						title={upstreamStats.subtitle}
					>
						{upstreamStats.subtitle}
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
