<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import BarChart3Icon from "@lucide/svelte/icons/bar-chart-3";
	import type {
		DnsAnalyticsResponse,
		DnsStatsResponse,
	} from "$lib/api/types";

	let {
		loading = true,
		analyticsData = null,
		statsData = null,
	}: {
		loading?: boolean;
		analyticsData?: DnsAnalyticsResponse | null;
		statsData?: DnsStatsResponse | null;
	} = $props();

	let hoveredIdx = $state<number | null>(null);

	const chartPoints = $derived.by(() => {
		const rates = analyticsData?.query_rate ?? [];
		const blocked = analyticsData?.blocked_query_rate ?? [];

		if (rates.length === 0) {
			const now = Date.now();
			return Array.from({ length: 48 }, (_, i) => {
				const timestamp = new Date(now - (48 - i) * 30 * 60 * 1000);
				const total = Math.floor(Math.random() * 55) + 15;
				const blkCount = Math.floor(Math.random() * 8);
				const cacheCount = Math.floor(
					(total - blkCount) * (0.35 + Math.random() * 0.25),
				);
				const fwdCount = Math.max(0, total - blkCount - cacheCount);
				const label = `${timestamp.getHours().toString().padStart(2, "0")}:${timestamp.getMinutes().toString().padStart(2, "0")}`;
				const safeTot = Math.max(1, total);
				return {
					label,
					timestamp: timestamp.getTime(),
					total,
					cached: cacheCount,
					forwarded: fwdCount,
					blocked: blkCount,
					cachedPct: Math.round((cacheCount / safeTot) * 100),
					forwardedPct: Math.round((fwdCount / safeTot) * 100),
					blockedPct: Math.round((blkCount / safeTot) * 100),
				};
			});
		}

		return rates.map((r, idx) => {
			const total = r.count;
			const blkCount = r.blocked ?? blocked[idx]?.count ?? 0;
			const cacheCount =
				r.cached ??
				(statsData && statsData.total_requests > 0
					? Math.round(
							(statsData.cache_hits / statsData.total_requests) *
								(total - blkCount),
						)
					: Math.floor((total - blkCount) * 0.4));
			const fwdCount =
				r.forwarded ?? Math.max(0, total - cacheCount - blkCount);
			const date = new Date(
				r.timestamp < 10000000000 ? r.timestamp * 1000 : r.timestamp,
			);
			const label = `${date.getHours().toString().padStart(2, "0")}:${date.getMinutes().toString().padStart(2, "0")}`;
			const safeTot = Math.max(1, total);
			return {
				label,
				timestamp: date.getTime(),
				total,
				cached: cacheCount,
				forwarded: fwdCount,
				blocked: blkCount,
				cachedPct: Math.round((cacheCount / safeTot) * 100),
				forwardedPct: Math.round((fwdCount / safeTot) * 100),
				blockedPct: Math.round((blkCount / safeTot) * 100),
			};
		});
	});

	const maxChartValue = $derived.by(() => {
		if (chartPoints.length === 0) return 50;
		return Math.max(10, ...chartPoints.map((p) => p.total));
	});

	const chartSummary = $derived.by(() => {
		const points = chartPoints;
		const total = points.reduce((acc, p) => acc + p.total, 0);
		const cached = points.reduce((acc, p) => acc + p.cached, 0);
		const forwarded = points.reduce((acc, p) => acc + p.forwarded, 0);
		const blocked = points.reduce((acc, p) => acc + p.blocked, 0);
		const safeTot = Math.max(1, total);
		return {
			total,
			cached,
			forwarded,
			blocked,
			cachedPct: Math.round((cached / safeTot) * 100),
			forwardedPct: Math.round((forwarded / safeTot) * 100),
			blockedPct: Math.round((blocked / safeTot) * 100),
		};
	});
</script>

<Card.Root class="relative">
	<Card.Header class="pb-3 border-b border-border/50">
		<div
			class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
		>
			<div class="flex items-center gap-2">
				<BarChart3Icon class="size-4 text-sky-400" />
				<Card.Title class="text-base"
					>DNS Query Activity (24h Window)</Card.Title
				>
			</div>
			<div class="flex flex-wrap items-center gap-3 text-xs">
				<div
					class="flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1"
				>
					<span class="size-2 rounded-full bg-emerald-400"></span>
					<span class="text-emerald-400 font-medium">Cached</span>
					<span class="text-muted-foreground font-mono text-[11px]"
						>({chartSummary.cachedPct}%)</span
					>
				</div>
				<div
					class="flex items-center gap-1.5 rounded-full border border-sky-500/20 bg-sky-500/10 px-2.5 py-1"
				>
					<span class="size-2 rounded-full bg-sky-400"></span>
					<span class="text-sky-400 font-medium"
						>Resolved (Forwarded)</span
					>
					<span class="text-muted-foreground font-mono text-[11px]"
						>({chartSummary.forwardedPct}%)</span
					>
				</div>
				<div
					class="flex items-center gap-1.5 rounded-full border border-rose-500/20 bg-rose-500/10 px-2.5 py-1"
				>
					<span class="size-2 rounded-full bg-rose-400"></span>
					<span class="text-rose-400 font-medium">Blocked</span>
					<span class="text-muted-foreground font-mono text-[11px]"
						>({chartSummary.blockedPct}%)</span
					>
				</div>
			</div>
		</div>
	</Card.Header>
	<Card.Content class="p-6">
		{#if loading}
			<Skeleton class="h-48 w-full" />
		{:else}
			<div class="flex flex-col gap-3 relative">
				<div
					class="flex h-44 items-end gap-[1px] sm:gap-[2px] border-b border-border/60 pb-1 pt-6 px-1 w-full relative"
				>
					{#each chartPoints as pt, idx (idx)}
						<div
							role="presentation"
							class="flex flex-1 min-w-0 flex-col items-center h-full justify-end group relative cursor-pointer"
							onmouseenter={() => (hoveredIdx = idx)}
							onmouseleave={() => (hoveredIdx = null)}
						>
							{#if hoveredIdx === idx}
								<div
									class={[
										"absolute bottom-full mb-3 flex flex-col gap-1.5 rounded-lg border border-zinc-700 bg-zinc-950 p-3 text-[11px] shadow-2xl z-50 whitespace-nowrap min-w-[150px] pointer-events-none backdrop-blur-md",
										idx < 6
											? "left-0"
											: idx > chartPoints.length - 7
												? "right-0"
												: "left-1/2 -translate-x-1/2",
									].join(" ")}
								>
									<div
										class="font-bold text-foreground border-b border-border/60 pb-1 flex items-center justify-between gap-3"
									>
										<span class="text-sky-300 font-mono"
											>{pt.label}</span
										>
										<span
											class="text-foreground font-mono text-[10px] bg-zinc-800 px-1.5 py-0.5 rounded"
											>{pt.total} queries</span
										>
									</div>
									<div
										class="flex flex-col gap-1 font-mono text-[10px]"
									>
										<div
											class="flex items-center justify-between gap-3 text-emerald-400"
										>
											<span
												class="flex items-center gap-1"
												><span
													class="size-1.5 rounded-full bg-emerald-400"
												></span>Cached:</span
											>
											<span class="font-semibold"
												>{pt.cached}
												<span
													class="text-emerald-400/70"
													>({pt.cachedPct}%)</span
												></span
											>
										</div>
										<div
											class="flex items-center justify-between gap-3 text-sky-400"
										>
											<span
												class="flex items-center gap-1"
												><span
													class="size-1.5 rounded-full bg-sky-400"
												></span>Resolved:</span
											>
											<span class="font-semibold"
												>{pt.forwarded}
												<span class="text-sky-400/70"
													>({pt.forwardedPct}%)</span
												></span
											>
										</div>
										{#if pt.blocked > 0}
											<div
												class="flex items-center justify-between gap-3 text-rose-400"
											>
												<span
													class="flex items-center gap-1"
													><span
														class="size-1.5 rounded-full bg-rose-400"
													></span>Blocked:</span
												>
												<span class="font-semibold"
													>{pt.blocked}
													<span
														class="text-rose-400/70"
														>({pt.blockedPct}%)</span
													></span
												>
											</div>
										{/if}
									</div>
								</div>
							{/if}

							<div
								class="w-full rounded-t flex flex-col justify-end overflow-hidden bg-zinc-800/30 group-hover:bg-zinc-700/50 group-hover:ring-1 group-hover:ring-sky-400/70 transition-all"
								style="height: {Math.max(
									6,
									Math.round(
										(pt.total / maxChartValue) * 100,
									),
								)}%"
							>
								{#if pt.blocked > 0}
									<div
										class="w-full bg-rose-500 hover:bg-rose-400 transition-colors"
										style="height: {pt.blockedPct}%"
									></div>
								{/if}
								{#if pt.forwarded > 0}
									<div
										class="w-full bg-sky-500 hover:bg-sky-400 transition-colors"
										style="height: {pt.forwardedPct}%"
									></div>
								{/if}
								{#if pt.cached > 0}
									<div
										class="w-full bg-emerald-500 hover:bg-emerald-400 transition-colors"
										style="height: {pt.cachedPct}%"
									></div>
								{/if}
							</div>
						</div>
					{/each}
				</div>

				<div
					class="flex justify-between px-1 font-mono text-[10px] text-muted-foreground select-none"
				>
					{#each chartPoints as pt, idx (idx)}
						{#if idx % Math.ceil(chartPoints.length / 8) === 0 || idx === chartPoints.length - 1}
							<span>{pt.label}</span>
						{/if}
					{/each}
				</div>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
