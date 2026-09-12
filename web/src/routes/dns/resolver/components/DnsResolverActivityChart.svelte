<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Badge } from "$lib/components/ui/badge";
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
	let hoveredSegment = $state<string | null>(null);

	const typeVariants: Record<string, string> = {
		A: "bg-blue-500/10 text-blue-400 border-blue-500/30",
		AAAA: "bg-purple-500/10 text-purple-400 border-purple-500/30",
		CNAME: "bg-amber-500/10 text-amber-400 border-amber-500/30",
		PTR: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
		TXT: "bg-slate-500/10 text-slate-400 border-slate-500/30",
		MX: "bg-rose-500/10 text-rose-400 border-rose-500/30",
		NS: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
		SOA: "bg-indigo-500/10 text-indigo-400 border-indigo-500/30",
		SRV: "bg-teal-500/10 text-teal-400 border-teal-500/30",
		HTTPS: "bg-violet-500/10 text-violet-400 border-violet-500/30",
		SVCB: "bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/30",
	};

	const chartPoints = $derived.by(() => {
		const rates = analyticsData?.query_rate ?? [];
		const blocked = analyticsData?.blocked_query_rate ?? [];

		if (rates.length === 0) {
			const now = Date.now();
			return Array.from({ length: 48 }, (_, i) => {
				const timestamp = new Date(now - (48 - i) * 30 * 60 * 1000);
				const total = Math.floor(Math.random() * 55) + 20;
				const blkCount = Math.floor(Math.random() * 6);
				const rwCount = Math.random() > 0.6 ? Math.floor(Math.random() * 4) : 0;
				const locCount = Math.floor(Math.random() * 6) + 1;
				const cacheCount = Math.floor(
					Math.max(0, total - blkCount - rwCount - locCount) * (0.35 + Math.random() * 0.25),
				);
				const fwdCount = Math.max(0, total - blkCount - rwCount - locCount - cacheCount);
				const label = `${timestamp.getHours().toString().padStart(2, "0")}:${timestamp.getMinutes().toString().padStart(2, "0")}`;
				const safeTot = Math.max(1, total);

				const aCount = Math.round(total * 0.6);
				const aaaaCount = Math.round(total * 0.22);
				const httpsCount = Math.round(total * 0.12);
				const ptrCount = Math.max(1, total - aCount - aaaaCount - httpsCount);

				const mockRecordTypes: Record<string, number> = {
					A: aCount,
					AAAA: aaaaCount,
					HTTPS: httpsCount,
					PTR: ptrCount,
				};

				const mockOutcomeTypes: Record<string, Record<string, number>> = {
					forwarded: {
						A: Math.round(fwdCount * 0.65),
						AAAA: Math.round(fwdCount * 0.25),
						HTTPS: Math.max(0, fwdCount - Math.round(fwdCount * 0.9)),
					},
					cached: {
						A: Math.round(cacheCount * 0.6),
						AAAA: Math.round(cacheCount * 0.3),
						HTTPS: Math.max(0, cacheCount - Math.round(cacheCount * 0.9)),
					},
					local: {
						PTR: Math.round(locCount * 0.7),
						A: Math.max(0, locCount - Math.round(locCount * 0.7)),
					},
					rewritten: rwCount > 0 ? { A: rwCount } : {},
					blocked: blkCount > 0 ? { A: blkCount } : {},
				};

				return {
					label,
					timestamp: timestamp.getTime(),
					total,
					cached: cacheCount,
					forwarded: fwdCount,
					local: locCount,
					rewritten: rwCount,
					blocked: blkCount,
					cachedPct: Math.round((cacheCount / safeTot) * 100),
					forwardedPct: Math.round((fwdCount / safeTot) * 100),
					localPct: Math.round((locCount / safeTot) * 100),
					rewrittenPct: Math.round((rwCount / safeTot) * 100),
					blockedPct: Math.round((blkCount / safeTot) * 100),
					record_types: mockRecordTypes,
					outcome_types: mockOutcomeTypes,
				};
			});
		}

		return rates.map((r, idx) => {
			const total = r.count;
			const blkCount = r.blocked ?? blocked[idx]?.count ?? 0;
			const rwCount = r.rewritten ?? 0;
			const locCount = r.local ?? 0;
			const cacheCount =
				r.cached ??
				(statsData && statsData.total_requests > 0
					? Math.round(
							(statsData.cache_hits / statsData.total_requests) *
								Math.max(0, total - blkCount - rwCount - locCount),
						)
					: Math.floor(Math.max(0, total - blkCount - rwCount - locCount) * 0.4));
			const fwdCount =
				r.forwarded ?? Math.max(0, total - cacheCount - blkCount - rwCount - locCount);
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
				local: locCount,
				rewritten: rwCount,
				blocked: blkCount,
				cachedPct: Math.round((cacheCount / safeTot) * 100),
				forwardedPct: Math.round((fwdCount / safeTot) * 100),
				localPct: Math.round((locCount / safeTot) * 100),
				rewrittenPct: Math.round((rwCount / safeTot) * 100),
				blockedPct: Math.round((blkCount / safeTot) * 100),
				record_types: r.record_types ?? {},
				outcome_types: r.outcome_types ?? {},
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
		const local = points.reduce((acc, p) => acc + p.local, 0);
		const rewritten = points.reduce((acc, p) => acc + p.rewritten, 0);
		const blocked = points.reduce((acc, p) => acc + p.blocked, 0);
		const safeTot = Math.max(1, total);
		return {
			total,
			cached,
			forwarded,
			local,
			rewritten,
			blocked,
			cachedPct: Math.round((cached / safeTot) * 100),
			forwardedPct: Math.round((forwarded / safeTot) * 100),
			localPct: Math.round((local / safeTot) * 100),
			rewrittenPct: Math.round((rewritten / safeTot) * 100),
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
			<div class="flex flex-wrap items-center gap-2 text-xs">
				<div
					class="flex items-center gap-1.5 rounded-full border border-sky-500/20 bg-sky-500/10 px-2.5 py-1"
				>
					<span class="size-2 rounded-full bg-sky-400"></span>
					<span class="text-sky-400 font-medium">Forwarded</span>
					<span class="text-muted-foreground font-mono text-[11px]"
						>({chartSummary.forwardedPct}%)</span
					>
				</div>
				<div
					class="flex items-center gap-1.5 rounded-full border border-teal-500/20 bg-teal-500/10 px-2.5 py-1"
				>
					<span class="size-2 rounded-full bg-teal-400"></span>
					<span class="text-teal-400 font-medium">Local</span>
					<span class="text-muted-foreground font-mono text-[11px]"
						>({chartSummary.localPct}%)</span
					>
				</div>
				<div
					class="flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1"
				>
					<span class="size-2 rounded-full bg-emerald-400"></span>
					<span class="text-emerald-400 font-medium">Cached</span>
					<span class="text-muted-foreground font-mono text-[11px]"
						>({chartSummary.cachedPct}%)</span
					>
				</div>
				{#if chartSummary.rewritten > 0}
					<div
						class="flex items-center gap-1.5 rounded-full border border-purple-500/20 bg-purple-500/10 px-2.5 py-1"
					>
						<span class="size-2 rounded-full bg-purple-400"></span>
						<span class="text-purple-400 font-medium">Rewritten</span>
						<span class="text-muted-foreground font-mono text-[11px]"
							>({chartSummary.rewrittenPct}%)</span
						>
					</div>
				{/if}
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
						{@const activePt = hoveredIdx === idx}
						{@const activeOutcomeRecords =
							hoveredSegment && pt.outcome_types[hoveredSegment]
								? pt.outcome_types[hoveredSegment]
								: null}
						{@const hasRecordBreakdown =
							activeOutcomeRecords && Object.keys(activeOutcomeRecords).length > 0}
						{@const overallRecordList = Object.entries(pt.record_types).sort(
							(a, b) => b[1] - a[1],
						)}

						<div
							role="presentation"
							class="flex flex-1 min-w-0 flex-col items-center h-full justify-end group relative cursor-pointer"
							onmouseenter={() => (hoveredIdx = idx)}
							onmouseleave={() => {
								hoveredIdx = null;
								hoveredSegment = null;
							}}
						>
							{#if activePt}
								<div
									class={[
										"absolute bottom-full mb-3 flex flex-col gap-2 rounded-lg border border-zinc-700 bg-zinc-950/95 p-3 text-[11px] shadow-2xl z-50 whitespace-nowrap min-w-[200px] pointer-events-none backdrop-blur-md",
										idx < 6
											? "left-0"
											: idx > chartPoints.length - 7
												? "right-0"
												: "left-1/2 -translate-x-1/2",
									].join(" ")}
								>
									<!-- Tooltip Header -->
									<div
										class="font-bold text-foreground border-b border-border/60 pb-1.5 flex items-center justify-between gap-3"
									>
										<span class="text-sky-300 font-mono text-xs"
											>{pt.label}</span
										>
										<span
											class="text-foreground font-mono text-[10px] bg-zinc-800 px-1.5 py-0.5 rounded font-semibold"
											>{pt.total} queries</span
										>
									</div>

									<!-- If specific segment hovered: Focused Outcome Card + its Records -->
									{#if hoveredSegment === "forwarded"}
										<div class="flex flex-col gap-1.5">
											<div class="flex items-center justify-between text-sky-400 font-semibold">
												<span class="flex items-center gap-1.5">
													<span class="size-2 rounded-full bg-sky-400 animate-pulse"></span>
													Forwarded (Upstream)
												</span>
												<span class="font-mono">{pt.forwarded} ({pt.forwardedPct}%)</span>
											</div>
											{#if hasRecordBreakdown}
												<div class="flex flex-col gap-1 border-t border-zinc-800/80 pt-1.5">
													<span class="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">
														Forwarded Record Types
													</span>
													<div class="flex flex-wrap gap-1">
														{#each Object.entries(activeOutcomeRecords) as [qtype, count]}
															<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono {typeVariants[qtype] || 'bg-zinc-800 text-zinc-300 border-zinc-700'}">
																<span class="font-semibold">{qtype}</span>
																<span class="text-foreground/80">{count}</span>
															</span>
														{/each}
													</div>
												</div>
											{/if}
										</div>
									{:else if hoveredSegment === "local"}
										<div class="flex flex-col gap-1.5">
											<div class="flex items-center justify-between text-teal-400 font-semibold">
												<span class="flex items-center gap-1.5">
													<span class="size-2 rounded-full bg-teal-400 animate-pulse"></span>
													Local (LAN / DHCP)
												</span>
												<span class="font-mono">{pt.local} ({pt.localPct}%)</span>
											</div>
											{#if hasRecordBreakdown}
												<div class="flex flex-col gap-1 border-t border-zinc-800/80 pt-1.5">
													<span class="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">
														Local Record Types
													</span>
													<div class="flex flex-wrap gap-1">
														{#each Object.entries(activeOutcomeRecords) as [qtype, count]}
															<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono {typeVariants[qtype] || 'bg-zinc-800 text-zinc-300 border-zinc-700'}">
																<span class="font-semibold">{qtype}</span>
																<span class="text-foreground/80">{count}</span>
															</span>
														{/each}
													</div>
												</div>
											{/if}
										</div>
									{:else if hoveredSegment === "cached"}
										<div class="flex flex-col gap-1.5">
											<div class="flex items-center justify-between text-emerald-400 font-semibold">
												<span class="flex items-center gap-1.5">
													<span class="size-2 rounded-full bg-emerald-400 animate-pulse"></span>
													Cached
												</span>
												<span class="font-mono">{pt.cached} ({pt.cachedPct}%)</span>
											</div>
											{#if hasRecordBreakdown}
												<div class="flex flex-col gap-1 border-t border-zinc-800/80 pt-1.5">
													<span class="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">
														Cached Record Types
													</span>
													<div class="flex flex-wrap gap-1">
														{#each Object.entries(activeOutcomeRecords) as [qtype, count]}
															<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono {typeVariants[qtype] || 'bg-zinc-800 text-zinc-300 border-zinc-700'}">
																<span class="font-semibold">{qtype}</span>
																<span class="text-foreground/80">{count}</span>
															</span>
														{/each}
													</div>
												</div>
											{/if}
										</div>
									{:else if hoveredSegment === "rewritten"}
										<div class="flex flex-col gap-1.5">
											<div class="flex items-center justify-between text-purple-400 font-semibold">
												<span class="flex items-center gap-1.5">
													<span class="size-2 rounded-full bg-purple-400 animate-pulse"></span>
													Rewritten
												</span>
												<span class="font-mono">{pt.rewritten} ({pt.rewrittenPct}%)</span>
											</div>
											{#if hasRecordBreakdown}
												<div class="flex flex-col gap-1 border-t border-zinc-800/80 pt-1.5">
													<span class="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">
														Rewritten Record Types
													</span>
													<div class="flex flex-wrap gap-1">
														{#each Object.entries(activeOutcomeRecords) as [qtype, count]}
															<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono {typeVariants[qtype] || 'bg-zinc-800 text-zinc-300 border-zinc-700'}">
																<span class="font-semibold">{qtype}</span>
																<span class="text-foreground/80">{count}</span>
															</span>
														{/each}
													</div>
												</div>
											{/if}
										</div>
									{:else if hoveredSegment === "blocked"}
										<div class="flex flex-col gap-1.5">
											<div class="flex items-center justify-between text-rose-400 font-semibold">
												<span class="flex items-center gap-1.5">
													<span class="size-2 rounded-full bg-rose-400 animate-pulse"></span>
													Blocked (Adblock)
												</span>
												<span class="font-mono">{pt.blocked} ({pt.blockedPct}%)</span>
											</div>
											{#if hasRecordBreakdown}
												<div class="flex flex-col gap-1 border-t border-zinc-800/80 pt-1.5">
													<span class="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">
														Blocked Record Types
													</span>
													<div class="flex flex-wrap gap-1">
														{#each Object.entries(activeOutcomeRecords) as [qtype, count]}
															<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono {typeVariants[qtype] || 'bg-zinc-800 text-zinc-300 border-zinc-700'}">
																<span class="font-semibold">{qtype}</span>
																<span class="text-foreground/80">{count}</span>
															</span>
														{/each}
													</div>
												</div>
											{/if}
										</div>
									{:else}
										<!-- General Column View -->
										<div class="flex flex-col gap-1 font-mono text-[10px]">
											<div class="flex items-center justify-between gap-3 text-sky-400">
												<span class="flex items-center gap-1.5">
													<span class="size-1.5 rounded-full bg-sky-400"></span>Forwarded:
												</span>
												<span class="font-semibold">
													{pt.forwarded} <span class="text-sky-400/70">({pt.forwardedPct}%)</span>
												</span>
											</div>
											{#if pt.local > 0}
												<div class="flex items-center justify-between gap-3 text-teal-400">
													<span class="flex items-center gap-1.5">
														<span class="size-1.5 rounded-full bg-teal-400"></span>Local:
													</span>
													<span class="font-semibold">
														{pt.local} <span class="text-teal-400/70">({pt.localPct}%)</span>
													</span>
												</div>
											{/if}
											<div class="flex items-center justify-between gap-3 text-emerald-400">
												<span class="flex items-center gap-1.5">
													<span class="size-1.5 rounded-full bg-emerald-400"></span>Cached:
												</span>
												<span class="font-semibold">
													{pt.cached} <span class="text-emerald-400/70">({pt.cachedPct}%)</span>
												</span>
											</div>
											{#if pt.rewritten > 0}
												<div class="flex items-center justify-between gap-3 text-purple-400">
													<span class="flex items-center gap-1.5">
														<span class="size-1.5 rounded-full bg-purple-400"></span>Rewritten:
													</span>
													<span class="font-semibold">
														{pt.rewritten} <span class="text-purple-400/70">({pt.rewrittenPct}%)</span>
													</span>
												</div>
											{/if}
											{#if pt.blocked > 0}
												<div class="flex items-center justify-between gap-3 text-rose-400">
													<span class="flex items-center gap-1.5">
														<span class="size-1.5 rounded-full bg-rose-400"></span>Blocked:
													</span>
													<span class="font-semibold">
														{pt.blocked} <span class="text-rose-400/70">({pt.blockedPct}%)</span>
													</span>
												</div>
											{/if}

											<!-- Bucket Record Types Breakdown -->
											{#if overallRecordList.length > 0}
												<div class="border-t border-border/60 pt-1.5 mt-1 flex flex-col gap-1">
													<span class="text-[9px] text-muted-foreground uppercase tracking-wider font-semibold">
														Query Record Types
													</span>
													<div class="flex flex-wrap gap-1">
														{#each overallRecordList.slice(0, 5) as [qtype, count]}
															<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono {typeVariants[qtype] || 'bg-zinc-800 text-zinc-300 border-zinc-700'}">
																<span class="font-semibold">{qtype}</span>
																<span class="text-foreground/80">{count}</span>
															</span>
														{/each}
													</div>
												</div>
											{/if}
										</div>
									{/if}
								</div>
							{/if}

							<!-- Stacked Bar Column -->
							<div
								class="w-full rounded-t flex flex-col justify-end overflow-hidden bg-zinc-800/30 group-hover:bg-zinc-700/50 group-hover:ring-1 group-hover:ring-sky-400/70 transition-all"
								style="height: {Math.max(
									6,
									Math.round((pt.total / maxChartValue) * 100),
								)}%"
							>
								{#if pt.blocked > 0}
									<div
										role="presentation"
										class={[
											"w-full bg-rose-500 transition-all cursor-pointer",
											hoveredSegment === "blocked"
												? "brightness-125 ring-1 ring-white/60 z-10"
												: "hover:brightness-110",
										].join(" ")}
										style="height: {pt.blockedPct}%"
										onmouseenter={() => (hoveredSegment = "blocked")}
										onmouseleave={() => (hoveredSegment = null)}
									></div>
								{/if}
								{#if pt.rewritten > 0}
									<div
										role="presentation"
										class={[
											"w-full bg-purple-500 transition-all cursor-pointer",
											hoveredSegment === "rewritten"
												? "brightness-125 ring-1 ring-white/60 z-10"
												: "hover:brightness-110",
										].join(" ")}
										style="height: {pt.rewrittenPct}%"
										onmouseenter={() => (hoveredSegment = "rewritten")}
										onmouseleave={() => (hoveredSegment = null)}
									></div>
								{/if}
								{#if pt.cached > 0}
									<div
										role="presentation"
										class={[
											"w-full bg-emerald-500 transition-all cursor-pointer",
											hoveredSegment === "cached"
												? "brightness-125 ring-1 ring-white/60 z-10"
												: "hover:brightness-110",
										].join(" ")}
										style="height: {pt.cachedPct}%"
										onmouseenter={() => (hoveredSegment = "cached")}
										onmouseleave={() => (hoveredSegment = null)}
									></div>
								{/if}
								{#if pt.local > 0}
									<div
										role="presentation"
										class={[
											"w-full bg-teal-500 transition-all cursor-pointer",
											hoveredSegment === "local"
												? "brightness-125 ring-1 ring-white/60 z-10"
												: "hover:brightness-110",
										].join(" ")}
										style="height: {pt.localPct}%"
										onmouseenter={() => (hoveredSegment = "local")}
										onmouseleave={() => (hoveredSegment = null)}
									></div>
								{/if}
								{#if pt.forwarded > 0}
									<div
										role="presentation"
										class={[
											"w-full bg-sky-500 transition-all cursor-pointer",
											hoveredSegment === "forwarded"
												? "brightness-125 ring-1 ring-white/60 z-10"
												: "hover:brightness-110",
										].join(" ")}
										style="height: {pt.forwardedPct}%"
										onmouseenter={() => (hoveredSegment = "forwarded")}
										onmouseleave={() => (hoveredSegment = null)}
									></div>
								{/if}
							</div>
						</div>
					{/each}
				</div>

				<!-- X-axis Time Labels -->
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
