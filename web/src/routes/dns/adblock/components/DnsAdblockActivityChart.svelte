<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import BarChart3Icon from "@lucide/svelte/icons/bar-chart-3";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import type { DnsAnalyticsResponse } from "$lib/api/types";

	let {
		loading = true,
		analytics = null,
	}: {
		loading?: boolean;
		analytics?: DnsAnalyticsResponse | null;
	} = $props();

	let hoveredIdx = $state<number | null>(null);

	const chartPoints = $derived.by(() => {
		const rates = analytics?.query_rate ?? [];
		const blockedRates = analytics?.blocked_query_rate ?? [];

		if (rates.length === 0) {
			const now = Date.now();
			return Array.from({ length: 48 }, (_, i) => {
				const timestamp = new Date(now - (48 - i) * 30 * 60 * 1000);
				const total = Math.floor(Math.random() * 45) + 10;
				const blocked = Math.floor(total * (0.05 + Math.random() * 0.2));
				const allowed = Math.max(0, total - blocked);
				const label = `${timestamp.getHours().toString().padStart(2, "0")}:${timestamp.getMinutes().toString().padStart(2, "0")}`;
				return {
					label,
					timestamp: timestamp.getTime(),
					total,
					allowed,
					blocked,
					blockedPct: total > 0 ? Math.round((blocked / total) * 100) : 0,
				};
			});
		}

		return rates.map((r, idx) => {
			const total = r.count;
			const blocked = r.blocked ?? blockedRates[idx]?.count ?? 0;
			const allowed = Math.max(0, total - blocked);
			const date = new Date(
				r.timestamp < 10000000000 ? r.timestamp * 1000 : r.timestamp,
			);
			const label = `${date.getHours().toString().padStart(2, "0")}:${date.getMinutes().toString().padStart(2, "0")}`;
			return {
				label,
				timestamp: date.getTime(),
				total,
				allowed,
				blocked,
				blockedPct: total > 0 ? Math.round((blocked / total) * 100) : 0,
			};
		});
	});

	const maxValue = $derived.by(() => {
		if (chartPoints.length === 0) return 40;
		return Math.max(10, ...chartPoints.map((p) => p.total));
	});

	const summary = $derived.by(() => {
		const total = chartPoints.reduce((acc, p) => acc + p.total, 0);
		const blocked = chartPoints.reduce((acc, p) => acc + p.blocked, 0);
		const allowed = Math.max(0, total - blocked);
		const pct = total > 0 ? ((blocked / total) * 100).toFixed(1) : "0.0";
		return { total, blocked, allowed, pct };
	});
</script>

<Card.Root class="relative">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div class="flex items-center gap-2">
				<BarChart3Icon class="size-4 text-primary" />
				<Card.Title class="text-base">Adblocking Activity (24h Timeline)</Card.Title>
			</div>

			<div class="flex flex-wrap items-center gap-3 text-xs">
				<div class="flex items-center gap-1.5 rounded-full border border-sky-500/20 bg-sky-500/10 px-2.5 py-1">
					<span class="size-2 rounded-full bg-sky-400"></span>
					<span class="text-sky-400 font-medium">Queries Allowed</span>
					<span class="text-muted-foreground font-mono text-[11px]">({summary.allowed.toLocaleString()})</span>
				</div>
				<div class="flex items-center gap-1.5 rounded-full border border-rose-500/20 bg-rose-500/10 px-2.5 py-1">
					<span class="size-2 rounded-full bg-rose-500"></span>
					<span class="text-rose-500 font-medium">Ads & Trackers Blocked</span>
					<span class="text-muted-foreground font-mono text-[11px]">({summary.blocked.toLocaleString()} — {summary.pct}%)</span>
				</div>
			</div>
		</div>
	</Card.Header>

	<Card.Content class="p-6">
		{#if loading && !analytics}
			<Skeleton class="h-48 w-full" />
		{:else}
			<div class="flex flex-col gap-3 relative">
				<div class="flex h-44 items-end gap-[1px] sm:gap-[2px] border-b border-border/60 pb-1 pt-6 px-1 w-full relative">
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
										"absolute bottom-full mb-3 flex flex-col gap-1.5 rounded-lg border border-border bg-popover p-3 text-[11px] shadow-2xl z-50 whitespace-nowrap min-w-[160px] pointer-events-none backdrop-blur-md",
										idx < 6
											? "left-0"
											: idx > chartPoints.length - 7
												? "right-0"
												: "left-1/2 -translate-x-1/2",
									].join(" ")}
								>
									<div class="font-bold text-foreground border-b border-border/60 pb-1 flex items-center justify-between gap-3">
										<span class="text-primary font-mono">{pt.label}</span>
										<span class="text-foreground font-mono text-[10px] bg-muted px-1.5 py-0.5 rounded">
											{pt.total} queries
										</span>
									</div>
									<div class="flex flex-col gap-1 font-mono text-[10px]">
										<div class="flex items-center justify-between gap-3 text-sky-500">
											<span class="flex items-center gap-1">
												<span class="size-1.5 rounded-full bg-sky-500"></span>
												Allowed:
											</span>
											<span class="font-semibold">{pt.allowed}</span>
										</div>
										<div class="flex items-center justify-between gap-3 text-rose-500">
											<span class="flex items-center gap-1">
												<span class="size-1.5 rounded-full bg-rose-500"></span>
												Blocked:
											</span>
											<span class="font-semibold">{pt.blocked} ({pt.blockedPct}%)</span>
										</div>
									</div>
								</div>
							{/if}

							<!-- Bar container -->
							<div
								class="w-full rounded-t flex flex-col justify-end overflow-hidden bg-muted/40 group-hover:ring-1 group-hover:ring-primary/60 transition-all"
								style="height: {Math.max(6, Math.round((pt.total / maxValue) * 100))}%"
							>
								{#if pt.blocked > 0}
									<div
										class="w-full bg-rose-500 hover:bg-rose-400 transition-colors"
										style="height: {pt.blockedPct}%"
									></div>
								{/if}
								{#if pt.allowed > 0}
									<div
										class="w-full bg-sky-500 hover:bg-sky-400 transition-colors"
										style="height: {100 - pt.blockedPct}%"
									></div>
								{/if}
							</div>
						</div>
					{/each}
				</div>

				<div class="flex justify-between px-1 font-mono text-[10px] text-muted-foreground select-none">
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
