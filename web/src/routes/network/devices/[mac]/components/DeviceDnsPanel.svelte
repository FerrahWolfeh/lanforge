<script lang="ts">
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import type { DeviceDnsResponse } from "$lib/api/types";

	/** The device's DNS over the last day: hourly chart, top answered and blocked domains, adblock. */
	let {
		dns,
		loading = false,
		adblock,
		onEditAdblock,
		onRule,
	}: {
		dns: DeviceDnsResponse | null;
		loading?: boolean;
		/** What adblock does to this device, e.g. "kids", "global lists only", "bypassed". */
		adblock: string | null;
		onEditAdblock?: () => void;
		/** Absent when the session may not change adblock rules. */
		onRule?: (domain: string, action: "block" | "allow") => void;
	} = $props();

	const W = 600;
	const H = 110;
	const PAD = 4;

	const BAR_RADIUS = 1.5;
	const hourFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", hourCycle: "h23" });

	/** One bar per hourly bucket, bottom-aligned. Blocked queries are drawn over the total from the bottom. */
	const chart = $derived.by(() => {
		const rate = dns?.rate ?? [];
		if (!rate.length) return null;
		const max = Math.max(1, ...rate.map((b) => b.total));
		const slot = W / rate.length;
		const barW = slot * 0.75;
		const inset = (slot - barW) / 2;
		const scale = (v: number) => (v / max) * (H - PAD);
		const bars = rate.map((b, i) => {
			const x = i * slot + inset;
			const h = scale(b.total);
			const top = H - h;
			const r = Math.min(BAR_RADIUS, h, barW / 2);
			// Rounded top corners only: the bar sits on the baseline.
			const path =
				h > 0
					? `M${x.toFixed(1)},${H} V${(top + r).toFixed(1)} Q${x.toFixed(1)},${top.toFixed(1)} ${(x + r).toFixed(1)},${top.toFixed(1)} H${(x + barW - r).toFixed(1)} Q${(x + barW).toFixed(1)},${top.toFixed(1)} ${(x + barW).toFixed(1)},${(top + r).toFixed(1)} V${H} Z`
					: "";
			const time = hourFormat.format(new Date(b.timestamp * 1000));
			return {
				key: b.timestamp,
				x,
				w: barW,
				path,
				blockedY: H - scale(b.blocked),
				blockedH: scale(b.blocked),
				blocked: b.blocked,
				total: b.total,
				label: `${time} · ${b.total} ${b.total === 1 ? "query" : "queries"}, ${b.blocked} blocked`,
			};
		});
		return { bars, max };
	});

	const topMax = $derived(Math.max(1, ...(dns?.top_domains ?? []).map((d) => d.count)));
	const blockedMax = $derived(Math.max(1, ...(dns?.top_blocked_domains ?? []).map((d) => d.count)));
</script>

{#snippet domainList(rows: { domain: string; count: number }[], max: number, tone: "brand" | "danger", ruleAction: "block" | "allow")}
	<ul class="flex flex-col gap-2">
		{#each rows as row (row.domain)}
			<li class="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1">
				<span class="truncate font-mono text-xs" title={row.domain}>{row.domain}</span>
				<span class="flex items-center gap-1.5 text-xs tabular-nums text-muted-foreground">
					{row.count.toLocaleString()}
					{#if onRule}
						<Button
							variant="ghost"
							size="xs"
							title="Adds a rule for every device"
							onclick={() => onRule(row.domain, ruleAction)}
						>{ruleAction === "block" ? "Block" : "Allow"}</Button>
					{/if}
				</span>
				<span class="col-span-2 block h-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
					<span
						class="block h-full rounded-full {tone === 'danger' ? 'bg-danger' : 'bg-brand-gradient'}"
						style={`width: ${Math.max(2, (row.count / max) * 100)}%`}
					></span>
				</span>
			</li>
		{/each}
	</ul>
{/snippet}

<section class="rounded-lg border border-border bg-card">
	<header class="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2.5">
		<h2 class="flex items-center gap-2 text-sm font-semibold">
			<GlobeIcon class="size-4 text-muted-foreground" />DNS, last 24 hours
		</h2>
		<span class="text-xs text-muted-foreground">all addresses of this device</span>
	</header>

	{#if loading && !dns}
		<div class="flex flex-col gap-2 p-3">
			<Skeleton class="h-24 w-full" />
			<Skeleton class="h-4 w-2/3" />
			<Skeleton class="h-4 w-1/2" />
		</div>
	{:else if !dns}
		<p class="p-3 text-sm text-muted-foreground">DNS activity is not available right now.</p>
	{:else if dns.logging_off}
		<p class="p-3 text-sm text-muted-foreground">
			This device's queries are not logged, so there is nothing to count.
		</p>
	{:else if dns.total === 0}
		<p class="p-3 text-sm text-muted-foreground">No DNS queries from this device in the last 24 hours.</p>
	{:else}
		{#if chart}
			<div class="px-3 pt-3">
				<svg
					viewBox="0 0 {W} {H}"
					class="block h-auto w-full"
					role="img"
					aria-label="Queries per hour over the last 24 hours, busiest hour {chart.max}"
					preserveAspectRatio="none"
				>
					<defs>
						<linearGradient id="dev-dns-bar" gradientUnits="userSpaceOnUse" x1="0" x2={W} y1="0" y2="0">
							<stop offset="0" stop-color="var(--brand-from)" />
							<stop offset="1" stop-color="var(--brand-to)" />
						</linearGradient>
					</defs>
					{#each chart.bars as bar (bar.key)}
						<g>
							<title>{bar.label}</title>
							{#if bar.path}<path d={bar.path} fill="url(#dev-dns-bar)" />{/if}
							{#if bar.blocked > 0}
								<rect x={bar.x} y={bar.blockedY} width={bar.w} height={bar.blockedH} fill="var(--danger)" />
							{/if}
						</g>
					{/each}
				</svg>
				<div class="mt-1 flex justify-between text-xs text-muted-foreground">
					<span>24 h ago</span>
					<span class="flex items-center gap-3">
						<span class="flex items-center gap-1"><span class="bg-brand-gradient inline-block size-2.5 rounded-[2px]"></span>queries</span>
						<span class="flex items-center gap-1"><span class="inline-block size-2.5 rounded-[2px] bg-danger"></span>blocked</span>
					</span>
					<span>now</span>
				</div>
			</div>
		{/if}
		<div class="flex flex-col gap-3 p-3">
			{#if dns.top_domains.length}
				<div class="flex flex-col gap-2">
					<h3 class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Most asked</h3>
					{@render domainList(dns.top_domains.slice(0, 5), topMax, "brand", "block")}
				</div>
			{/if}
			{#if dns.top_blocked_domains.length}
				<div class="flex flex-col gap-2">
					<h3 class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Blocked</h3>
					{@render domainList(dns.top_blocked_domains.slice(0, 5), blockedMax, "danger", "allow")}
				</div>
			{/if}
		</div>
	{/if}

	<footer class="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-xs text-muted-foreground">
		<span>Adblock: <span class="font-medium text-foreground">{adblock ?? "…"}</span></span>
		{#if onEditAdblock}
			<Button variant="ghost" size="xs" onclick={onEditAdblock}><PencilIcon />Edit</Button>
		{/if}
	</footer>
</section>
