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
	}: {
		dns: DeviceDnsResponse | null;
		loading?: boolean;
		/** What adblock does to this device, e.g. "kids", "global lists only", "bypassed". */
		adblock: string | null;
		onEditAdblock?: () => void;
	} = $props();

	const W = 600;
	const H = 110;
	const PAD = 4;

	const chart = $derived.by(() => {
		const rate = dns?.rate ?? [];
		if (rate.length < 2) return null;
		const max = Math.max(1, ...rate.map((b) => b.total));
		const x = (i: number) => (i / (rate.length - 1)) * W;
		const y = (v: number) => H - PAD - (v / max) * (H - PAD * 2);
		const line = (key: "total" | "blocked") =>
			rate.map((b, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(b[key]).toFixed(1)}`).join(" ");
		const total = line("total");
		return { total, area: `${total} L${W},${H} L0,${H} Z`, blocked: line("blocked"), max };
	});

	const topMax = $derived(Math.max(1, ...(dns?.top_domains ?? []).map((d) => d.count)));
	const blockedMax = $derived(Math.max(1, ...(dns?.top_blocked_domains ?? []).map((d) => d.count)));
</script>

{#snippet domainList(rows: { domain: string; count: number }[], max: number, tone: "brand" | "danger")}
	<ul class="flex flex-col gap-2">
		{#each rows as row (row.domain)}
			<li class="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1">
				<span class="truncate font-mono text-xs" title={row.domain}>{row.domain}</span>
				<span class="text-xs tabular-nums text-muted-foreground">{row.count.toLocaleString()}</span>
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
						<linearGradient id="dev-dns-line" x1="0" x2="1">
							<stop offset="0" stop-color="var(--brand-from)" />
							<stop offset="1" stop-color="var(--brand-to)" />
						</linearGradient>
						<linearGradient id="dev-dns-area" x1="0" x2="0" y1="0" y2="1">
							<stop offset="0" stop-color="var(--brand-to)" stop-opacity="0.25" />
							<stop offset="1" stop-color="var(--brand-from)" stop-opacity="0" />
						</linearGradient>
					</defs>
					<path d={chart.area} fill="url(#dev-dns-area)" />
					<path d={chart.total} fill="none" stroke="url(#dev-dns-line)" stroke-width="2" vector-effect="non-scaling-stroke" />
					<path d={chart.blocked} fill="none" stroke="var(--danger)" stroke-width="1.5" opacity="0.8" vector-effect="non-scaling-stroke" />
				</svg>
				<div class="mt-1 flex justify-between text-xs text-muted-foreground">
					<span>24 h ago</span>
					<span class="flex items-center gap-3">
						<span class="flex items-center gap-1"><span class="bg-brand-gradient inline-block h-0.5 w-3"></span>queries</span>
						<span class="flex items-center gap-1"><span class="inline-block h-0.5 w-3 bg-danger"></span>blocked</span>
					</span>
					<span>now</span>
				</div>
			</div>
		{/if}
		<div class="flex flex-col gap-3 p-3">
			{#if dns.top_domains.length}
				<div class="flex flex-col gap-2">
					<h3 class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Most asked</h3>
					{@render domainList(dns.top_domains.slice(0, 5), topMax, "brand")}
				</div>
			{/if}
			{#if dns.top_blocked_domains.length}
				<div class="flex flex-col gap-2">
					<h3 class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Blocked</h3>
					{@render domainList(dns.top_blocked_domains.slice(0, 5), blockedMax, "danger")}
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
