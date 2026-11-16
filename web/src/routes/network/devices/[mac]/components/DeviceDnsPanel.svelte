<script lang="ts">
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import type { DeviceDnsResponse } from "$lib/api/types";
	import DnsHourlyBars from "$lib/components/dns/DnsHourlyBars.svelte";

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

	const topMax = $derived(Math.max(1, ...(dns?.top_domains ?? []).map((d) => d.count)));
	const blockedMax = $derived(Math.max(1, ...(dns?.top_blocked_domains ?? []).map((d) => d.count)));
</script>

{#snippet domainList(rows: { domain: string; count: number }[], max: number, tone: "brand" | "danger", ruleAction: "block" | "allow")}
	<ul class="flex flex-col gap-2">
		{#each rows as row (row.domain)}
			<li class="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1">
				<a href={`/dns/domains/${encodeURIComponent(row.domain)}`} class="truncate font-mono text-xs hover:underline" title={row.domain}>{row.domain}</a>
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
		<DnsHourlyBars rate={dns.rate ?? []} />
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
