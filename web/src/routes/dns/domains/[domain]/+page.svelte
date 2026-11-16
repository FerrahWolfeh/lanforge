<script lang="ts">
	import { originText } from "$lib/components/dns/dnsLog";
	import { page } from "$app/state";
	import { toast } from "svelte-sonner";
	import { auth } from "$lib/stores/auth.svelte";
	import { dnsDomain, dnsAdblockCheck, dnsBlock, dnsAllow } from "$lib/api/client";
	import type { AdblockCheckResponse, DnsDomainResponse } from "$lib/api/types";
	import { formatTimeAgo } from "$lib/utils/format";
	import { createSequence } from "$lib/utils";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import StatusLine from "$lib/components/StatusLine.svelte";
	import StatStrip, { type StatStripItem } from "$lib/components/StatStrip.svelte";
	import DnsHourlyBars from "$lib/components/dns/DnsHourlyBars.svelte";

	import ChevronRightIcon from "@lucide/svelte/icons/chevron-right";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ShieldBanIcon from "@lucide/svelte/icons/shield-ban";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import UsersIcon from "@lucide/svelte/icons/users";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ActivityIcon from "@lucide/svelte/icons/activity";

	const domain = $derived((page.params.domain ?? "").trim().toLowerCase().replace(/\.$/, ""));

	let stats = $state<DnsDomainResponse | null>(null);
	let notFound = $state(false);
	let failed = $state<string | null>(null);
	let loading = $state(true);
	let verdict = $state<AdblockCheckResponse | null>(null);
	let verdictFailed = $state(false);

	const statsSeq = createSequence();
	const verdictSeq = createSequence();

	async function loadStats() {
		const seq = statsSeq.next();
		loading = true;
		failed = null;
		notFound = false;
		try {
			const res = await dnsDomain(domain);
			if (!statsSeq.isCurrent(seq)) return;
			stats = res;
		} catch (err: any) {
			if (!statsSeq.isCurrent(seq)) return;
			stats = null;
			if (err?.status === 404) notFound = true;
			else failed = err?.message ?? "Failed to load the domain";
		}
		loading = false;
	}

	async function loadVerdict() {
		const seq = verdictSeq.next();
		try {
			const res = await dnsAdblockCheck(domain);
			if (!verdictSeq.isCurrent(seq)) return;
			verdict = res;
			verdictFailed = false;
		} catch {
			if (!verdictSeq.isCurrent(seq)) return;
			verdict = null;
			verdictFailed = true;
		}
	}

	$effect(() => {
		if (!domain) return;
		stats = null;
		verdict = null;
		verdictFailed = false;
		loadStats();
		loadVerdict();
	});

	const canRules = $derived(auth.can("dns_write"));

	async function rule(action: "block" | "allow") {
		try {
			if (action === "block") {
				await dnsBlock(domain);
				toast.success(`${domain} blocked for every device`);
			} else {
				await dnsAllow(domain);
				toast.success(`${domain} allowed for every device`);
			}
			await loadVerdict();
		} catch (err: any) {
			toast.error(err?.message ?? `Failed to ${action} ${domain}`);
		}
	}

	const strip = $derived.by((): StatStripItem[] => {
		const s = stats;
		return [
			{ label: "queries, 24 h", value: s ? s.total : null, icon: GlobeIcon },
			{
				label: "blocked, 24 h",
				value: s ? s.blocked : null,
				icon: ShieldBanIcon,
				...(s && s.total > 0 ? { bar: s.blocked / s.total, barTone: "danger" as const } : {}),
			},
			{ label: "devices", value: s ? s.clients.length : null, icon: UsersIcon },
			{ label: "last asked", value: s ? (s.last_seen ? formatTimeAgo(s.last_seen) : "—") : null, icon: ClockIcon },
		];
	});

	const verdictView = $derived.by(() => {
		const v = verdict;
		if (!v) return null;
		const f = v.filter;
		if (!v.matched || !f) {
			return { tone: "none" as const, title: "Not filtered", text: "No list or rule matches this domain, so it resolves normally." };
		}
		const how = originText(f.origin, v.source_matches);
		const rule = f.rule ? ` Matching rule: ${f.rule}` : "";
		if (f.action === "allow") {
			return { tone: "allow" as const, title: "Allowed", text: `Allowed by ${how}, which overrides any block.${rule}` };
		}
		return { tone: "block" as const, title: "Blocked", text: `Blocked by ${how}.${rule}` };
	});
</script>

<svelte:head>
	<title>{domain} — DNS — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-4">
	<nav class="flex min-w-0 items-center gap-1.5 text-sm text-muted-foreground" aria-label="Breadcrumb">
		<a href="/dns/resolver" class="hover:text-foreground">DNS</a>
		<ChevronRightIcon class="size-3.5 shrink-0" />
		<span class="truncate font-mono text-foreground">{domain}</span>
	</nav>

	{#if notFound}
		<StatusLine tone="warning" title="Domain not found:" text=" {domain} has no DNS activity on record." href="/dns/resolver" linkLabel="DNS overview" />
	{:else if failed}
		<StatusLine tone="danger" title="Could not load {domain}:" text=" {failed}" />
	{:else}
		<!-- Header -->
		<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div class="flex min-w-0 items-center gap-3">
				<span class="flex size-11 shrink-0 items-center justify-center rounded-lg border border-border bg-muted">
					<GlobeIcon class="size-5" />
				</span>
				<div class="flex min-w-0 flex-col">
					<h1 class="break-all font-mono text-xl font-semibold tracking-tight">{domain}</h1>
					<span class="text-xs text-muted-foreground">DNS activity over the last 24 hours</span>
				</div>
			</div>
			<div class="flex flex-wrap items-center gap-2">
				{#if canRules}
					<Button variant="outline" size="sm" onclick={() => rule("block")} class="text-danger">
						<ShieldAlertIcon />Block
					</Button>
					<Button variant="outline" size="sm" onclick={() => rule("allow")}>
						<ShieldCheckIcon />Allow
					</Button>
				{/if}
				<Button size="sm" href={`/dns/log?domain=${encodeURIComponent(domain)}`}>All queries →</Button>
			</div>
		</div>

		{#if verdictFailed}
			<StatusLine tone="warning" title="Adblock check failed:" text=" could not tell whether this domain is filtered." />
		{/if}

		<StatStrip items={strip} />

		<div class="grid gap-4 lg:grid-cols-2 lg:items-start">
			<div class="flex min-w-0 flex-col gap-4">
				<!-- Adblock verdict -->
				<section class="rounded-lg border border-border bg-card">
					<header class="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
						<h2 class="flex items-center gap-2 text-sm font-semibold">
							<ShieldBanIcon class="size-4 text-muted-foreground" />Adblock
						</h2>
					</header>
					{#if verdictView}
						<div class="flex flex-col gap-1 p-3 text-sm">
							<span class="font-medium {verdictView.tone === 'block' ? 'text-danger' : ''}">{verdictView.title}</span>
							<span class="break-words text-muted-foreground">{verdictView.text}</span>
						</div>
					{:else if verdictFailed}
						<p class="p-3 text-sm text-muted-foreground">The adblock verdict is not available right now.</p>
					{:else}
						<div class="flex flex-col gap-2 p-3">
							<Skeleton class="h-4 w-24" />
							<Skeleton class="h-4 w-2/3" />
						</div>
					{/if}
				</section>

				<!-- Hourly bars -->
				<section class="rounded-lg border border-border bg-card">
					<header class="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
						<h2 class="flex items-center gap-2 text-sm font-semibold">
							<ActivityIcon class="size-4 text-muted-foreground" />Queries per hour
						</h2>
					</header>
					{#if loading && !stats}
						<div class="p-3"><Skeleton class="h-24 w-full" /></div>
					{:else if stats && stats.total === 0}
						<p class="p-3 text-sm text-muted-foreground">No queries for this domain in the last 24 hours.</p>
					{:else if stats}
						<div class="pb-3">
							<DnsHourlyBars rate={stats.rate ?? []} ariaLabel="Queries for {domain} per hour over the last 24 hours" />
						</div>
					{/if}
				</section>
			</div>

			<!-- Who asked -->
			<section class="min-w-0 rounded-lg border border-border bg-card">
				<header class="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
					<h2 class="flex items-center gap-2 text-sm font-semibold">
						<UsersIcon class="size-4 text-muted-foreground" />Who asked
					</h2>
					{#if stats && stats.clients.length > 0}
						<span class="text-xs text-muted-foreground">busiest first</span>
					{/if}
				</header>
				{#if loading && !stats}
					<div class="flex flex-col gap-2 p-3">
						{#each { length: 4 } as _, i (i)}
							<Skeleton class="h-10 w-full" />
						{/each}
					</div>
				{:else if !stats || stats.total === 0 || stats.clients.length === 0}
					<p class="p-3 text-sm text-muted-foreground">No device asked for this domain in the last 24 hours.</p>
				{:else}
					<ul class="divide-y divide-border">
						{#each stats.clients as c, i (`${c.mac ?? ""}-${c.addresses[0] ?? i}`)}
							{@const first = c.addresses[0] ?? ""}
							{@const more = c.addresses.length - 1}
							{@const label = c.name || (c.mac ? "Unnamed device" : first || "Unknown client")}
							<li class="flex items-center gap-3 px-3 py-2 text-sm">
								<div class="flex min-w-0 flex-1 flex-col">
									{#if c.mac}
										<a
											href={`/network/devices/${encodeURIComponent(c.mac)}`}
											class="truncate font-medium hover:underline">{label}</a
										>
									{:else}
										<span class="truncate font-medium {c.name ? '' : 'font-mono text-xs'}">{label}</span>
									{/if}
									{#if (first && (c.name || c.mac)) || more > 0}
										<span class="truncate font-mono text-xs text-muted-foreground" title={c.addresses.join("\n")}>
											{c.name || c.mac ? first : ""}{more > 0 ? ` +${more}` : ""}
										</span>
									{/if}
								</div>
								<div class="flex shrink-0 flex-col items-end text-xs tabular-nums">
									<span>{c.total.toLocaleString()} {c.total === 1 ? "query" : "queries"}</span>
									<span class="text-muted-foreground">
										{#if c.blocked > 0}<span class="text-danger">{c.blocked.toLocaleString()} blocked</span> · {/if}{formatTimeAgo(c.last_seen).toLowerCase()}
									</span>
								</div>
							</li>
						{/each}
					</ul>
				{/if}
			</section>
		</div>
	{/if}
</div>
