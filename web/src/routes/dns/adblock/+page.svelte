<script lang="ts">
	import { onMount } from "svelte";
	import { toast } from "svelte-sonner";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import {
		dnsAdblockStatus,
		dnsStats,
		dnsAnalytics,
		dnsAdblockUrls,
		dnsAdblockCheck,
	} from "$lib/api/client";
	import type {
		DnsAdblockStatusResponse,
		DnsStatsResponse,
		DnsAnalyticsResponse,
		DnsAdblockUrlEntry,
		AdblockCheckResponse,
	} from "$lib/api/types";

	import DnsAdblockStatsCards from "./components/DnsAdblockStatsCards.svelte";
	import DnsAdblockActivityChart from "./components/DnsAdblockActivityChart.svelte";
	import DnsAdblockTopBlocked from "./components/DnsAdblockTopBlocked.svelte";

	let loading = $state(true);
	let status = $state<DnsAdblockStatusResponse | null>(null);
	let stats = $state<DnsStatsResponse | null>(null);
	let analytics = $state<DnsAnalyticsResponse | null>(null);
	let sources = $state<DnsAdblockUrlEntry[]>([]);

	let checkDomainInput = $state("");
	let checking = $state(false);
	let checkResult = $state<AdblockCheckResponse | null>(null);

	async function loadAllData() {
		loading = true;
		try {
			const [statusRes, statsRes, analyticsRes, sourcesRes] =
				await Promise.allSettled([
					dnsAdblockStatus(),
					dnsStats(),
					dnsAnalytics(10),
					dnsAdblockUrls(),
				]);

			if (statusRes.status === "fulfilled" && statusRes.value) {
				status = statusRes.value;
			}
			if (statsRes.status === "fulfilled" && statsRes.value) {
				stats = statsRes.value;
			}
			if (analyticsRes.status === "fulfilled" && analyticsRes.value) {
				analytics = analyticsRes.value;
			}
			if (sourcesRes.status === "fulfilled" && sourcesRes.value) {
				sources = sourcesRes.value;
			}
		} catch {
			toast.error("Failed to load adblock telemetry");
		} finally {
			loading = false;
		}
	}

	async function handleCheckDomain(e?: Event) {
		if (e) e.preventDefault();
		const domain = checkDomainInput.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/\.$/, "");
		if (!domain) {
			toast.error("Please enter a domain to check");
			return;
		}

		checking = true;
		checkResult = null;
		try {
			const res = await dnsAdblockCheck(domain);
			checkResult = res;
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to check domain");
		} finally {
			checking = false;
		}
	}

	function setQuickCheck(domain: string) {
		checkDomainInput = domain;
		handleCheckDomain();
	}

	onMount(() => {
		loadAllData();
	});
</script>

<div class="space-y-6">
	<!-- Top Metric Summary Cards -->
	<DnsAdblockStatsCards
		{loading}
		{status}
		{stats}
		sourceCount={sources.length}
	/>

	<!-- 24h Activity Timeline Chart -->
	<DnsAdblockActivityChart {loading} {analytics} />

	<!-- Interactive Domain Filter Diagnostic -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<SearchIcon class="size-4 text-primary" />
					<Card.Title class="text-sm font-semibold">
						Filter Rule Diagnostic
					</Card.Title>
				</div>
				<Badge variant="outline" class="font-mono text-[11px]">
					Live Resolution Check
				</Badge>
			</div>
			<Card.Description class="text-xs">
				Test how any domain is evaluated by the filter engine and inspect matched rules, source attribution, and exception overrides.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-4 space-y-4">
			<form onsubmit={handleCheckDomain} class="flex flex-col sm:flex-row gap-2">
				<div class="relative flex-1">
					<SearchIcon class="absolute left-3 top-2.5 size-4 text-muted-foreground" />
					<Input
						type="text"
						placeholder="e.g. doubleclick.net, analytics.google.com, github.com"
						bind:value={checkDomainInput}
						class="pl-9 h-9 font-mono text-xs"
					/>
				</div>
				<Button type="submit" size="sm" class="h-9 px-4 gap-1.5" disabled={checking}>
					{#if checking}
						<span class="animate-spin text-xs">⟳</span>
						Checking...
					{:else}
						<SearchIcon class="size-3.5" />
						Check Domain
					{/if}
				</Button>
			</form>

			<div class="flex items-center gap-1.5 text-xs text-muted-foreground flex-wrap">
				<span>Quick test:</span>
				<button
					type="button"
					onclick={() => setQuickCheck("doubleclick.net")}
					class="underline hover:text-foreground font-mono"
				>
					doubleclick.net
				</button>
				<span>•</span>
				<button
					type="button"
					onclick={() => setQuickCheck("google-analytics.com")}
					class="underline hover:text-foreground font-mono"
				>
					google-analytics.com
				</button>
				<span>•</span>
				<button
					type="button"
					onclick={() => setQuickCheck("github.com")}
					class="underline hover:text-foreground font-mono"
				>
					github.com
				</button>
			</div>

			<!-- Diagnostic Verdict Display -->
			{#if checkResult}
				<div class="rounded-lg border p-4 space-y-3 {checkResult.matched && checkResult.filter?.action === 'block' ? 'bg-rose-500/5 border-rose-500/20' : 'bg-emerald-500/5 border-emerald-500/20'}">
					<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
						<div class="flex items-center gap-2">
							{#if checkResult.matched && checkResult.filter?.action === 'block'}
								<ShieldAlertIcon class="size-5 text-rose-500" />
								<div>
									<div class="text-sm font-semibold text-rose-600 dark:text-rose-400">
										BLOCKED
									</div>
									<div class="text-xs text-muted-foreground">
										Domain matches an active blocking rule and will be sinkholed.
									</div>
								</div>
							{:else}
								<ShieldCheckIcon class="size-5 text-emerald-500" />
								<div>
									<div class="text-sm font-semibold text-emerald-600 dark:text-emerald-400">
										ALLOWED
									</div>
									<div class="text-xs text-muted-foreground">
										{#if checkResult.filter?.action === 'allow'}
											Domain is explicitly allowed by an exception rule.
										{:else}
											Domain does not match any blocking rules.
										{/if}
									</div>
								</div>
							{/if}
						</div>

						<Badge variant="outline" class="font-mono text-xs self-start sm:self-auto">
							{checkResult.domain}
						</Badge>
					</div>

					{#if checkResult.filter}
						<div class="pt-3 border-t border-border/40 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
							<div>
								<span class="text-muted-foreground block text-[11px] font-medium uppercase tracking-wider">
									Matched Rule
								</span>
								<div class="flex items-center gap-2 mt-1">
									<code class="font-mono font-medium text-foreground bg-muted/60 px-1.5 py-0.5 rounded text-xs">
										{checkResult.filter.rule ?? checkResult.domain}
									</code>
									{#if checkResult.filter.important}
										<Badge variant="secondary" class="font-mono text-[10px] bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20">
											$important
										</Badge>
									{/if}
								</div>
							</div>

							<div>
								<span class="text-muted-foreground block text-[11px] font-medium uppercase tracking-wider">
									Origin
								</span>
								<div class="mt-1 font-mono text-xs text-foreground">
									{#if checkResult.filter.origin.type === 'user_rule'}
										Custom User Rule
									{:else if checkResult.filter.origin.type === 'user_allowlist'}
										Manual Allowlist
									{:else if checkResult.filter.origin.type === 'list'}
										Remote Source List #{checkResult.filter.origin.source_id}
									{/if}
								</div>
							</div>
						</div>
					{/if}

					{#if checkResult.source_matches && checkResult.source_matches.length > 0}
						<div class="pt-3 border-t border-border/40 space-y-2">
							<span class="text-muted-foreground block text-[11px] font-medium uppercase tracking-wider">
								Matching Source Lists ({checkResult.source_matches.length})
							</span>
							<div class="space-y-1.5">
								{#each checkResult.source_matches as sm}
									<div class="flex items-center justify-between gap-2 p-2 rounded bg-background/60 border border-border/50 text-xs">
										<div class="flex items-center gap-2 min-w-0">
											<Badge
												variant="outline"
												class="text-[10px] font-mono shrink-0 {sm.action === 'block' ? 'bg-rose-500/10 text-rose-600 border-rose-500/20' : 'bg-emerald-500/10 text-emerald-600 border-emerald-500/20'}"
											>
												{sm.action.toUpperCase()}
											</Badge>
											<span class="font-mono truncate text-muted-foreground" title={sm.url}>
												{sm.url}
											</span>
										</div>
										{#if sm.rule}
											<code class="font-mono text-[11px] shrink-0 text-foreground bg-muted/40 px-1 py-0.5 rounded">
												{sm.rule}
											</code>
										{/if}
									</div>
								{/each}
							</div>
						</div>
					{/if}
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Rankings: Top Blocked Domains & Top Clients -->
	<DnsAdblockTopBlocked
		{loading}
		topBlockedDomains={analytics?.top_blocked_domains ?? []}
		topBlockedClients={analytics?.top_blocked_clients ?? []}
		onAllowedDomain={() => loadAllData()}
	/>

	<!-- Engine Architecture & Hardware Efficiency Card -->
	<Card.Root class="border-border/60 bg-muted/20">
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<CpuIcon class="size-4 text-primary" />
					<Card.Title class="text-sm font-semibold">
						Zero-Copy Reversed-FST Filtering Architecture
					</Card.Title>
				</div>
				<Badge variant="outline" class="font-mono text-[11px] gap-1">
					<ZapIcon class="size-3 text-amber-500" />
					~0.2µs Query Evaluation
				</Badge>
			</div>
		</Card.Header>
		<Card.Content class="p-4 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
			<div class="flex flex-col gap-1.5 p-3 rounded-lg border bg-card">
				<div class="flex items-center gap-1.5 font-semibold text-foreground">
					<span class="size-2 rounded-full bg-emerald-500"></span>
					Tier 1: In-Memory Overrides & Exceptions
				</div>
				<p class="text-muted-foreground">
					User custom rules and adblock <code class="text-primary font-mono">@@</code> exceptions evaluated in-memory with priority override and <code class="text-amber-500 font-mono">$important</code> handling.
				</p>
			</div>

			<div class="flex flex-col gap-1.5 p-3 rounded-lg border bg-card">
				<div class="flex items-center gap-1.5 font-semibold text-foreground">
					<span class="size-2 rounded-full bg-sky-500"></span>
					Tier 2: Zero-Copy Mmap Reversed FST
				</div>
				<p class="text-muted-foreground">
					Finite State Transducer compiled on disk (<code class="text-primary font-mono">blocklist.fst</code>). Traverses reversed labels (<code class="text-foreground font-mono">com.doubleclick</code>) for deterministic suffix & exact matching in ~0.2µs with zero heap bloat.
				</p>
			</div>

			<div class="flex flex-col gap-1.5 p-3 rounded-lg border bg-card">
				<div class="flex items-center gap-1.5 font-semibold text-foreground">
					<span class="size-2 rounded-full bg-purple-500"></span>
					Tier 3: Incremental HTTP Manifest Cache
				</div>
				<p class="text-muted-foreground">
					Per-source ETag & Last-Modified conditional downloads. Merges sorted lists via streaming multi-way k-merge, skipping unchanged sources entirely.
				</p>
			</div>
		</Card.Content>
	</Card.Root>
</div>
