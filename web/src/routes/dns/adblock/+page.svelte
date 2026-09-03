<script lang="ts">
	import { onMount } from "svelte";
	import { toast } from "svelte-sonner";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import {
		dnsAdblockStatus,
		dnsStats,
		dnsAnalytics,
		dnsAdblockUrls,
	} from "$lib/api/client";
	import type {
		DnsAdblockStatusResponse,
		DnsStatsResponse,
		DnsAnalyticsResponse,
		DnsAdblockUrlEntry,
	} from "$lib/api/types";

	import DnsAdblockStatsCards from "./components/DnsAdblockStatsCards.svelte";
	import DnsAdblockActivityChart from "./components/DnsAdblockActivityChart.svelte";
	import DnsAdblockTopBlocked from "./components/DnsAdblockTopBlocked.svelte";

	let loading = $state(true);
	let status = $state<DnsAdblockStatusResponse | null>(null);
	let stats = $state<DnsStatsResponse | null>(null);
	let analytics = $state<DnsAnalyticsResponse | null>(null);
	let sources = $state<DnsAdblockUrlEntry[]>([]);

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
						Embedded 3-Tier Filter Hierarchy
					</Card.Title>
				</div>
				<Badge variant="outline" class="font-mono text-[11px] gap-1">
					<ZapIcon class="size-3 text-amber-500" />
					Sub-Microsecond Latency
				</Badge>
			</div>
		</Card.Header>
		<Card.Content class="p-4 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
			<div class="flex flex-col gap-1.5 p-3 rounded-lg border bg-card">
				<div class="flex items-center gap-1.5 font-semibold text-foreground">
					<span class="size-2 rounded-full bg-emerald-500"></span>
					Tier 1: Hot LRU Cache
				</div>
				<p class="text-muted-foreground">
					Stores recent domain evaluation hits/misses in a lock-shielded 50k-slot LRU buffer for instant O(1) matching.
				</p>
			</div>

			<div class="flex flex-col gap-1.5 p-3 rounded-lg border bg-card">
				<div class="flex items-center gap-1.5 font-semibold text-foreground">
					<span class="size-2 rounded-full bg-sky-500"></span>
					Tier 2: Bloom Filter (0.5% FP)
				</div>
				<p class="text-muted-foreground">
					Probabilistic bit-vector check for immediate negative short-circuiting without touching disk or memory-mapped files.
				</p>
			</div>

			<div class="flex flex-col gap-1.5 p-3 rounded-lg border bg-card">
				<div class="flex items-center gap-1.5 font-semibold text-foreground">
					<span class="size-2 rounded-full bg-purple-500"></span>
					Tier 3: Mmap FST Dictionary
				</div>
				<p class="text-muted-foreground">
					Finite State Transducer compiled on disk (<code class="text-primary font-mono">blocklist.fst</code>). Paged by OS kernel cache with zero heap bloat.
				</p>
			</div>
		</Card.Content>
	</Card.Root>
</div>
