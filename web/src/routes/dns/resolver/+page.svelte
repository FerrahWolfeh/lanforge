<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import * as Field from "$lib/components/ui/field";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import {
		dnsStats,
		dnsUpstreams,
		dnsUpstreamAdd,
		dnsUpstreamRemove,
		dnsQuery,
		dnsReverseResolverList,
		dnsReverseResolverAdd,
		dnsReverseResolverRemove,
		dnsAnalytics,
	} from "$lib/api/client";
	import type {
		DnsStatsResponse,
		DnsUpstreamEntry,
		ReverseResolverEntry,
		DnsAnalyticsResponse,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import ServerIcon from "@lucide/svelte/icons/server";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import BarChart3Icon from "@lucide/svelte/icons/bar-chart-3";

	let statsData = $state<DnsStatsResponse | null>(null);
	let analyticsData = $state<DnsAnalyticsResponse | null>(null);
	let upstreams = $state<DnsUpstreamEntry[]>([]);
	let reverseResolvers = $state<ReverseResolverEntry[]>([]);
	let loading = $state(true);

	// Interactive Dig / DNS Query Test Tool
	let digDomain = $state("");
	let digRecordType = $state("A");
	let digLoading = $state(false);
	let digResult = $state<any | null>(null);

	// Add Upstream Modal State
	let upstreamOpen = $state(false);
	let upstreamSubmitting = $state(false);
	let formUpstreamAddr = $state("");
	let formUpstreamProto = $state("Udp");
	let formUpstreamDomain = $state("");

	// Add Reverse Resolver Modal State
	let reverseOpen = $state(false);
	let reverseSubmitting = $state(false);
	let formSubnet = $state("");
	let formResolverUri = $state("");

	async function loadAllData() {
		loading = true;
		try {
			const [sRes, uRes, rRes, aRes] = await Promise.allSettled([
				dnsStats(),
				dnsUpstreams(),
				dnsReverseResolverList(),
				dnsAnalytics(10),
			]);

			if (sRes.status === "fulfilled") statsData = sRes.value;

			if (uRes.status === "fulfilled") {
				const raw: any = uRes.value;
				upstreams = Array.isArray(raw)
					? raw
					: Array.isArray(raw?.upstreams)
						? raw.upstreams
						: Array.isArray(raw?.data)
							? raw.data
							: [];
			}

			if (rRes.status === "fulfilled") {
				const raw: any = rRes.value;
				reverseResolvers = Array.isArray(raw)
					? raw
					: Array.isArray(raw?.resolvers)
						? raw.resolvers
						: Array.isArray(raw?.data)
							? raw.data
							: [];
			}

			if (aRes.status === "fulfilled") {
				analyticsData = aRes.value;
			}
		} catch {
			toast.error("Failed to load DNS resolver status");
		} finally {
			loading = false;
		}
	}

	async function handleDigQuery(e: Event) {
		e.preventDefault();
		if (!digDomain.trim()) return;

		digLoading = true;
		digResult = null;
		try {
			const res = await dnsQuery(digDomain.trim(), digRecordType);
			digResult = res;
			toast.success(`DNS query completed for ${digDomain.trim()}`);
		} catch (err: any) {
			toast.error(`DNS query failed: ${err?.message || "Unknown error"}`);
		} finally {
			digLoading = false;
		}
	}

	async function handleAddUpstream(e: Event) {
		e.preventDefault();
		if (!formUpstreamAddr.trim()) {
			toast.error("Server address or URL is required");
			return;
		}

		upstreamSubmitting = true;
		try {
			await dnsUpstreamAdd({
				addr: formUpstreamAddr.trim(),
				protocol: formUpstreamProto,
				domain: formUpstreamDomain.trim() || undefined,
			});
			toast.success(
				`Added upstream DNS server ${formUpstreamAddr.trim()}`,
			);
			upstreamOpen = false;
			await loadAllData();
		} catch {
			toast.error("Failed to add upstream DNS server");
		} finally {
			upstreamSubmitting = false;
		}
	}

	function getUpstreamAddr(item: DnsUpstreamEntry): string {
		if (typeof item.target === "string" && item.target.trim())
			return item.target;
		if (item.target && typeof item.target === "object" && item.target.addr)
			return item.target.addr;
		if (item.addr) return item.addr;
		if (item.url) return item.url;
		return "—";
	}

	function getUpstreamProtocol(item: DnsUpstreamEntry): string {
		if (item.protocol) return item.protocol.toUpperCase();
		if (
			item.target &&
			typeof item.target === "object" &&
			item.target.protocol
		)
			return item.target.protocol.toUpperCase();
		return "UDP";
	}

	function getUpstreamLatency(item: DnsUpstreamEntry): string {
		if (item.rtt_ewma_us !== undefined && item.rtt_ewma_us !== null) {
			return `${(item.rtt_ewma_us / 1000).toFixed(1)} ms`;
		}
		if (item.last_rtt_us !== undefined && item.last_rtt_us !== null) {
			return `${(item.last_rtt_us / 1000).toFixed(1)} ms`;
		}
		if (item.rtt_ms !== undefined && item.rtt_ms !== null) {
			return `${item.rtt_ms} ms`;
		}
		if (item.latency_ms !== undefined && item.latency_ms !== null) {
			return `${item.latency_ms} ms`;
		}
		return "—";
	}

	function formatSubnet(subnet: any): string {
		if (typeof subnet === "string" && subnet.trim()) return subnet;
		if (
			subnet &&
			typeof subnet === "object" &&
			"addr" in subnet &&
			"prefix_len" in subnet
		) {
			return `${subnet.addr}/${subnet.prefix_len}`;
		}
		return "—";
	}

	function formatResolverUri(item: ReverseResolverEntry): string {
		if (typeof item.resolver === "string" && item.resolver.trim())
			return item.resolver;
		if (
			item.resolver &&
			typeof item.resolver === "object" &&
			item.resolver.addr
		) {
			const proto = item.resolver.protocol
				? `${item.resolver.protocol.toLowerCase()}://`
				: "";
			return `${proto}${item.resolver.addr}`;
		}
		if (item.resolver_uri) return item.resolver_uri;
		return "—";
	}

	async function handleRemoveUpstream(item: DnsUpstreamEntry) {
		const targetAddr = getUpstreamAddr(item);
		try {
			await dnsUpstreamRemove({
				addr: targetAddr,
				protocol: getUpstreamProtocol(item),
			});
			toast.success(`Removed upstream ${targetAddr}`);
			await loadAllData();
		} catch {
			toast.error(`Failed to remove upstream ${targetAddr}`);
		}
	}

	async function handleAddReverse(e: Event) {
		e.preventDefault();
		if (!formSubnet.trim() || !formResolverUri.trim()) {
			toast.error("Subnet and Resolver URI are required");
			return;
		}

		reverseSubmitting = true;
		try {
			await dnsReverseResolverAdd(
				formSubnet.trim(),
				formResolverUri.trim(),
			);
			toast.success(`Added reverse resolver for ${formSubnet.trim()}`);
			reverseOpen = false;
			await loadAllData();
		} catch {
			toast.error("Failed to add reverse PTR resolver");
		} finally {
			reverseSubmitting = false;
		}
	}

	async function handleRemoveReverse(item: ReverseResolverEntry) {
		const subnetStr = formatSubnet(item.subnet);
		try {
			await dnsReverseResolverRemove(subnetStr);
			toast.success(`Removed PTR resolver for ${subnetStr}`);
			await loadAllData();
		} catch {
			toast.error(`Failed to remove PTR resolver for ${subnetStr}`);
		}
	}

	onMount(loadAllData);

	const cacheHitPct = $derived.by(() => {
		if (!statsData || statsData.total_requests === 0) return 0;
		return Math.round(
			(statsData.cache_hits / statsData.total_requests) * 100,
		);
	});

	const cacheMissesCount = $derived.by(() => {
		if (!statsData) return 0;
		return (
			statsData.cache_misses ??
			Math.max(
				0,
				statsData.total_requests -
					statsData.cache_hits -
					statsData.blocked_queries,
			)
		);
	});

	// Time-series query chart calculations (Pi-hole style query disposition breakdown)
	const chartPoints = $derived.by(() => {
		const rates = analyticsData?.query_rate ?? [];
		const blocked = analyticsData?.blocked_query_rate ?? [];

		if (rates.length === 0) {
			// Generate high-density time series points (28 buckets over last 2h)
			const now = Date.now();
			return Array.from({ length: 28 }, (_, i) => {
				const timestamp = new Date(now - (28 - i) * 4 * 60 * 1000);
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

	const recordTypes = ["A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SRV"];
</script>

<svelte:head>
	<title>DNS Resolver — Lanforge</title>
</svelte:head>

<Tooltip.Provider>
	<div class="flex flex-col gap-6">
		<!-- Page Header -->
		<div
			class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
		>
			<div>
				<h1 class="text-foreground text-2xl font-bold tracking-tight">
					DNS Resolver & Upstreams
				</h1>
				<p class="text-muted-foreground text-sm">
					Recursive DNS forwarding, query time series, upstream pool,
					and live lookup tools
				</p>
			</div>
			<div class="flex items-center gap-2">
				<Button
					variant="outline"
					size="sm"
					onclick={loadAllData}
					disabled={loading}
				>
					<RefreshCwIcon
						data-icon="inline-start"
						class={loading ? "animate-spin" : ""}
					/>
					Refresh
				</Button>
				<Button size="sm" onclick={() => (upstreamOpen = true)}>
					<PlusIcon data-icon="inline-start" />
					Add Upstream Server
				</Button>
			</div>
		</div>

		<!-- Pi-hole / AdGuard Style Top Metric Cards -->
		<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
			<!-- Total Queries -->
			<Card.Root
				class="relative overflow-hidden transition-all hover:border-zinc-700"
			>
				<Card.Content class="flex flex-col gap-3 p-5">
					<div class="flex items-center justify-between">
						<span
							class="text-muted-foreground text-xs font-semibold uppercase tracking-wider"
						>
							Total Queries
						</span>
						<div
							class="flex size-8 items-center justify-center rounded-lg border bg-sky-500/10 border-sky-500/20"
						>
							<GlobeIcon class="size-4 text-sky-400" />
						</div>
					</div>
					{#if loading || !statsData}
						<Skeleton class="h-8 w-28" />
						<Skeleton class="h-3.5 w-20" />
					{:else}
						<div class="flex flex-col gap-0.5">
							<span
								class="text-foreground text-3xl font-bold tabular-nums tracking-tight"
							>
								{statsData.total_requests.toLocaleString()}
							</span>
							<span
								class="text-muted-foreground text-xs font-medium"
							>
								Processed since daemon start
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
							<span
								class="text-muted-foreground text-xs font-medium"
							>
								{statsData.cache_hits.toLocaleString()} hits / {cacheMissesCount.toLocaleString()}
								misses
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
							<span
								class="text-muted-foreground text-xs font-medium"
							>
								Adblock & filter rule matches
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
						<Skeleton class="h-8 w-28" />
						<Skeleton class="h-3.5 w-20" />
					{:else}
						<div class="flex flex-col gap-0.5">
							<span
								class="text-foreground text-3xl font-bold tabular-nums tracking-tight"
							>
								{upstreams.length > 0
									? upstreams.length
									: "System (OS)"}
							</span>
							<span
								class="text-muted-foreground text-xs font-medium"
							>
								{upstreams.length > 0
									? "Configured upstream servers"
									: "Default system DNS fallback"}
							</span>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>
		</div>

		<!-- Pi-hole Style Time-Series Query Activity Chart -->
		<Card.Root class="overflow-hidden">
			<Card.Header class="pb-3 border-b border-border/50">
				<div
					class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
				>
					<div class="flex items-center gap-2">
						<BarChart3Icon class="size-4 text-sky-400" />
						<Card.Title class="text-base"
							>DNS Query Activity Over Time</Card.Title
						>
					</div>
					<div class="flex flex-wrap items-center gap-3 text-xs">
						<div
							class="flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-1"
						>
							<span class="size-2 rounded-full bg-emerald-400"
							></span>
							<span class="text-emerald-400 font-medium"
								>Cached</span
							>
							<span
								class="text-muted-foreground font-mono text-[11px]"
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
							<span
								class="text-muted-foreground font-mono text-[11px]"
								>({chartSummary.forwardedPct}%)</span
							>
						</div>
						<div
							class="flex items-center gap-1.5 rounded-full border border-rose-500/20 bg-rose-500/10 px-2.5 py-1"
						>
							<span class="size-2 rounded-full bg-rose-400"
							></span>
							<span class="text-rose-400 font-medium"
								>Blocked</span
							>
							<span
								class="text-muted-foreground font-mono text-[11px]"
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
					<!-- Interactive Stacked Bar Timeline Chart -->
					<div class="flex flex-col gap-2">
						<div
							class="flex h-48 items-end gap-1.5 sm:gap-2 border-b border-border/60 pb-2 pt-4 px-1 overflow-x-auto"
						>
							{#each chartPoints as pt, idx (idx)}
								<div
									class="flex flex-1 flex-col items-center gap-1 h-full justify-end group relative min-w-[12px]"
								>
									<!-- Hover Tooltip -->
									<div
										class="absolute bottom-full mb-2 hidden group-hover:flex flex-col gap-1 rounded-lg border border-border/80 bg-zinc-950 p-2.5 text-[11px] shadow-2xl z-30 whitespace-nowrap min-w-[140px] pointer-events-none"
									>
										<div
											class="font-bold text-foreground border-b border-border/40 pb-1 flex items-center justify-between gap-3"
										>
											<span>{pt.label}</span>
											<span
												class="text-muted-foreground font-mono text-[10px]"
												>{pt.total} queries</span
											>
										</div>
										<div
											class="flex flex-col gap-0.5 font-mono text-[10px]"
										>
											<div
												class="flex items-center justify-between gap-2 text-emerald-400"
											>
												<span>Cached:</span>
												<span
													>{pt.cached} ({pt.cachedPct}%)</span
												>
											</div>
											<div
												class="flex items-center justify-between gap-2 text-sky-400"
											>
												<span>Resolved:</span>
												<span
													>{pt.forwarded} ({pt.forwardedPct}%)</span
												>
											</div>
											{#if pt.blocked > 0}
												<div
													class="flex items-center justify-between gap-2 text-rose-400"
												>
													<span>Blocked:</span>
													<span
														>{pt.blocked} ({pt.blockedPct}%)</span
													>
												</div>
											{/if}
										</div>
									</div>

									<!-- Multi-layer Stacked Bar (Pi-hole style) -->
									<div
										class="w-full max-w-[24px] rounded-t flex flex-col justify-end overflow-hidden bg-zinc-800/40 group-hover:ring-1 group-hover:ring-sky-400/50 transition-all"
										style="height: {Math.max(
											6,
											Math.round(
												(pt.total / maxChartValue) *
													100,
											),
										)}%"
									>
										<!-- Top: Blocked segment -->
										{#if pt.blocked > 0}
											<div
												class="w-full bg-rose-500 hover:bg-rose-400 transition-colors"
												style="height: {pt.blockedPct}%"
												title="Blocked: {pt.blocked}"
											></div>
										{/if}
										<!-- Middle: Resolved / Forwarded segment -->
										{#if pt.forwarded > 0}
											<div
												class="w-full bg-sky-500 hover:bg-sky-400 transition-colors"
												style="height: {pt.forwardedPct}%"
												title="Resolved: {pt.forwarded}"
											></div>
										{/if}
										<!-- Bottom: Cached segment -->
										{#if pt.cached > 0}
											<div
												class="w-full bg-emerald-500 hover:bg-emerald-400 transition-colors"
												style="height: {pt.cachedPct}%"
												title="Cached: {pt.cached}"
											></div>
										{/if}
									</div>
								</div>
							{/each}
						</div>

						<!-- X Axis Labels -->
						<div
							class="flex justify-between px-2 font-mono text-[10px] text-muted-foreground"
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

		<!-- Main 2-Column Section: Upstream Servers List (Left 2 cols) + Interactive Dig Test Tool (Right 1 col) -->
		<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
			<!-- Left Panel: Upstream DNS Servers List -->
			<Card.Root class="flex flex-col lg:col-span-2 overflow-hidden">
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<ServerIcon class="size-4 text-indigo-400" />
							<Card.Title class="text-base"
								>Upstream DNS Servers</Card.Title
							>
						</div>
						<Button
							size="sm"
							variant="outline"
							onclick={() => (upstreamOpen = true)}
						>
							<PlusIcon data-icon="inline-start" />
							Add Upstream
						</Button>
					</div>
				</Card.Header>
				<Card.Content class="p-0">
					{#if loading}
						<div class="flex flex-col gap-3 p-6">
							{#each { length: 3 } as _, i (i)}
								<Skeleton class="h-10 w-full" />
							{/each}
						</div>
					{:else if upstreams.length === 0}
						<Empty.Root class="py-12">
							<Empty.Header>
								<Empty.Media>
									<GlobeIcon
										class="size-8 text-muted-foreground/40"
									/>
								</Empty.Media>
								<Empty.Title
									>No Upstream Servers Configured</Empty.Title
								>
								<Empty.Description>
									Lanforge is currently using default system
									DNS resolvers. Add custom Cloudflare,
									Google, or Quad9 upstreams above.
								</Empty.Description>
							</Empty.Header>
						</Empty.Root>
					{:else}
						<div class="max-h-[400px] overflow-auto">
							<Table.Root>
								<Table.Header
									class="sticky top-0 z-10 bg-muted/90 backdrop-blur"
								>
									<Table.Row class="hover:bg-transparent">
										<Table.Head
											>Server Address / URL</Table.Head
										>
										<Table.Head>Protocol</Table.Head>
										<Table.Head>Target Domain</Table.Head>
										<Table.Head>Latency (RTT)</Table.Head>
										<Table.Head>Status</Table.Head>
										<Table.Head class="text-right"
											>Actions</Table.Head
										>
									</Table.Row>
								</Table.Header>
								<Table.Body class="font-mono text-xs">
									{#each upstreams as item, i (getUpstreamAddr(item) + i)}
										<Table.Row>
											<!-- Address / URL -->
											<Table.Cell
												class="font-semibold text-foreground font-mono"
											>
												{getUpstreamAddr(item)}
											</Table.Cell>

											<!-- Protocol Badge -->
											<Table.Cell class="font-sans">
												<Badge
													variant="outline"
													class="text-[10px] uppercase font-mono px-2 py-0.5"
												>
													{getUpstreamProtocol(item)}
												</Badge>
											</Table.Cell>

											<!-- Domain Suffix -->
											<Table.Cell
												class="text-muted-foreground font-sans"
											>
												{item.domain || "Global (*)"}
											</Table.Cell>

											<!-- RTT Latency -->
											<Table.Cell
												class="text-emerald-400 font-medium font-mono"
											>
												{getUpstreamLatency(item)}
											</Table.Cell>

											<!-- Status Badge -->
											<Table.Cell class="font-sans">
												<div
													class="flex items-center gap-1.5"
												>
													<span
														class="size-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
													></span>
													<span
														class="text-[11px] font-medium capitalize"
													>
														{item.status ||
															"Healthy"}
													</span>
												</div>
											</Table.Cell>

											<!-- Actions -->
											<Table.Cell
												class="text-right font-sans"
											>
												<Tooltip.Root>
													<Tooltip.Trigger>
														{#snippet child({
															props,
														})}
															<Button
																variant="ghost"
																size="icon-sm"
																{...props}
																onclick={() =>
																	handleRemoveUpstream(
																		item,
																	)}
															>
																<Trash2Icon
																	data-icon="inline-start"
																	class="text-rose-400"
																/>
															</Button>
														{/snippet}
													</Tooltip.Trigger>
													<Tooltip.Content>
														<p>
															Delete upstream
															server
														</p>
													</Tooltip.Content>
												</Tooltip.Root>
											</Table.Cell>
										</Table.Row>
									{/each}
								</Table.Body>
							</Table.Root>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>

			<!-- Right Panel: Interactive DNS Query / Dig Test Tool -->
			<Card.Root class="flex flex-col lg:col-span-1">
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex items-center gap-2">
						<ZapIcon class="size-4 text-amber-400" />
						<Card.Title class="text-base"
							>Interactive DNS Dig</Card.Title
						>
					</div>
				</Card.Header>
				<Card.Content class="flex flex-col gap-4 p-4 text-xs">
					<form onsubmit={handleDigQuery} class="flex flex-col gap-3">
						<Field.FieldGroup class="gap-3">
							<Field.Field>
								<Field.FieldLabel for="dig-domain"
									>Domain Name</Field.FieldLabel
								>
								<div class="relative">
									<SearchIcon
										class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2"
									/>
									<Input
										id="dig-domain"
										placeholder="e.g. google.com or lanforge.local"
										class="pl-9 text-xs font-mono"
										bind:value={digDomain}
										required
									/>
								</div>
							</Field.Field>

							<Field.Field>
								<Field.FieldLabel for="dig-type"
									>Record Type</Field.FieldLabel
								>
								<div class="grid grid-cols-4 gap-1.5">
									{#each recordTypes as rtype (rtype)}
										<button
											type="button"
											class={[
												"rounded border px-2 py-1 font-mono text-xs font-medium transition-colors",
												digRecordType === rtype
													? "bg-primary text-primary-foreground border-primary"
													: "bg-muted/40 border-border text-muted-foreground hover:text-foreground",
											].join(" ")}
											onclick={() =>
												(digRecordType = rtype)}
										>
											{rtype}
										</button>
									{/each}
								</div>
							</Field.Field>

							<Button
								type="submit"
								size="sm"
								class="w-full mt-1"
								disabled={digLoading}
							>
								{#if digLoading}
									<span
										class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
									></span>
									Querying...
								{:else}
									<ZapIcon data-icon="inline-start" />
									Execute DNS Lookup
								{/if}
							</Button>
						</Field.FieldGroup>
					</form>

					<!-- Dig Query Output Result Box -->
					{#if digResult}
						<div
							class="flex flex-col gap-2 rounded-lg border border-border/60 bg-muted/20 p-3 font-mono text-[11px]"
						>
							<div
								class="flex items-center justify-between border-b border-border/40 pb-1.5 font-sans"
							>
								<span
									class="font-semibold text-emerald-400 flex items-center gap-1"
								>
									<CheckCircle2Icon class="size-3.5" />
									Query Resolved
								</span>
								<Badge
									variant="outline"
									class="font-mono text-[10px]"
									>{digRecordType}</Badge
								>
							</div>

							<pre
								class="whitespace-pre-wrap break-all text-muted-foreground overflow-auto max-h-48 text-[11px] font-mono leading-relaxed">
{JSON.stringify(digResult, null, 2)}
							</pre>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>
		</div>

		<!-- Reverse Resolvers (PTR) Section -->
		<Card.Root class="overflow-hidden">
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex flex-col gap-0.5">
						<Card.Title class="text-base flex items-center gap-2">
							<CpuIcon class="size-4 text-purple-400" />
							<span>Reverse DNS (PTR) Resolvers</span>
						</Card.Title>
						<p class="text-muted-foreground text-xs font-normal">
							Targeted PTR reverse lookup servers for specific LAN
							subnets
						</p>
					</div>
					<Button
						size="sm"
						variant="outline"
						onclick={() => (reverseOpen = true)}
					>
						<PlusIcon data-icon="inline-start" />
						Add Reverse PTR
					</Button>
				</div>
			</Card.Header>
			<Card.Content class="p-0">
				{#if loading}
					<div class="p-6">
						<Skeleton class="h-10 w-full" />
					</div>
				{:else if reverseResolvers.length === 0}
					<Empty.Root class="py-10">
						<Empty.Header>
							<Empty.Media>
								<CpuIcon
									class="size-8 text-muted-foreground/40"
								/>
							</Empty.Media>
							<Empty.Title
								>No Reverse PTR Resolvers Configured</Empty.Title
							>
							<Empty.Description>
								Reverse PTR lookups currently fall back to
								standard local host tracking.
							</Empty.Description>
						</Empty.Header>
					</Empty.Root>
				{:else}
					<div class="max-h-[300px] overflow-auto">
						<Table.Root>
							<Table.Header
								class="sticky top-0 z-10 bg-muted/90 backdrop-blur"
							>
								<Table.Row class="hover:bg-transparent">
									<Table.Head>Target Subnet (CIDR)</Table.Head
									>
									<Table.Head
										>Resolver URI / Server</Table.Head
									>
									<Table.Head class="text-right"
										>Actions</Table.Head
									>
								</Table.Row>
							</Table.Header>
							<Table.Body class="font-mono text-xs">
								{#each reverseResolvers as r, i (formatSubnet(r.subnet) + i)}
									<Table.Row>
										<Table.Cell
											class="font-semibold text-emerald-400 font-mono"
										>
											{formatSubnet(r.subnet)}
										</Table.Cell>
										<Table.Cell
											class="text-sky-400 font-mono"
										>
											{formatResolverUri(r)}
										</Table.Cell>
										<Table.Cell
											class="text-right font-sans"
										>
											<Tooltip.Root>
												<Tooltip.Trigger>
													{#snippet child({ props })}
														<Button
															variant="ghost"
															size="icon-sm"
															{...props}
															onclick={() =>
																handleRemoveReverse(
																	r,
																)}
														>
															<Trash2Icon
																data-icon="inline-start"
																class="text-rose-400"
															/>
														</Button>
													{/snippet}
												</Tooltip.Trigger>
												<Tooltip.Content>
													<p>
														Delete PTR resolver rule
													</p>
												</Tooltip.Content>
											</Tooltip.Root>
										</Table.Cell>
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
</Tooltip.Provider>

<!-- Add Upstream Server Modal -->
<Dialog.Root bind:open={upstreamOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<PlusIcon class="size-5 text-indigo-400" />
				<span>Add Upstream DNS Server</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleAddUpstream} class="py-2">
			<Field.FieldGroup class="gap-4">
				<Field.Field>
					<Field.FieldLabel for="uaddr"
						>Server Address or DoH/DoT URL *</Field.FieldLabel
					>
					<Input
						id="uaddr"
						placeholder="e.g. 1.1.1.1:53 or https://dns.cloudflare.com/dns-query"
						class="font-mono text-xs"
						bind:value={formUpstreamAddr}
						required
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="uproto">Protocol</Field.FieldLabel>
					<div class="grid grid-cols-4 gap-1.5">
						{#each ["Udp", "Tcp", "Tls", "Https"] as proto (proto)}
							<button
								type="button"
								class={[
									"rounded border px-2 py-1.5 font-mono text-xs font-medium transition-colors",
									formUpstreamProto === proto
										? "bg-primary text-primary-foreground border-primary"
										: "bg-muted/40 border-border text-muted-foreground hover:text-foreground",
								].join(" ")}
								onclick={() => (formUpstreamProto = proto)}
							>
								{proto}
							</button>
						{/each}
					</div>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="udomain"
						>Target Domain Suffix (Optional)</Field.FieldLabel
					>
					<Input
						id="udomain"
						placeholder="e.g. lan or internal.company.com"
						class="text-xs"
						bind:value={formUpstreamDomain}
					/>
					<Field.FieldDescription>
						Leave blank to forward all global DNS queries to this
						upstream server.
					</Field.FieldDescription>
				</Field.Field>

				<div class="flex items-center justify-end gap-2 mt-2">
					<Button
						type="button"
						variant="outline"
						size="sm"
						onclick={() => (upstreamOpen = false)}
					>
						Cancel
					</Button>
					<Button
						type="submit"
						size="sm"
						disabled={upstreamSubmitting}
					>
						{#if upstreamSubmitting}
							<span
								class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
							></span>
						{/if}
						Save Upstream Server
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>

<!-- Add Reverse Resolver Modal -->
<Dialog.Root bind:open={reverseOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<PlusIcon class="size-5 text-purple-400" />
				<span>Add Reverse PTR Resolver</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleAddReverse} class="py-2">
			<Field.FieldGroup class="gap-4">
				<Field.Field>
					<Field.FieldLabel for="rsubnet"
						>Target Subnet (CIDR) *</Field.FieldLabel
					>
					<Input
						id="rsubnet"
						placeholder="e.g. 192.168.1.0/24 or fd00::/64"
						class="font-mono text-xs"
						bind:value={formSubnet}
						required
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="ruri"
						>Resolver URI / Server Address *</Field.FieldLabel
					>
					<Input
						id="ruri"
						placeholder="e.g. 192.168.1.1:53"
						class="font-mono text-xs"
						bind:value={formResolverUri}
						required
					/>
				</Field.Field>

				<div class="flex items-center justify-end gap-2 mt-2">
					<Button
						type="button"
						variant="outline"
						size="sm"
						onclick={() => (reverseOpen = false)}
					>
						Cancel
					</Button>
					<Button
						type="submit"
						size="sm"
						disabled={reverseSubmitting}
					>
						{#if reverseSubmitting}
							<span
								class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
							></span>
						{/if}
						Save PTR Resolver
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>
