<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import PauseIcon from "@lucide/svelte/icons/pause";
	import PlayIcon from "@lucide/svelte/icons/play";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import { dnsQueryLog, dnsLogSseUrl, dnsStats } from "$lib/api/client";
	import type { DnsQueryLogEntry, DnsStatsResponse } from "$lib/api/types";

	// Child components
	import DnsLogStatsCards from "./components/DnsLogStatsCards.svelte";
	import DnsLogTable from "./components/DnsLogTable.svelte";

	let loading = $state(true);
	let isLive = $state(true);
	let stats = $state<DnsStatsResponse | null>(null);
	let entries = $state<DnsQueryLogEntry[]>([]);
	let total = $state(0);

	// Filters & Pagination
	let searchQuery = $state("");
	let selectedType = $state("");
	let selectedResult = $state("");
	let limit = $state(50);
	let offset = $state(0);

	let searchTimeout: ReturnType<typeof setTimeout> | null = null;
	let eventSource: EventSource | null = null;

	async function loadDaemonStats() {
		try {
			const s = await dnsStats();
			if (s) stats = s;
		} catch {
			// silent fallback
		}
	}

	async function loadHistoricalLogs() {
		loading = true;
		try {
			await loadDaemonStats();
			const res = await dnsQueryLog({
				limit,
				offset,
				client: searchQuery.trim() || undefined,
			});
			if (res) {
				entries = res.entries;
				total = res.total;
			}
		} catch {
			toast.error("Failed to load historical DNS query logs");
		} finally {
			loading = false;
		}
	}

	function startSseStream() {
		stopSseStream();
		if (!isLive) return;

		try {
			const url = dnsLogSseUrl({
				client: searchQuery.trim() || undefined,
			});
			eventSource = new EventSource(url);

			eventSource.onmessage = (event) => {
				try {
					const parsed = JSON.parse(event.data);
					// Extract event payload
					const dnsEv =
						parsed.event?.Dns?.QueryResolved ??
						parsed.event?.QueryResolved ??
						parsed.data?.QueryResolved ??
						parsed.data ??
						parsed;
					if (dnsEv && typeof dnsEv === "object") {
						const ts =
							typeof dnsEv.timestamp === "number"
								? dnsEv.timestamp
								: typeof parsed.timestamp === "number"
									? parsed.timestamp
									: Date.now();
						const newEntry: DnsQueryLogEntry = {
							timestamp: ts,
							src_ip: String(dnsEv.src_ip ?? "127.0.0.1"),
							src_mac: dnsEv.src_mac
								? String(dnsEv.src_mac)
								: null,
							src_hostname: dnsEv.src_hostname
								? String(dnsEv.src_hostname)
								: null,
							domain: String(dnsEv.domain ?? ""),
							qtype: (dnsEv.qtype ?? "A") as any,
							result:
								typeof dnsEv.result === "string"
									? dnsEv.result
									: String(dnsEv.result ?? "Allowed"),
							upstream_us: Number(dnsEv.upstream_us ?? 0),
							cached: Boolean(dnsEv.cached),
							answer: dnsEv.answer ? String(dnsEv.answer) : null,
						};

						// Prepend to live entries list and bump total
						entries = [newEntry, ...entries.slice(0, 499)];
						total += 1;
					}
				} catch {
					// Ignore invalid SSE packet frame
				}
			};

			eventSource.onerror = () => {
				// Reconnect handled automatically by browser EventSource
			};
		} catch {
			// fallback silently
		}
	}

	function stopSseStream() {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
	}

	function toggleLiveFeed() {
		isLive = !isLive;
		if (isLive) {
			toast.info("Resumed live DNS query feed");
			startSseStream();
		} else {
			stopSseStream();
			toast.info("Paused live DNS query feed");
		}
	}

	function handleSearchInput(q: string) {
		searchQuery = q;
		offset = 0;
		if (searchTimeout) clearTimeout(searchTimeout);
		searchTimeout = setTimeout(() => {
			if (isLive) {
				startSseStream();
			} else {
				loadHistoricalLogs();
			}
		}, 300);
	}

	function handleTypeSelect(kind: string) {
		selectedType = kind;
		offset = 0;
		if (!isLive) {
			loadHistoricalLogs();
		}
	}

	function handleResultSelect(res: string) {
		selectedResult = res;
		offset = 0;
		if (!isLive) {
			loadHistoricalLogs();
		}
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		if (isLive) {
			isLive = false;
			stopSseStream();
		}
		loadHistoricalLogs();
	}

	function clearLogBuffer() {
		entries = [];
		total = 0;
		toast.success("Cleared log view buffer");
	}

	// Filtered list derived state for client-side filtering of live SSE buffer
	const filteredEntries = $derived.by(() => {
		let list = entries;
		if (selectedType) {
			list = list.filter((e) => e.qtype === selectedType);
		}
		if (selectedResult) {
			const resLow = selectedResult.toLowerCase();
			if (resLow === "blocked") {
				list = list.filter(
					(e) =>
						e.result.toLowerCase().includes("block") ||
						e.result.toLowerCase().includes("deny"),
				);
			} else if (resLow === "cached") {
				list = list.filter((e) => e.cached);
			} else if (resLow === "allowed") {
				list = list.filter(
					(e) =>
						!e.result.toLowerCase().includes("block") &&
						!e.result.toLowerCase().includes("deny"),
				);
			} else if (resLow === "rewrite") {
				list = list.filter((e) =>
					e.result.toLowerCase().includes("rewrite"),
				);
			}
		}
		return list;
	});

	onMount(() => {
		loadHistoricalLogs();
		startSseStream();
	});

	onDestroy(() => {
		stopSseStream();
	});
</script>

<svelte:head>
	<title>DNS Query Log — Lanforge</title>
</svelte:head>

<div class="space-y-6">
	<!-- Top Action Bar -->
	<div
		class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
	>
		<div>
			<h1
				class="text-2xl font-bold tracking-tight flex items-center gap-2"
			>
				<ListFilterIcon class="h-6 w-6 text-primary" />
				DNS Query Log
			</h1>
			<p class="text-sm text-muted-foreground">
				Real-time monitoring, telemetry breakdown, and client query
				audit trail.
			</p>
		</div>

		<div class="flex items-center gap-2">
			<!-- Live Feed Toggle Button -->
			<Button
				variant={isLive ? "default" : "outline"}
				size="sm"
				onclick={toggleLiveFeed}
				class="gap-2"
			>
				{#if isLive}
					<PauseIcon class="h-4 w-4" />
					Pause Stream
				{:else}
					<PlayIcon class="h-4 w-4" />
					Live Feed
				{/if}
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={() => loadHistoricalLogs()}
				disabled={loading}
				class="gap-2"
			>
				<RefreshCwIcon
					class="h-4 w-4 {loading ? 'animate-spin' : ''}"
				/>
				Refresh
			</Button>

			<Button
				variant="ghost"
				size="sm"
				onclick={clearLogBuffer}
				class="gap-2 text-muted-foreground hover:text-foreground"
			>
				<Trash2Icon class="h-4 w-4" />
				Clear View
			</Button>
		</div>
	</div>

	<!-- Top Metric Summary Cards -->
	<DnsLogStatsCards
		{loading}
		{isLive}
		entries={filteredEntries}
		{total}
		{stats}
	/>

	<!-- DNS Query Log Data Table -->
	<DnsLogTable
		{loading}
		entries={filteredEntries}
		{total}
		{searchQuery}
		{selectedType}
		{selectedResult}
		{limit}
		{offset}
		onSearchChange={handleSearchInput}
		onTypeChange={handleTypeSelect}
		onResultChange={handleResultSelect}
		onPageChange={handlePageChange}
		onAddRewrite={(domain, target) => {
			toast.info(`Creating rewrite rule for ${domain}`);
		}}
	/>
</div>
