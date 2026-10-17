<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import * as Tabs from "$lib/components/ui/tabs";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import HistoryIcon from "@lucide/svelte/icons/history";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import { page } from "$app/state";
	import { dnsQueryLog, dnsLogSseUrl, dnsStats, dnsRewriteAdd } from "$lib/api/client";
	import type { DnsQueryLogEntry, DnsStatsResponse, RewriteRule } from "$lib/api/types";
	import PageHeader from "$lib/components/PageHeader.svelte";

	// Child components
	import DnsLogStatsCards from "./components/DnsLogStatsCards.svelte";
	import DnsLogTable from "./components/DnsLogTable.svelte";
	import DnsLogLiveTail from "./components/DnsLogLiveTail.svelte";
	import DnsLogDetailDialog from "./components/DnsLogDetailDialog.svelte";
	import DnsRewriteDialog from "../rewrites/components/DnsRewriteDialog.svelte";

	let activeTab = $state<"history" | "live">("history");
	let stats = $state<DnsStatsResponse | null>(null);

	// --- Tab 1: Query History State ---
	let historyLoading = $state(true);
	let historyEntries = $state<DnsQueryLogEntry[]>([]);
	let historyTotal = $state(0);
	let searchQuery = $state("");
	let selectedType = $state("");
	let selectedResult = $state("");
	let limit = $state(50);
	let offset = $state(0);
	let searchDebounce: ReturnType<typeof setTimeout> | null = null;

	// --- Tab 2: Live Stream State ---
	let liveEntries = $state<DnsQueryLogEntry[]>([]);
	let isLivePaused = $state(false);
	let isLiveConnected = $state(false);
	let bufferLimit = $state(200);
	let eventSource: EventSource | null = null;

	// --- Shared Dialog States ---
	let inspectRecord = $state<DnsQueryLogEntry | null>(null);
	let inspectDialogOpen = $state(false);
	let rewriteDialogOpen = $state(false);
	let activeRewriteRule = $state<RewriteRule | null>(null);

	async function loadDaemonStats() {
		try {
			const s = await dnsStats();
			if (s) stats = s;
		} catch {
			// silent fallback
		}
	}

	async function loadHistoricalLogs() {
		historyLoading = true;
		try {
			await loadDaemonStats();
			const res = await dnsQueryLog({
				domain: searchQuery.trim() || undefined,
				qtype: selectedType || undefined,
				result: selectedResult || undefined,
				limit,
				offset,
			});
			if (res) {
				historyEntries = res.entries;
				historyTotal = res.total;
			}
		} catch {
			toast.error("Failed to load historical DNS query logs");
		} finally {
			historyLoading = false;
		}
	}

	function handleSearchInput(q: string) {
		searchQuery = q;
		offset = 0;
		if (searchDebounce) clearTimeout(searchDebounce);
		searchDebounce = setTimeout(() => {
			loadHistoricalLogs();
		}, 300);
	}

	function handleTypeSelect(kind: string) {
		selectedType = kind;
		offset = 0;
		loadHistoricalLogs();
	}

	function handleResultSelect(res: string) {
		selectedResult = res;
		offset = 0;
		loadHistoricalLogs();
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		loadHistoricalLogs();
	}

	// --- Live SSE Stream Life-cycle ---
	function startLiveStream() {
		stopLiveStream();
		try {
			const url = dnsLogSseUrl();
			eventSource = new EventSource(url);
			isLiveConnected = true;

			eventSource.onmessage = (event) => {
				if (isLivePaused) return;
				try {
					const parsed = JSON.parse(event.data);
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
							src_mac: dnsEv.src_mac ? String(dnsEv.src_mac) : null,
							src_hostname: dnsEv.src_hostname ? String(dnsEv.src_hostname) : null,
							domain: String(dnsEv.domain ?? ""),
							qtype: (dnsEv.qtype ?? "A") as any,
							result: String(dnsEv.result ?? "forwarded").toLowerCase(),
							upstream_us: Number(dnsEv.upstream_us ?? 0),
							cached: Boolean(dnsEv.cached),
							answer: dnsEv.answer ? String(dnsEv.answer) : null,
							filter: dnsEv.filter ?? null,
						};

						liveEntries = [newEntry, ...liveEntries.slice(0, bufferLimit - 1)];
					}
				} catch {
					// Ignore invalid frame
				}
			};

			eventSource.onerror = () => {
				isLiveConnected = false;
			};
		} catch {
			isLiveConnected = false;
		}
	}

	function stopLiveStream() {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
		isLiveConnected = false;
	}

	function toggleLivePause() {
		isLivePaused = !isLivePaused;
		if (isLivePaused) {
			toast.info("Paused live stream updates");
		} else {
			toast.info("Resumed live stream updates");
		}
	}

	function clearLiveBuffer() {
		liveEntries = [];
		toast.success("Cleared live tail buffer");
	}

	// Tab switcher lifecycle watcher
	$effect(() => {
		if (activeTab === "live") {
			if (!eventSource) {
				startLiveStream();
			}
		}
	});

	function handleInspect(entry: DnsQueryLogEntry) {
		inspectRecord = entry;
		inspectDialogOpen = true;
	}

	function handleOpenRewrite(domain: string, target: string) {
		activeRewriteRule = {
			domain,
			rtype: "A",
			answer: target && target !== "—" ? { kind: "static", value: target } : { kind: "static", value: "127.0.0.1" },
			enabled: true,
		} as any;
		rewriteDialogOpen = true;
	}

	async function handleSaveRewrite(payload: any) {
		try {
			await dnsRewriteAdd(payload);
			toast.success(`Created DNS rewrite rule for ${payload.domain}`);
			rewriteDialogOpen = false;
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save DNS rewrite rule");
			throw err;
		}
	}

	onMount(() => {
		const resultParam = page.url.searchParams.get("result");
		if (resultParam) {
			selectedResult = resultParam;
		}
		loadHistoricalLogs();
	});

	onDestroy(() => {
		stopLiveStream();
	});
</script>

<svelte:head>
	<title>DNS Query Log — Lanforge</title>
</svelte:head>

<div class="space-y-6">
	<!-- Top Action Bar -->
	<PageHeader
		title="DNS Query Log"
		description="Network resolution telemetry, live packet stream, and client query audit trail."
		icon={ListFilterIcon}
	>
		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				onclick={() => {
					if (activeTab === "history") {
						loadHistoricalLogs();
					} else {
						startLiveStream();
					}
				}}
				disabled={historyLoading && activeTab === "history"}
				class="gap-2"
			>
				<RefreshCwIcon
					class="size-3.5 {historyLoading && activeTab === 'history' ? 'animate-spin' : ''}"
				/>
				Refresh
			</Button>
		{/snippet}
	</PageHeader>

	<!-- Top Metric Summary Cards -->
	<DnsLogStatsCards
		loading={historyLoading}
		isLive={isLiveConnected && !isLivePaused}
		entries={activeTab === "live" ? liveEntries : historyEntries}
		total={historyTotal}
		{stats}
		{selectedResult}
		onSelectResult={(res) => {
			activeTab = "history";
			handleResultSelect(res);
		}}
	/>

	<!-- Tabbed Rules View (Consistent with Adblock rules & SQM tabs style) -->
	<Tabs.Root bind:value={activeTab} class="space-y-4">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div class="overflow-x-auto no-scrollbar w-full sm:w-auto -mx-1 px-1 py-0.5">
				<Tabs.List class="inline-flex w-max h-9 p-1">
					<Tabs.Trigger value="history" class="gap-1.5 text-xs shrink-0">
						<HistoryIcon class="size-3.5 text-primary" />
						<span>Query History</span>
						{#if historyTotal > 0}
							<Badge variant="secondary" class="ml-1 px-1.5 py-0 text-[10px] font-mono">
								{historyTotal.toLocaleString()}
							</Badge>
						{/if}
					</Tabs.Trigger>

					<Tabs.Trigger value="live" class="gap-1.5 text-xs shrink-0">
						<RadioIcon
							class="size-3.5 {isLiveConnected && !isLivePaused
								? 'text-emerald-500 animate-pulse'
								: 'text-muted-foreground'}"
						/>
						<span>Live Stream</span>
						{#if liveEntries.length > 0}
							<Badge variant="secondary" class="ml-1 px-1.5 py-0 text-[10px] font-mono">
								{liveEntries.length}
							</Badge>
						{/if}
					</Tabs.Trigger>
				</Tabs.List>
			</div>
		</div>

		<!-- Container 1: Query History Tab Content (Preserved DOM state via hidden toggle) -->
		<div class={activeTab === "history" ? "block space-y-4" : "hidden"}>
			<DnsLogTable
				loading={historyLoading}
				entries={historyEntries}
				total={historyTotal}
				{searchQuery}
				{selectedType}
				{selectedResult}
				{limit}
				{offset}
				onSearchChange={handleSearchInput}
				onTypeChange={handleTypeSelect}
				onResultChange={handleResultSelect}
				onPageChange={handlePageChange}
				onAddRewrite={handleOpenRewrite}
			/>
		</div>

		<!-- Container 2: Live Stream Tab Content (Preserved DOM state via hidden toggle) -->
		<div class={activeTab === "live" ? "block space-y-4" : "hidden"}>
			<DnsLogLiveTail
				entries={liveEntries}
				isPaused={isLivePaused}
				isConnected={isLiveConnected}
				{bufferLimit}
				onTogglePause={toggleLivePause}
				onClearBuffer={clearLiveBuffer}
				onInspect={handleInspect}
				onAddRewrite={handleOpenRewrite}
				onBufferLimitChange={(newLimit) => {
					bufferLimit = newLimit;
					if (liveEntries.length > newLimit) {
						liveEntries = liveEntries.slice(0, newLimit);
					}
				}}
			/>
		</div>
	</Tabs.Root>
</div>

<!-- Shared Query Inspection Dialog -->
<DnsLogDetailDialog
	bind:open={inspectDialogOpen}
	entry={inspectRecord}
	onAddRewrite={handleOpenRewrite}
/>

<!-- Shared DNS Rewrite Creation Dialog -->
<DnsRewriteDialog
	bind:open={rewriteDialogOpen}
	rule={activeRewriteRule}
	onSave={handleSaveRewrite}
/>
