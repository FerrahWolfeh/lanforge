<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import * as Tabs from "$lib/components/ui/tabs";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import HistoryIcon from "@lucide/svelte/icons/history";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import XIcon from "@lucide/svelte/icons/x";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import { page } from "$app/state";
	import { replaceState } from "$app/navigation";
	import { dnsQueryLog, dnsLogSseUrl, openEventStream, type EventStream } from "$lib/api/client";
	import type { DnsQueryLogEntry } from "$lib/api/types";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import { createSequence } from "$lib/utils";

	// Child components
	import DnsLogTable from "./components/DnsLogTable.svelte";
	import DnsLogLiveTail from "./components/DnsLogLiveTail.svelte";
	import DnsLogDetailDialog from "./components/DnsLogDetailDialog.svelte";
	import DnsRewriteDialog from "../rewrites/components/DnsRewriteDialog.svelte";

	let activeTab = $state<"history" | "live">("history");

	// --- Tab 1: Query History State ---
	let historyLoading = $state(true);
	let historyEntries = $state<DnsQueryLogEntry[]>([]);
	let historyTotal = $state(0);
	let searchQuery = $state("");
	let selectedType = $state("");
	let selectedResult = $state("");
	/** Set from `?client=` (a device's MAC link); empty means all clients. */
	let selectedClient = $state("");
	/** Set from `?domain=` (a domain page link): prefills the search and shows a chip. */
	let selectedDomain = $state("");
	let limit = $state(50);
	let offset = $state(0);
	let searchDebounce: ReturnType<typeof setTimeout> | null = null;

	// --- Tab 2: Live Stream State ---
	let liveEntries = $state<DnsQueryLogEntry[]>([]);
	let liveSeq = 0;
	let isLivePaused = $state(false);
	let isLiveConnected = $state(false);
	let bufferLimit = $state(200);
	let eventSource: EventStream | null = null;

	// --- Shared Dialog States ---
	let inspectRecord = $state<DnsQueryLogEntry | null>(null);
	let inspectDialogOpen = $state(false);
	let rewriteDialogOpen = $state(false);
	let rewritePrefill = $state<{ domain: string; answer: string } | null>(null);

	const historySeq = createSequence();

	async function loadHistoricalLogs() {
		const seq = historySeq.next();
		historyLoading = true;
		try {
			const res = await dnsQueryLog({
				client: selectedClient || undefined,
				domain: searchQuery.trim() || undefined,
				qtype: selectedType || undefined,
				result: selectedResult || undefined,
				limit,
				offset,
			});
			if (!historySeq.isCurrent(seq)) return;
			if (res) {
				historyEntries = res.entries;
				historyTotal = res.total;
			}
		} catch {
			if (!historySeq.isCurrent(seq)) return;
			toast.error("Failed to load historical DNS query logs");
		}
		historyLoading = false;
	}

	function dropParam(name: string) {
		const url = new URL(page.url);
		url.searchParams.delete(name);
		replaceState(url, page.state);
	}

	function handleSearchInput(q: string) {
		searchQuery = q;
		// Typing something else replaces the domain filter.
		if (selectedDomain && q !== selectedDomain) {
			selectedDomain = "";
			dropParam("domain");
		}
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

	/** Filters both tabs by one client; the live stream restarts with the new filter. */
	function clearClient() {
		selectedClient = "";
		// Drop the param too, so a reload or a shared link does not bring the filter back.
		const url = new URL(page.url);
		url.searchParams.delete("client");
		replaceState(url, page.state);
		offset = 0;
		loadHistoricalLogs();
		if (eventSource) {
			liveEntries = [];
			startLiveStream();
		}
	}

	function clearDomain() {
		selectedDomain = "";
		searchQuery = "";
		dropParam("domain");
		offset = 0;
		loadHistoricalLogs();
	}

	// --- Live SSE Stream Life-cycle ---
	function startLiveStream() {
		stopLiveStream();
		try {
			const url = dnsLogSseUrl({ client: selectedClient || undefined });
			eventSource = openEventStream(url, {
				onopen: () => {
					isLiveConnected = true;
				},
				onerror: () => {
					isLiveConnected = false;
				},
				onmessage: (event) => {
				isLiveConnected = true;
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
							coalesce_id:
								typeof dnsEv.coalesce_id === "number"
									? dnsEv.coalesce_id
									: typeof parsed.coalesce_id === "number"
										? parsed.coalesce_id
										: null,
							repeats: typeof dnsEv.repeats === "number" ? dnsEv.repeats : 1,
							_seq: ++liveSeq,
						};

						liveEntries = [newEntry, ...liveEntries.slice(0, bufferLimit - 1)];
					}
				} catch {
					// Ignore invalid frame
				}
				},
			});
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
		} else {
			stopLiveStream();
		}
	});

	function handleInspect(entry: DnsQueryLogEntry) {
		inspectRecord = entry;
		inspectDialogOpen = true;
	}

	function handleOpenRewrite(domain: string, target: string) {
		rewritePrefill = { domain, answer: target && target !== "—" ? target : "" };
		rewriteDialogOpen = true;
	}

	onMount(() => {
		const resultParam = page.url.searchParams.get("result");
		if (resultParam) {
			selectedResult = resultParam;
		}
		selectedClient = page.url.searchParams.get("client") ?? "";
		selectedDomain = page.url.searchParams.get("domain") ?? "";
		if (selectedDomain) searchQuery = selectedDomain;
		loadHistoricalLogs();
	});

	onDestroy(() => {
		if (searchDebounce) clearTimeout(searchDebounce);
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
		description="Every DNS question your devices asked, newest first."
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

	{#if selectedClient || selectedDomain}
		<div class="flex flex-wrap gap-2">
		{#if selectedClient}
			<span class="inline-flex items-center gap-1.5 rounded-full bg-selected py-1 pr-1 pl-3 text-xs text-selected-foreground">
				Client: <span class="font-mono">{selectedClient}</span>
				<button
					type="button"
					class="inline-flex size-5 items-center justify-center rounded-full hover:bg-muted"
					aria-label="Clear client filter"
					onclick={clearClient}
				>
					<XIcon class="size-3" />
				</button>
			</span>
		{/if}
		{#if selectedDomain}
			<span class="inline-flex items-center gap-1.5 rounded-full bg-selected py-1 pr-1 pl-3 text-xs text-selected-foreground">
				Domain: <span class="font-mono">{selectedDomain}</span>
				<button
					type="button"
					class="inline-flex size-5 items-center justify-center rounded-full hover:bg-muted"
					aria-label="Clear domain filter"
					onclick={clearDomain}
				>
					<XIcon class="size-3" />
				</button>
			</span>
		{/if}
		</div>
	{/if}


	<!-- Tabbed Rules View (Consistent with Adblock rules & SQM tabs style) -->
	<Tabs.Root bind:value={activeTab} class="space-y-4">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div class="overflow-x-auto no-scrollbar w-full sm:w-auto -mx-1 px-1 py-0.5">
				<Tabs.List class="inline-flex w-max h-9 p-1">
					<Tabs.Trigger value="history" class="gap-1.5 text-xs shrink-0">
						<HistoryIcon class="size-3.5 text-primary" />
						<span>Query History</span>
						{#if historyTotal > 0}
							<Badge variant="secondary" class="ml-1 px-1.5 py-0 text-xs font-mono">
								{historyTotal.toLocaleString()}
							</Badge>
						{/if}
					</Tabs.Trigger>

					<Tabs.Trigger value="live" class="gap-1.5 text-xs shrink-0">
						<RadioIcon
							class="size-3.5 {isLiveConnected && !isLivePaused
								? 'text-success'
								: 'text-muted-foreground'}"
						/>
						<span>Live Stream</span>
						{#if liveEntries.length > 0}
							<Badge variant="secondary" class="ml-1 px-1.5 py-0 text-xs font-mono">
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
	prefill={rewritePrefill}
/>
