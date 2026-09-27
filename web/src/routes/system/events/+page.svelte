<script lang="ts">
	import { onMount, onDestroy } from "svelte";
	import { Button } from "$lib/components/ui/button";
	import { toast } from "svelte-sonner";
	import { eventsUrl, eventsHistory, status } from "$lib/api/client";
	import { parseTimedEvent, type SseEvent, type StatusResponse } from "$lib/api/types";
	import EventStatsCards from "./components/EventStatsCards.svelte";
	import EventTable from "./components/EventTable.svelte";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PauseIcon from "@lucide/svelte/icons/pause";
	import PlayIcon from "@lucide/svelte/icons/play";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";

	let loading = $state(true);
	let isLive = $state(true);
	let reconnecting = $state(false);
	let bufferLimit = $state(500);
	let events = $state<SseEvent[]>([]);
	let systemStatus = $state<StatusResponse | null>(null);

	let eventSource: EventSource | null = null;
	let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
	let reconnectAttempts = 0;

	async function loadSystemStatus() {
		try {
			systemStatus = await status();
		} catch {
			// Silent fallback for status vitals
		}
	}

	async function loadHistoricalEvents() {
		loading = true;
		try {
			await loadSystemStatus();
			const res = await eventsHistory({ limit: bufferLimit });
			if (res && Array.isArray(res.entries)) {
				// Reverse so newest is at the top
				events = res.entries.slice().reverse();
			}
		} catch (err) {
			toast.error("Failed to load historical system events");
		} finally {
			loading = false;
		}
	}

	function startSseStream() {
		stopSseStream();
		if (!isLive) return;

		try {
			const url = eventsUrl();
			eventSource = new EventSource(url);

			eventSource.onopen = () => {
				reconnecting = false;
				reconnectAttempts = 0;
			};

			eventSource.onmessage = (msgEvent) => {
				if (!msgEvent.data || msgEvent.data === "keepalive") return;

				try {
					const parsed = JSON.parse(msgEvent.data);
					const newEvent = parseTimedEvent(parsed, msgEvent.lastEventId);

					// Avoid inserting duplicates if the event was already in initial history
					events = [newEvent, ...events.filter((e) => e.id !== newEvent.id)];

					// Enforce FIFO buffer limit
					if (events.length > bufferLimit) {
						events = events.slice(0, bufferLimit);
					}
				} catch {
					// Ignore malformed JSON chunks
				}
			};

			eventSource.onerror = () => {
				stopSseStream();
				if (!isLive) return;

				reconnecting = true;
				const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), 15000);
				reconnectAttempts++;

				reconnectTimeout = setTimeout(() => {
					if (isLive) {
						startSseStream();
					}
				}, delay);
			};
		} catch {
			reconnecting = true;
		}
	}

	function stopSseStream() {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
		if (reconnectTimeout) {
			clearTimeout(reconnectTimeout);
			reconnectTimeout = null;
		}
	}

	function toggleLiveFeed() {
		isLive = !isLive;
		if (isLive) {
			toast.info("Resumed live event stream");
			startSseStream();
		} else {
			stopSseStream();
			reconnecting = false;
			toast.info("Live event stream paused");
		}
	}

	function clearBuffer() {
		events = [];
		toast.success("Local event buffer cleared");
	}

	async function refreshAll() {
		await loadHistoricalEvents();
		if (isLive) {
			startSseStream();
		}
		toast.success("Event history reloaded");
	}

	onMount(async () => {
		await loadHistoricalEvents();
		startSseStream();
	});

	onDestroy(() => {
		stopSseStream();
	});
</script>

<div class="space-y-6">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-2xl font-bold tracking-tight">System Events</h1>
			<p class="text-sm text-muted-foreground mt-0.5">
				Real-time monitoring of daemon lifecycles, network discovery, firewall changes, and DHCP leases.
			</p>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant={isLive ? "outline" : "default"}
				size="sm"
				onclick={toggleLiveFeed}
				class="gap-1.5 text-xs"
			>
				{#if isLive}
					<PauseIcon class="size-3.5 text-amber-500" />
					<span>Pause Feed</span>
				{:else}
					<PlayIcon class="size-3.5 text-emerald-500" />
					<span>Live Stream</span>
				{/if}
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={refreshAll}
				disabled={loading}
				class="gap-1.5 text-xs"
			>
				<RefreshCwIcon class="size-3.5 {loading ? 'animate-spin' : ''}" />
				<span>Refresh</span>
			</Button>

			<Button
				variant="ghost"
				size="sm"
				onclick={clearBuffer}
				disabled={events.length === 0}
				class="gap-1.5 text-xs text-muted-foreground hover:text-destructive"
			>
				<Trash2Icon class="size-3.5" />
				<span class="hidden sm:inline">Clear</span>
			</Button>
		</div>
	</div>

	<!-- Stats & Metric Cards -->
	<EventStatsCards
		{loading}
		{isLive}
		{reconnecting}
		{events}
		{bufferLimit}
		status={systemStatus}
	/>

	<!-- Events Data Table Card -->
	<EventTable
		{events}
		{loading}
		{isLive}
		bind:bufferLimit
		onToggleLive={toggleLiveFeed}
		onClearBuffer={clearBuffer}
		onRefreshHistory={refreshAll}
	/>
</div>
