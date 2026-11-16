<script lang="ts">
	import { onMount, onDestroy } from "svelte";
	import { Button } from "$lib/components/ui/button";
	import { toast } from "svelte-sonner";
	import { eventsUrl, eventsHistory, openEventStream, type EventStream } from "$lib/api/client";
	import { parseTimedEvent, type SseEvent } from "$lib/api/types";
	import EventTable from "./components/EventTable.svelte";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PauseIcon from "@lucide/svelte/icons/pause";
	import PlayIcon from "@lucide/svelte/icons/play";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import NavTabs from "$lib/components/NavTabs.svelte";
	import { systemTabs } from "../tabs";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";

	let loading = $state(true);
	let isLive = $state(true);
	let reconnecting = $state(false);
	let bufferLimit = $state(500);
	let events = $state<SseEvent[]>([]);

	let eventSource: EventStream | null = null;
	let destroyed = false;

	async function loadHistoricalEvents() {
		loading = true;
		try {
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
			eventSource = openEventStream(url, {
				onopen: () => {
					reconnecting = false;
				},
				// The stream reconnects on its own; a 401 logs out inside it.
				onerror: () => {
					reconnecting = isLive;
				},
				onmessage: (msgEvent) => {
				if (!msgEvent.data || msgEvent.data === "keepalive") return;

				try {
					const parsed = JSON.parse(msgEvent.data);
					const newEvent = parseTimedEvent(parsed, msgEvent.lastEventId);

					// The daemon sends no SSE ids, so events cannot be deduplicated by id; the stream is
					// stopped while history reloads instead. Enforce the FIFO buffer limit.
					events = [newEvent, ...events].slice(0, bufferLimit);
				} catch {
					// Ignore malformed JSON chunks
				}
				},
			});
		} catch {
			reconnecting = true;
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
		// Keep the stream closed while history loads, so no event lands in the buffer being replaced.
		stopSseStream();
		await loadHistoricalEvents();
		if (isLive && !destroyed) {
			startSseStream();
		}
		toast.success("Event history reloaded");
	}

	onMount(async () => {
		await loadHistoricalEvents();
		if (!destroyed) startSseStream();
	});

	onDestroy(() => {
		destroyed = true;
		stopSseStream();
	});
</script>

<div class="space-y-6">
	<!-- Page Header -->
	<PageHeader
		title="System Events"
		description="What happened on the router: devices, leases, services and configuration changes."
		icon={ActivityIcon}
	>
		{#snippet badge()}
			{#if reconnecting}
				<StatusBadge variant="warning" text="Reconnecting" showDot />
			{:else if isLive}
				<StatusBadge variant="online" text="Live Stream" showDot />
			{:else}
				<StatusBadge variant="dormant" text="Paused" showDot />
			{/if}
		{/snippet}

		{#snippet actions()}
			<Button
				variant={isLive ? "outline" : "default"}
				size="sm"
				onclick={toggleLiveFeed}
				class="gap-1.5 text-xs"
			>
				{#if isLive}
					<PauseIcon class="size-3.5 text-warning" />
					<span>Pause Feed</span>
				{:else}
					<PlayIcon class="size-3.5 text-success" />
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
		{/snippet}
	</PageHeader>

	<!-- System Diagnostics Sub-Navigation Tabs -->
	<NavTabs tabs={systemTabs} ariaLabel="System diagnostics navigation" />


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
