<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import * as Dialog from "$lib/components/ui/dialog";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import {
		dnsCacheDump,
		dnsCacheFlush,
		dnsCacheStatsExt,
	} from "$lib/api/client";
	import type {
		DnsCacheEntry,
		DnsCacheStatsExtResponse,
	} from "$lib/api/types";

	// Child components
	import DnsCacheStatsCards from "./components/DnsCacheStatsCards.svelte";
	import DnsCacheTypeDistribution from "./components/DnsCacheTypeDistribution.svelte";
	import DnsCacheTable from "./components/DnsCacheTable.svelte";

	let loading = $state(true);
	let stats = $state<DnsCacheStatsExtResponse | null>(null);
	let entries = $state<DnsCacheEntry[]>([]);
	let total = $state(0);

	// Filters & Pagination
	let searchQuery = $state("");
	let selectedType = $state("");
	let limit = $state(50);
	let offset = $state(0);

	// Actions & Modals
	let flushModalOpen = $state(false);
	let flushing = $state(false);

	let searchTimeout: ReturnType<typeof setTimeout> | null = null;

	async function loadStats() {
		try {
			const s = await dnsCacheStatsExt();
			if (s) stats = s;
		} catch {
			// fallback / silent
		}
	}

	async function loadEntries() {
		try {
			const res = await dnsCacheDump({
				limit,
				offset,
				q: searchQuery.trim() || undefined,
				kind: selectedType || undefined,
			});
			entries = res.entries;
			total = res.total;
		} catch {
			toast.error("Failed to load DNS cache entries");
		}
	}

	async function refreshAll(showToast = false) {
		loading = true;
		try {
			await Promise.all([loadStats(), loadEntries()]);
			if (showToast) {
				toast.success("DNS cache updated");
			}
		} finally {
			loading = false;
		}
	}

	function handleSearchInput(q: string) {
		searchQuery = q;
		offset = 0;
		if (searchTimeout) clearTimeout(searchTimeout);
		searchTimeout = setTimeout(() => {
			loadEntries();
		}, 300);
	}

	function handleTypeSelect(kind: string) {
		selectedType = kind;
		offset = 0;
		loadEntries();
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		loadEntries();
	}

	async function confirmFlushCache() {
		flushing = true;
		try {
			await dnsCacheFlush();
			toast.success("DNS cache flushed successfully");
			flushModalOpen = false;
			offset = 0;
			await refreshAll();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to flush DNS cache");
		} finally {
			flushing = false;
		}
	}

	onMount(() => {
		refreshAll();
		const interval = setInterval(() => {
			loadStats();
			loadEntries();
		}, 10_000);
		return () => clearInterval(interval);
	});
</script>

<svelte:head>
	<title>DNS Cache — Lanforge</title>
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
				<DatabaseIcon class="h-6 w-6 text-primary" />
				DNS Cache Inspection
			</h1>
			<p class="text-sm text-muted-foreground">
				Inspect live in-memory DNS resolution records, memory footprint,
				and lifetime expirations.
			</p>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={() => refreshAll(true)}
				disabled={loading}
				class="gap-2"
			>
				<RefreshCwIcon
					class="h-4 w-4 {loading ? 'animate-spin' : ''}"
				/>
				Refresh
			</Button>

			<Button
				variant="destructive"
				size="sm"
				onclick={() => (flushModalOpen = true)}
				class="gap-2"
			>
				<Trash2Icon class="h-4 w-4" />
				Flush Cache
			</Button>
		</div>
	</div>

	<!-- Top Metric Summary Cards -->
	<DnsCacheStatsCards {loading} {stats} />

	<!-- Record Type Breakdown Pills -->
	<DnsCacheTypeDistribution
		{loading}
		entriesByType={stats?.entries_by_type ?? {}}
		{selectedType}
		onSelectType={handleTypeSelect}
	/>

	<!-- Cached Records Data Table -->
	<DnsCacheTable
		{loading}
		{entries}
		{total}
		{searchQuery}
		{selectedType}
		{limit}
		{offset}
		onSearchChange={handleSearchInput}
		onTypeChange={handleTypeSelect}
		onPageChange={handlePageChange}
		onAddRewrite={(domain, target) => {
			toast.info(`Creating rewrite rule for ${domain}`);
		}}
	/>
</div>

<!-- Flush Cache Confirmation Modal -->
<Dialog.Root bind:open={flushModalOpen}>
	<Dialog.Content class="sm:max-w-[425px]">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2 text-destructive">
				<AlertTriangleIcon class="h-5 w-5" />
				Flush DNS Cache
			</Dialog.Title>
			<Dialog.Description class="text-xs pt-1">
				Are you sure you want to clear all cached DNS records?
				Subsequent domain queries will be forwarded to your configured
				upstreams.
			</Dialog.Description>
		</Dialog.Header>

		<Dialog.Footer class="gap-2 sm:gap-0 mt-4">
			<Button
				variant="outline"
				onclick={() => (flushModalOpen = false)}
				disabled={flushing}
			>
				Cancel
			</Button>
			<Button
				variant="destructive"
				onclick={confirmFlushCache}
				disabled={flushing}
				class="gap-2"
			>
				{#if flushing}
					<RefreshCwIcon class="h-4 w-4 animate-spin" />
					Flushing...
				{:else}
					<Trash2Icon class="h-4 w-4" />
					Clear Cache Now
				{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
