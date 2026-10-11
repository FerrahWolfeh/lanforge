<script lang="ts">
	import { onMount } from "svelte";
	import { createPolling } from "$lib/utils/polling";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import WrenchIcon from "@lucide/svelte/icons/wrench";
	import FileDownIcon from "@lucide/svelte/icons/file-down";

	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";
	import DbStatsCards from "./components/DbStatsCards.svelte";
	import { dbState, formatBytes, formatTimeAgo } from "./dbState.svelte";

	let { children } = $props();

	const tabs: NavTabItem[] = [
		{ label: "Inventory", href: "/system/database", icon: LayersIcon },
		{ label: "Storage Settings", href: "/system/database/settings", icon: SlidersIcon },
		{ label: "Maintenance", href: "/system/database/maintenance", icon: WrenchIcon },
		{ label: "Backup & Restore", href: "/system/database/backup", icon: FileDownIcon },
	];

	onMount(() => {
		dbState.loadAll();
		const stopPolling = createPolling(() => {
			dbState.loadAll(true);
		}, 10000);
		return () => {
			stopPolling();
		};
	});
</script>

<svelte:head>
	<title>Database & Persistence — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 w-full">
	<!-- Page Header -->
	<PageHeader
		title="Database & Persistence"
		description="Storage engine health, persistent inventory, background flushes, and configuration management."
		icon={DatabaseIcon}
	>
		{#snippet badge()}
			{#if dbState.loading && !dbState.systemStatus}
				<Skeleton class="h-5 w-28 rounded-full" />
			{:else if dbState.isInMemory}
				<StatusBadge variant="warning" text="Volatile / In-Memory" showDot />
				<HelpPopover
					title="Volatile Storage Mode"
					description="Running in-memory without redb. All runtime state is kept in process memory and resets when Lanforge restarts."
				>
					{#snippet children()}
						<div class="flex flex-col gap-2 text-xs">
							<p class="text-muted-foreground leading-relaxed">
								To persist leases, hosts, and DNS rules across restarts, switch to a permanent path (e.g. <code class="font-mono text-foreground font-semibold">/var/lib/lanforge/lanforge.redb</code>) in Storage Settings.
							</p>
							<div class="flex gap-2 pt-1">
								<Button variant="outline" size="sm" class="flex-1 text-xs h-7" href="/system/database/settings">
									Settings
								</Button>
								<Button variant="outline" size="sm" class="flex-1 text-xs h-7" href="/system/database/backup">
									Backups
								</Button>
							</div>
						</div>
					{/snippet}
				</HelpPopover>
			{:else}
				<StatusBadge variant="online" text="redb (Connected)" showDot />
				<HelpPopover
					title="Persistent Storage Engine"
					description="Using an embedded redb database on disk. Leases, reservations, and configuration are persisted across reboots."
				/>
			{/if}
		{/snippet}

		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				onclick={() => dbState.loadAll()}
				disabled={dbState.loading || dbState.refreshing}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon
					class={dbState.refreshing ? "animate-spin size-3.5" : "size-3.5"}
					data-icon="inline-start"
				/>
				Refresh
			</Button>
		{/snippet}
	</PageHeader>

	<!-- Top 4 High-Density Metric Cards -->
	<DbStatsCards
		systemStatus={dbState.systemStatus}
		metrics={dbState.metrics}
		totalStoredEntities={dbState.totalStoredEntities}
		loading={dbState.loading}
		isInMemory={dbState.isInMemory}
		engineLabel={dbState.engineLabel}
		isHealthy={dbState.isHealthy}
		{formatBytes}
		{formatTimeAgo}
	/>

	<!-- Navigation Tabs Bar -->
	<NavTabs {tabs} ariaLabel="Database storage navigation" />

	<!-- Page Content Slot -->
	{@render children()}
</div>
