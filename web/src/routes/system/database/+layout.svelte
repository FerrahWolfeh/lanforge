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
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div class="flex items-center gap-3">
			<div class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0">
				<DatabaseIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-1">
				<div class="flex flex-wrap items-center gap-2.5">
					<h1 class="text-2xl font-bold tracking-tight">Database & Persistence</h1>
					{#if dbState.loading && !dbState.systemStatus}
						<Skeleton class="h-5 w-28 rounded-full" />
					{:else if dbState.isInMemory}
						<div class="flex items-center gap-1.5">
							<Badge
								variant="outline"
								class="border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 font-medium text-xs gap-1.5"
							>
								<AlertTriangleIcon class="size-3" />
								Volatile / In-Memory
							</Badge>
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
						</div>
					{:else}
						<div class="flex items-center gap-1.5">
							<Badge
								variant="outline"
								class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
							>
								<span class="relative flex size-2 mr-1.5">
									<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
									<span class="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
								</span>
								redb (Connected)
							</Badge>
							<HelpPopover
								title="Persistent Storage Engine"
								description="Using an embedded redb database on disk. Leases, reservations, and configuration are persisted across reboots."
							/>
						</div>
					{/if}
				</div>
				<p class="text-sm text-muted-foreground">
					Storage engine health, persistent inventory, background flushes, and configuration management.
				</p>
			</div>
		</div>

		<div class="flex flex-wrap items-center gap-2">
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
		</div>
	</div>

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
