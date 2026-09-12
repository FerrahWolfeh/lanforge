<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ServerIcon from "@lucide/svelte/icons/server";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import type { StatusResponse, DbMetrics } from "$lib/api/types";

	let {
		systemStatus = null,
		metrics = null,
		totalStoredEntities = 0,
		loading = false,
		isInMemory = false,
		engineLabel = "Persistent (redb)",
		isHealthy = true,
		formatBytes = (b: number) => `${b} B`,
		formatTimeAgo = () => "Never",
	}: {
		systemStatus?: StatusResponse | null;
		metrics?: DbMetrics | null;
		totalStoredEntities?: number;
		loading?: boolean;
		isInMemory?: boolean;
		engineLabel?: string;
		isHealthy?: boolean;
		formatBytes?: (b: number) => string;
		formatTimeAgo?: (secs: number | null | undefined) => string;
	} = $props();
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Card 1: Storage Engine -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground">
				<span>Storage Engine</span>
				<HardDriveIcon class="size-4 text-indigo-400" />
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1.5 pt-1">
			{#if loading && !systemStatus}
				<Skeleton class="h-7 w-32" />
				<Skeleton class="mt-2 h-4 w-40" />
			{:else}
				<div class="text-xl font-bold tracking-tight text-foreground flex items-center gap-2">
					<span>{engineLabel}</span>
				</div>
				<div class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center">
						<span class="text-[11px]">Backend Mode:</span>
						<Badge variant="outline" class="text-[10px] px-1.5 py-0 h-4 font-mono font-normal">
							{isInMemory ? "In-Memory (RAM)" : "redb (Disk)"}
						</Badge>
					</div>
					<p class="text-[11px] text-muted-foreground font-mono truncate mt-0.5" title={systemStatus?.db?.path || "redb"}>
						{systemStatus?.db?.path || "redb (embedded)"}
					</p>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 2: Persistence Cadence -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground">
				<span>Persistence Cadence</span>
				<ActivityIcon class="size-4 text-emerald-400" />
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1.5 pt-1">
			{#if loading && !metrics}
				<Skeleton class="h-7 w-20" />
				<Skeleton class="mt-2 h-4 w-32" />
			{:else}
				<div class="text-xl font-bold tracking-tight text-foreground flex items-baseline gap-2">
					<span>{(metrics?.flush_count ?? 0).toLocaleString()}</span>
					<span class="text-xs font-normal text-muted-foreground">total flushes</span>
				</div>
				<div class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center">
						<span class="text-[11px]">Last Sync:</span>
						<span class="text-foreground text-[11px] font-medium font-mono">
							{formatTimeAgo(systemStatus?.db?.last_flush_secs_ago)}
						</span>
					</div>
					<div class="flex justify-between items-center text-[11px]">
						<span>Interval:</span>
						<span class="text-foreground font-medium">60s tick</span>
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 3: Stored Records & Inventory -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground">
				<span>Stored Records</span>
				<ServerIcon class="size-4 text-blue-400" />
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1.5 pt-1">
			{#if loading && !metrics}
				<Skeleton class="h-7 w-24" />
				<Skeleton class="mt-2 h-4 w-36" />
			{:else}
				<div class="text-xl font-bold tracking-tight text-foreground flex items-baseline gap-2">
					<span>{totalStoredEntities.toLocaleString()}</span>
					<span class="text-xs font-normal text-muted-foreground">entities</span>
				</div>
				<div class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center">
						<span class="text-[11px]">Devices written:</span>
						<span class="text-foreground text-[11px] font-medium font-mono">
							{(metrics?.devices_written ?? 0).toLocaleString()}
						</span>
					</div>
					<div class="flex justify-between items-center text-[11px]">
						<span>Disk footprint:</span>
						<span class="text-foreground font-medium font-mono">
							{formatBytes(systemStatus?.db?.size_bytes ?? 0)}
						</span>
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 4: Engine Health -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-muted-foreground">
				<span>Engine Health</span>
				{#if isHealthy}
					<CheckCircleIcon class="size-4 text-emerald-400" />
				{:else}
					<AlertTriangleIcon class="size-4 text-amber-400" />
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1.5 pt-1">
			{#if loading && !metrics}
				<Skeleton class="h-7 w-24" />
				<Skeleton class="mt-2 h-4 w-36" />
			{:else if isHealthy}
				<div class="text-xl font-bold text-emerald-500 flex items-center gap-2">
					<span>Optimal</span>
				</div>
				<div class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center text-[11px]">
						<span>Write errors:</span>
						<Badge variant="outline" class="text-[10px] px-1.5 py-0 h-4 border-emerald-500/30 text-emerald-500 font-mono">
							0 errors
						</Badge>
					</div>
					<span class="text-[11px] text-muted-foreground truncate mt-0.5">
						Clean persistent write lock
					</span>
				</div>
			{:else}
				<div class="text-xl font-bold text-amber-500 flex items-center gap-2">
					<span>Attention</span>
				</div>
				<div class="flex flex-col gap-0.5 border-t pt-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center text-[11px]">
						<span>Last status:</span>
						<span class="text-amber-500 font-medium">Write error detected</span>
					</div>
					<span class="text-[11px] text-muted-foreground truncate mt-0.5">
						Check daemon storage logs
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
