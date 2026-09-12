<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ServerIcon from "@lucide/svelte/icons/server";

	let {
		loading = false,
		totalConfiguredCount = 0,
		v4PoolsCount = 0,
		v6PoolsCount = 0,
		totalManagedAddresses = 0,
		totalUsedAddresses = 0,
		totalAvailableAddresses = 0,
		aggregateUtilization = 0,
	}: {
		loading?: boolean;
		totalConfiguredCount?: number;
		v4PoolsCount?: number;
		v6PoolsCount?: number;
		totalManagedAddresses?: number;
		totalUsedAddresses?: number;
		totalAvailableAddresses?: number;
		aggregateUtilization?: number;
	} = $props();

	function getUtilizationStyles(pct: number) {
		if (pct >= 90) {
			return {
				bar: "bg-rose-500",
				badge: "text-rose-400 border-rose-500/30 bg-rose-500/10",
				label: "Critical",
			};
		}
		if (pct >= 75) {
			return {
				bar: "bg-amber-500",
				badge: "text-amber-400 border-amber-500/30 bg-amber-500/10",
				label: "Elevated",
			};
		}
		return {
			bar: "bg-emerald-500",
			badge: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
			label: "Healthy",
		};
	}
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Card 1: Configured Scopes -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Configured Scopes
				</span>
				<div class="bg-blue-500/10 border-blue-500/20 text-blue-400 flex size-8 items-center justify-center rounded-lg border">
					<LayersIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-16" />
				<Skeleton class="h-4 w-32" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span class="text-foreground text-2xl font-bold font-mono tracking-tight">
						{totalConfiguredCount}
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						{v4PoolsCount} IPv4 / {v6PoolsCount} IPv6 pools
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 2: Total Managed IPs -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Managed Capacity
				</span>
				<div class="bg-emerald-500/10 border-emerald-500/20 text-emerald-400 flex size-8 items-center justify-center rounded-lg border">
					<NetworkIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-20" />
				<Skeleton class="h-4 w-28" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span class="text-foreground text-2xl font-bold font-mono tracking-tight">
						{totalManagedAddresses.toLocaleString()} IPs
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						Across all active ranges
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 3: Active Leases in Use -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Active Leases
				</span>
				<div class="bg-purple-500/10 border-purple-500/20 text-purple-400 flex size-8 items-center justify-center rounded-lg border">
					<ActivityIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-20" />
				<Skeleton class="h-4 w-28" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span class="text-foreground text-2xl font-bold font-mono tracking-tight">
						{totalUsedAddresses}
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						{totalAvailableAddresses} available for clients
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 4: Aggregate Utilization -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Global Utilization
				</span>
				<div class="bg-amber-500/10 border-amber-500/20 text-amber-400 flex size-8 items-center justify-center rounded-lg border">
					<ServerIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-20" />
				<Skeleton class="h-4 w-28" />
			{:else}
				{@const style = getUtilizationStyles(aggregateUtilization)}
				<div class="flex flex-col gap-1.5">
					<div class="flex items-center justify-between">
						<span class="text-foreground text-2xl font-bold font-mono tracking-tight">
							{aggregateUtilization}%
						</span>
						<Badge variant="outline" class={`text-[10px] font-semibold ${style.badge}`}>
							{style.label}
						</Badge>
					</div>
					<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted">
						<div
							class={`h-full ${style.bar} transition-all duration-500`}
							style={`width: ${Math.min(100, Math.max(0, aggregateUtilization))}%`}
						></div>
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
