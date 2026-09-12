<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ClockIcon from "@lucide/svelte/icons/clock";

	let {
		loading = false,
		totalCount = 0,
		v4Count = 0,
		v6Count = 0,
		expiringSoonCount = 0,
	}: {
		loading?: boolean;
		totalCount?: number;
		v4Count?: number;
		v6Count?: number;
		expiringSoonCount?: number;
	} = $props();
</script>

<div class="grid grid-cols-2 lg:grid-cols-4 gap-3">
	<!-- Total Leases -->
	<Card.Root>
		<Card.Header class="flex flex-row items-center justify-between pb-2 p-3 sm:p-4">
			<Card.Title class="text-xs font-medium text-muted-foreground">
				Total Leases
			</Card.Title>
			<NetworkIcon class="size-3.5 sm:size-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content class="p-3 sm:p-4 pt-0">
			{#if loading}
				<Skeleton class="h-7 w-12" />
			{:else}
				<div class="text-xl sm:text-2xl font-bold font-mono">{totalCount}</div>
				<p class="text-[11px] text-muted-foreground mt-0.5 hidden sm:block">
					Dynamic IPv4 & IPv6 allocations
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- IPv4 Leases -->
	<Card.Root>
		<Card.Header class="flex flex-row items-center justify-between pb-2 p-3 sm:p-4">
			<Card.Title class="text-xs font-medium text-muted-foreground">
				IPv4 Leases
			</Card.Title>
			<Badge variant="secondary" class="text-[10px] px-1.5 py-0 font-mono">
				v4
			</Badge>
		</Card.Header>
		<Card.Content class="p-3 sm:p-4 pt-0">
			{#if loading}
				<Skeleton class="h-7 w-12" />
			{:else}
				<div class="text-xl sm:text-2xl font-bold font-mono text-emerald-400">{v4Count}</div>
				<p class="text-[11px] text-muted-foreground mt-0.5 hidden sm:block">
					Standard RFC 2131 dynamic pools
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- IPv6 Leases -->
	<Card.Root>
		<Card.Header class="flex flex-row items-center justify-between pb-2 p-3 sm:p-4">
			<Card.Title class="text-xs font-medium text-muted-foreground">
				DHCPv6 & PD
			</Card.Title>
			<GlobeIcon class="size-3.5 sm:size-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content class="p-3 sm:p-4 pt-0">
			{#if loading}
				<Skeleton class="h-7 w-12" />
			{:else}
				<div class="text-xl sm:text-2xl font-bold font-mono text-sky-400">{v6Count}</div>
				<p class="text-[11px] text-muted-foreground mt-0.5 hidden sm:block">
					IA_NA addresses & IA_PD prefixes
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Expiring Soon -->
	<Card.Root>
		<Card.Header class="flex flex-row items-center justify-between pb-2 p-3 sm:p-4">
			<Card.Title class="text-xs font-medium text-muted-foreground">
				Expiring Soon
			</Card.Title>
			<ClockIcon class="size-3.5 sm:size-4 text-amber-500" />
		</Card.Header>
		<Card.Content class="p-3 sm:p-4 pt-0">
			{#if loading}
				<Skeleton class="h-7 w-12" />
			{:else}
				<div class="flex items-center gap-1.5">
					<span class="text-xl sm:text-2xl font-bold font-mono text-foreground">
						{expiringSoonCount}
					</span>
					{#if expiringSoonCount > 0}
						<Badge variant="secondary" class="bg-amber-500/10 text-amber-500 text-[10px] px-1 py-0 font-mono">
							&lt; 1h
						</Badge>
					{/if}
				</div>
				<p class="text-[11px] text-muted-foreground mt-0.5 hidden sm:block">
					Leases requiring renewal soon
				</p>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
