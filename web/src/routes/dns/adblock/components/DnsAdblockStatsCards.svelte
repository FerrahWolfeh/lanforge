<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import PercentIcon from "@lucide/svelte/icons/percent";
	import type { DnsAdblockStatusResponse, DnsStatsResponse } from "$lib/api/types";

	let {
		loading = false,
		status = null,
		stats = null,
		sourceCount = 0,
	}: {
		loading?: boolean;
		status?: DnsAdblockStatusResponse | null;
		stats?: DnsStatsResponse | null;
		sourceCount?: number;
	} = $props();

	const blocklistDomains = $derived(status?.blocklist_size ?? 0);
	const allowlistDomains = $derived(status?.allowlist_size ?? 0);
	const totalQueries = $derived(stats?.total_requests ?? 0);
	const blockedQueries = $derived(stats?.blocked_queries ?? 0);

	const blockPercentage = $derived.by(() => {
		if (totalQueries === 0) return 0;
		return ((blockedQueries / totalQueries) * 100).toFixed(1);
	});
	const exceptionsDomains = $derived(status?.exceptions_size ?? 0);
	const totalAllowedOrExceptions = $derived(allowlistDomains + exceptionsDomains);
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Total Blocklist Domains -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2">
			<Card.Title class="text-sm font-medium">Domains on Blocklist</Card.Title>
			<DatabaseIcon class="size-4 text-primary" />
		</Card.Header>
		<Card.Content>
			{#if loading && !status}
				<Skeleton class="h-8 w-28 mb-1" />
				<Skeleton class="h-3 w-36" />
			{:else}
				<div class="text-2xl font-bold tracking-tight">
					{blocklistDomains.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Compiled in zero-copy FST ({sourceCount} remote {sourceCount === 1 ? "source" : "sources"})
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Blocked Queries -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2">
			<Card.Title class="text-sm font-medium">Queries Blocked</Card.Title>
			<ShieldAlertIcon class="size-4 text-rose-500" />
		</Card.Header>
		<Card.Content>
			{#if loading && !stats}
				<Skeleton class="h-8 w-28 mb-1" />
				<Skeleton class="h-3 w-36" />
			{:else}
				<div class="text-2xl font-bold tracking-tight text-rose-500 dark:text-rose-400">
					{blockedQueries.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Out of {totalQueries.toLocaleString()} total DNS requests
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Block Percentage -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2">
			<Card.Title class="text-sm font-medium">Block Percentage</Card.Title>
			<PercentIcon class="size-4 text-amber-500" />
		</Card.Header>
		<Card.Content>
			{#if loading && !stats}
				<Skeleton class="h-8 w-28 mb-1" />
				<Skeleton class="h-3 w-36" />
			{:else}
				<div class="text-2xl font-bold tracking-tight">
					{blockPercentage}%
				</div>
				<div class="w-full bg-muted rounded-full h-1.5 mt-2.5 overflow-hidden">
					<div
						class="bg-rose-500 h-1.5 rounded-full transition-all duration-500"
						style="width: {Math.min(100, Math.max(0, Number(blockPercentage)))}%"
					></div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Allowlist & @@ Exceptions -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="flex flex-row items-center justify-between pb-2">
			<Card.Title class="text-sm font-medium">Exceptions & Allowlist</Card.Title>
			<ShieldCheckIcon class="size-4 text-emerald-500" />
		</Card.Header>
		<Card.Content>
			{#if loading && !status}
				<Skeleton class="h-8 w-28 mb-1" />
				<Skeleton class="h-3 w-36" />
			{:else}
				<div class="text-2xl font-bold tracking-tight text-emerald-600 dark:text-emerald-400">
					{totalAllowedOrExceptions.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					{#if exceptionsDomains > 0}
						{allowlistDomains.toLocaleString()} manual, {exceptionsDomains.toLocaleString()} list @@ rules
					{:else}
						Whitelisted domains taking precedence
					{/if}
				</p>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
