<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import type { Component } from "svelte";

	interface InventoryItem {
		id: string;
		title: string;
		icon: Component<{ class?: string }>;
		/** null: not readable for this session (users and tokens are admin-only). */
		count: number | null;
		unit: string;
		route: string;
		description: string;
	}

	let {
		inventoryItems = [],
		isInMemory = false,
		loading = false,
	}: {
		inventoryItems?: InventoryItem[];
		isInMemory?: boolean;
		loading?: boolean;
	} = $props();
</script>

<Card.Root class="gap-0 py-0">
	<div class="flex flex-col gap-0.5 border-b px-4 py-3">
		<span class="text-sm font-semibold">What is stored</span>
		<span class="text-xs text-muted-foreground">
			State only: configuration lives in lanforge.toml, not in the database.
			{#if isInMemory}<span class="text-warning">This instance keeps it in memory: it is lost on restart.</span>{/if}
		</span>
	</div>
	<div class="flex flex-col divide-y divide-border">
		{#each inventoryItems as item (item.id)}
			{@const Icon = item.icon}
			<a href={item.route} class="flex items-center gap-3 px-4 py-3 transition-colors hover:bg-accent/40 min-w-0">
				<Icon class="size-4 shrink-0 text-muted-foreground" />
				<span class="flex min-w-0 flex-1 flex-col">
					<span class="text-sm font-medium text-foreground">{item.title}</span>
					<span class="truncate text-xs text-muted-foreground">{item.description}</span>
				</span>
				{#if loading && item.count === null}
					<Skeleton class="h-4 w-16" />
				{:else}
					<span class="text-sm tabular-nums text-foreground">
						{item.count === null ? "—" : item.count.toLocaleString()}
						<span class="text-xs text-muted-foreground">{item.unit}</span>
					</span>
				{/if}
				<ArrowRightIcon class="size-3.5 shrink-0 text-muted-foreground" />
			</a>
		{/each}
	</div>
</Card.Root>
