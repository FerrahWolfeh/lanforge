<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import FilterIcon from "@lucide/svelte/icons/filter";
	import type { DnsRecordType } from "$lib/api/types";

	let {
		loading = true,
		entriesByType = {},
		selectedType = "",
		onSelectType = (type: string) => {},
	}: {
		loading?: boolean;
		entriesByType?: Record<string, number>;
		selectedType?: string;
		onSelectType?: (type: string) => void;
	} = $props();

	const typeVariants: Record<string, string> = {
		A: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20 hover:bg-blue-500/20",
		AAAA: "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20 hover:bg-purple-500/20",
		CNAME: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20 hover:bg-amber-500/20",
		PTR: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/20",
		TXT: "bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20 hover:bg-slate-500/20",
		MX: "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20 hover:bg-rose-500/20",
		NS: "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/20 hover:bg-cyan-500/20",
		SOA: "bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20 hover:bg-indigo-500/20",
		SRV: "bg-teal-500/10 text-teal-600 dark:text-teal-400 border-teal-500/20 hover:bg-teal-500/20",
		HTTPS: "bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-500/20 hover:bg-violet-500/20",
		SVCB: "bg-fuchsia-500/10 text-fuchsia-600 dark:text-fuchsia-400 border-fuchsia-500/20 hover:bg-fuchsia-500/20",
	};

	const sortedTypes = $derived.by(() => {
		if (!entriesByType) return [];
		return Object.entries(entriesByType)
			.filter(([_, count]) => count > 0)
			.sort((a, b) => b[1] - a[1]);
	});

	const totalCount = $derived.by(() => {
		if (!entriesByType) return 0;
		return Object.values(entriesByType).reduce(
			(acc, curr) => acc + curr,
			0,
		);
	});
</script>

<Card.Root>
	<Card.Header
		class="flex flex-row items-center justify-between pb-3 space-y-0"
	>
		<div class="space-y-1">
			<Card.Title class="text-base font-semibold flex items-center gap-2">
				<FilterIcon class="h-4 w-4 text-primary" />
				Record Type Breakdown
			</Card.Title>
			<Card.Description class="text-xs">
				Distribution of record types currently held in memory
			</Card.Description>
		</div>
	</Card.Header>
	<Card.Content>
		{#if loading}
			<div class="flex flex-wrap gap-2">
				<Skeleton class="h-7 w-20 rounded-full" />
				<Skeleton class="h-7 w-24 rounded-full" />
				<Skeleton class="h-7 w-16 rounded-full" />
				<Skeleton class="h-7 w-28 rounded-full" />
			</div>
		{:else if sortedTypes.length === 0}
			<p class="text-xs text-muted-foreground italic py-2">
				No records in cache.
			</p>
		{:else}
			<div class="flex flex-wrap items-center gap-2">
				<!-- All Pill -->
				<button
					type="button"
					onclick={() => onSelectType("")}
					class="transition-all focus:outline-none"
				>
					<Badge
						variant={selectedType === "" ? "default" : "outline"}
						class="px-3 py-1 text-xs cursor-pointer font-medium"
					>
						All Types ({totalCount.toLocaleString()})
					</Badge>
				</button>

				{#each sortedTypes as [kind, count] (kind)}
					{@const style =
						typeVariants[kind] ||
						"bg-secondary text-secondary-foreground border-border"}
					{@const isSelected = selectedType === kind}
					<button
						type="button"
						onclick={() => onSelectType(isSelected ? "" : kind)}
						class="transition-all focus:outline-none"
					>
						<Badge
							variant="outline"
							class="px-3 py-1 text-xs cursor-pointer font-medium border flex items-center gap-1.5 transition-all {style} {isSelected
								? 'ring-2 ring-primary ring-offset-1 ring-offset-background font-bold'
								: 'opacity-90 hover:opacity-100'}"
						>
							<span>{kind}</span>
							<span class="opacity-75 font-normal text-[11px]"
								>({count.toLocaleString()})</span
							>
						</Badge>
					</button>
				{/each}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
