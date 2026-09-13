<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import ChevronLeftIcon from "@lucide/svelte/icons/chevron-left";
	import ChevronRightIcon from "@lucide/svelte/icons/chevron-right";
	import ChevronsLeftIcon from "@lucide/svelte/icons/chevrons-left";
	import ChevronsRightIcon from "@lucide/svelte/icons/chevrons-right";

	interface Props {
		pageIndex?: number;
		pageSize?: number;
		totalItems?: number;
		itemName?: string;
		pageSizeOptions?: number[];
		showPageSize?: boolean;
		disabled?: boolean;
		onPageChange?: (newPageIndex: number) => void;
		onPageSizeChange?: (newPageSize: number) => void;
	}

	let {
		pageIndex = $bindable(0),
		pageSize = $bindable(15),
		totalItems = 0,
		itemName = "items",
		pageSizeOptions = [10, 15, 25, 50],
		showPageSize = true,
		disabled = false,
		onPageChange,
		onPageSizeChange,
	}: Props = $props();

	const totalPages = $derived(Math.max(1, Math.ceil(totalItems / pageSize)));
	const startItem = $derived(totalItems > 0 ? pageIndex * pageSize + 1 : 0);
	const endItem = $derived(Math.min((pageIndex + 1) * pageSize, totalItems));

	function handlePage(idx: number) {
		const target = Math.max(0, Math.min(totalPages - 1, idx));
		pageIndex = target;
		onPageChange?.(target);
	}

	function handleSizeChange(e: Event) {
		const val = Number((e.target as HTMLSelectElement).value);
		pageSize = val;
		pageIndex = 0;
		onPageSizeChange?.(val);
		onPageChange?.(0);
	}
</script>

<div
	class="shrink-0 flex flex-col sm:flex-row sm:items-center sm:justify-between px-4 sm:px-6 py-2.5 border-t border-border/60 text-xs text-muted-foreground gap-3 bg-card"
>
	<!-- Left: Record summary -->
	<div class="flex items-center gap-2">
		<span class="text-[11px]">
			Showing <strong class="text-foreground font-semibold">{startItem}–{endItem}</strong> of{" "}
			<strong class="text-foreground font-semibold">{totalItems}</strong> {itemName}
		</span>
	</div>

	<!-- Right: Controls -->
	<div class="flex flex-wrap items-center gap-3">
		{#if showPageSize && totalItems > pageSizeOptions[0]}
			<div class="flex items-center gap-1.5 text-[11px]">
				<span>Rows:</span>
				<select
					value={pageSize}
					onchange={handleSizeChange}
					class="h-7 rounded-lg border border-input bg-background px-2 py-0.5 text-xs text-foreground outline-none focus:ring-1 focus:ring-ring cursor-pointer transition-colors"
					aria-label="Items per page"
				>
					{#each pageSizeOptions as size}
						<option value={size}>{size}</option>
					{/each}
				</select>
			</div>
		{/if}

		<span class="text-[11px] font-medium whitespace-nowrap">
			Page {pageIndex + 1} of {totalPages}
		</span>

		<div class="flex items-center gap-1">
			<Button
				variant="outline"
				size="icon"
				class="size-7 rounded-lg"
				disabled={pageIndex === 0 || disabled}
				onclick={() => handlePage(0)}
				title="First page"
			>
				<ChevronsLeftIcon class="size-3.5" />
			</Button>
			<Button
				variant="outline"
				size="icon"
				class="size-7 rounded-lg"
				disabled={pageIndex === 0 || disabled}
				onclick={() => handlePage(pageIndex - 1)}
				title="Previous page"
			>
				<ChevronLeftIcon class="size-3.5" />
			</Button>
			<Button
				variant="outline"
				size="icon"
				class="size-7 rounded-lg"
				disabled={pageIndex >= totalPages - 1 || disabled}
				onclick={() => handlePage(pageIndex + 1)}
				title="Next page"
			>
				<ChevronRightIcon class="size-3.5" />
			</Button>
			<Button
				variant="outline"
				size="icon"
				class="size-7 rounded-lg"
				disabled={pageIndex >= totalPages - 1 || disabled}
				onclick={() => handlePage(totalPages - 1)}
				title="Last page"
			>
				<ChevronsRightIcon class="size-3.5" />
			</Button>
		</div>
	</div>
</div>
