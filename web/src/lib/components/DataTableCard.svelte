<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import SearchIcon from "@lucide/svelte/icons/search";
	import DataTablePagination from "$lib/components/DataTablePagination.svelte";
	import { cn } from "$lib/utils";
	import type { Snippet, Component } from "svelte";

	interface Props {
		title: string;
		icon?: Component<{ class?: string }>;
		titleExtra?: Snippet;
		description?: string;
		itemName?: string;
		total?: number;
		searchQuery?: string;
		searchPlaceholder?: string;
		showSearch?: boolean;
		loading?: boolean;
		isEmpty?: boolean;
		columns?: number;
		skeletonRows?: number;
		emptyMessage?: string;
		emptyFilteredMessage?: string;
		emptyAction?: Snippet;
		minTableWidth?: string;
		containerHeight?: string;
		showPagination?: boolean;
		pageIndex?: number;
		pageSize?: number;
		pageSizeOptions?: number[];
		showPageSize?: boolean;
		class?: string;
		header?: Snippet;
		filters?: Snippet;
		actions?: Snippet;
		empty?: Snippet;
		skeleton?: Snippet;
		children?: Snippet;
		onSearchChange?: (query: string) => void;
		onPageChange?: (newPageIndex: number) => void;
		onPageSizeChange?: (newPageSize: number) => void;
	}

	let {
		title,
		icon: Icon,
		titleExtra,
		description,
		itemName = "items",
		total = 0,
		searchQuery = $bindable(""),
		searchPlaceholder = "Search...",
		showSearch = true,
		loading = false,
		isEmpty: customIsEmpty,
		columns = 5,
		skeletonRows = 6,
		emptyMessage,
		emptyFilteredMessage,
		emptyAction,
		minTableWidth = "min-w-[750px]",
		containerHeight = "h-[calc(100vh-250px)] min-h-[480px] max-h-[750px]",
		showPagination = true,
		pageIndex = $bindable(0),
		pageSize = $bindable(50),
		pageSizeOptions = [10, 15, 25, 50],
		showPageSize = true,
		class: className = "",
		header,
		filters,
		actions,
		empty,
		skeleton,
		children,
		onSearchChange,
		onPageChange,
		onPageSizeChange,
	}: Props = $props();

	const isAutoHeight = $derived(
		containerHeight === "h-auto" || containerHeight === "auto" || containerHeight === ""
	);
	const isEmpty = $derived(customIsEmpty !== undefined ? customIsEmpty : total === 0);
	const startItem = $derived(total === 0 ? 0 : pageIndex * pageSize + 1);
	const endItem = $derived(Math.min((pageIndex + 1) * pageSize, total));
	const autoDescription = $derived(
		showPagination
			? `Showing ${startItem}–${endItem} of ${total.toLocaleString()} ${itemName}`
			: total > 0
				? `${total.toLocaleString()} ${itemName}`
				: ""
	);
	const displayDescription = $derived(
		description !== undefined ? description : autoDescription
	);
</script>

<Card.Root
	class={cn(
		"flex flex-col overflow-hidden border shadow-sm",
		containerHeight,
		className
	)}
>
	<!-- Card Header with Title, Description, and Controls Toolbar -->
	<Card.Header class="pb-3 shrink-0 border-b bg-card">
		<div
			class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
		>
			<!-- Title & Auto Description -->
			<div>
				<div class="flex items-center gap-2 flex-wrap">
					<Card.Title class="text-base font-semibold flex items-center gap-2">
						{#if Icon}
							<Icon class="h-4 w-4 text-primary shrink-0" />
						{/if}
						<span>{title}</span>
					</Card.Title>
					{#if titleExtra}
						{@render titleExtra()}
					{/if}
				</div>
				{#if displayDescription}
					<Card.Description class="text-xs">
						{displayDescription}
					</Card.Description>
				{/if}
			</div>

			<!-- Search, Filters, and Actions Toolbar -->
			{#if showSearch || filters || actions}
				<div class="flex flex-wrap items-center gap-2">
					{#if showSearch}
						<div class="relative w-full sm:w-60">
							<SearchIcon
								class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground"
							/>
							<Input
								type="text"
								placeholder={searchPlaceholder}
								class="pl-9 h-9 text-xs"
								bind:value={searchQuery}
								oninput={(e: Event) =>
									onSearchChange?.((e.target as HTMLInputElement).value)}
							/>
						</div>
					{/if}

					{#if filters}
						{@render filters()}
					{/if}

					{#if actions}
						{@render actions()}
					{/if}
				</div>
			{/if}
		</div>
	</Card.Header>

	<!-- Table Body with Scroll Container -->
	<Card.Content
		class={cn(
			"p-0 relative",
			isAutoHeight ? "overflow-x-auto" : "flex-1 min-h-0 overflow-auto"
		)}
	>
		<Table.Root class={minTableWidth}>
			<Table.Header
				class="sticky top-0 z-10 bg-card/95 backdrop-blur-md border-b shadow-xs"
			>
				<Table.Row class="hover:bg-transparent">
					{#if header}
						{@render header()}
					{/if}
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#if loading && isEmpty}
					{#if skeleton}
						{@render skeleton()}
					{:else}
						{#each Array(skeletonRows) as _}
							<Table.Row>
								{#each Array(columns) as _, colIdx}
									<Table.Cell class={colIdx === columns - 1 ? "text-right" : ""}>
										<Skeleton
											class="h-4 {colIdx === 0
												? 'w-20'
												: colIdx === 1
													? 'w-36'
													: 'w-24'} {colIdx === columns - 1 ? 'ml-auto' : ''}"
										/>
									</Table.Cell>
								{/each}
							</Table.Row>
						{/each}
					{/if}
				{:else if isEmpty}
					{#if empty}
						{@render empty()}
					{:else}
						<Table.Row class="hover:bg-transparent">
							<Table.Cell
								colspan={columns}
								class={cn(
									"text-center text-muted-foreground text-sm",
									isAutoHeight ? "py-12" : "h-48"
								)}
							>
								<div class="flex flex-col items-center justify-center text-center p-4">
									{#if Icon}
										<Icon class="size-8 text-muted-foreground/40 mb-2" />
									{/if}
									<p class="text-xs sm:text-sm font-medium text-foreground">
										{#if searchQuery.trim()}
											{emptyFilteredMessage ??
												`No ${itemName} match the active filter criteria.`}
										{:else}
											{emptyMessage ?? `No ${itemName} have been found.`}
										{/if}
									</p>
									{#if emptyAction}
										<div class="mt-3">
											{@render emptyAction()}
										</div>
									{/if}
								</div>
							</Table.Cell>
						</Table.Row>
					{/if}
				{:else}
					{@render children?.()}
				{/if}
			</Table.Body>
		</Table.Root>
	</Card.Content>

	<!-- Fixed Pinned Pagination Footer -->
	{#if showPagination}
		<DataTablePagination
			bind:pageIndex
			bind:pageSize
			totalItems={total}
			{itemName}
			{pageSizeOptions}
			{showPageSize}
			disabled={loading}
			{onPageChange}
			{onPageSizeChange}
		/>
	{/if}
</Card.Root>
