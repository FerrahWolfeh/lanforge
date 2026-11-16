<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import SearchIcon from "@lucide/svelte/icons/search";
	import DataTablePagination from "$lib/components/DataTablePagination.svelte";
	import { cn } from "$lib/utils";
	import { IsMobile } from "$lib/hooks/is-mobile.svelte";
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
		/** Card list rendered instead of the table on phone-width screens. */
		mobile?: Snippet;
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
		// The card is as tall as its rows, capped near the viewport so the header and pager stay in
		// view. Phones get no cap: the page scrolls, not a box inside it.
		containerHeight = "md:max-h-[calc(100dvh-17rem)]",
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
		mobile,
		children,
		onSearchChange,
		onPageChange,
		onPageSizeChange,
	}: Props = $props();

	const isAutoHeight = $derived(
		containerHeight === "h-auto" || containerHeight === "auto" || containerHeight === ""
	);
	const isMobile = new IsMobile();
	const showMobile = $derived(mobile !== undefined && isMobile.current);
	let cardEl = $state<HTMLElement | null>(null);

	// On a phone the next page's first row sits a screen above the pager: go back up.
	function handlePageChange(newPageIndex: number) {
		if (showMobile) cardEl?.scrollIntoView({ block: "start" });
		onPageChange?.(newPageIndex);
	}

	const isEmpty = $derived(customIsEmpty !== undefined ? customIsEmpty : total === 0);
	// A wide table cuts its centered placeholder off on a phone: show it outside the table.
	const phonePlaceholder = $derived(isMobile.current && isEmpty);
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
	bind:ref={cardEl}
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
			isAutoHeight ? "overflow-x-auto" : "overflow-x-auto md:flex-1 md:min-h-0 md:overflow-auto"
		)}
	>
		{#if showMobile || phonePlaceholder}
			{#if loading && isEmpty}
				<div class="divide-y divide-border/60">
					{#each Array(skeletonRows) as _}
						<div class="flex flex-col gap-2 px-4 py-3">
							<Skeleton class="h-4 w-36" />
							<Skeleton class="h-3 w-48" />
						</div>
					{/each}
				</div>
			{:else if isEmpty}
				<div class="flex flex-col items-center justify-center text-center px-4 py-12">
					{#if Icon}
						<Icon class="size-8 text-muted-foreground/40 mb-2" />
					{/if}
					<p class="text-xs font-medium text-foreground">
						{#if searchQuery.trim()}
							{emptyFilteredMessage ?? `No ${itemName} match the active filter criteria.`}
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
			{:else}
				<div class="divide-y divide-border/60">
					{@render mobile?.()}
				</div>
			{/if}
		{:else}
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
		{/if}
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
			onPageChange={handlePageChange}
			{onPageSizeChange}
		/>
	{/if}
</Card.Root>
