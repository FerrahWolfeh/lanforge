<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import InfoPopover from "./InfoPopover.svelte";
	import StatusBadge from "./StatusBadge.svelte";
	import type { Component, Snippet } from "svelte";

	let {
		label,
		value = null,
		subtext = "",
		icon: Icon,
		badge,
		popover,
		loading = false,
		valueExtra,
		actions,
		footer,
		children,
	}: {
		label: string;
		value?: string | number | null;
		subtext?: string;
		icon?: Component<{ class?: string }>;
		badge?: { text: string; variant?: string; showDot?: boolean; pulse?: boolean };
		popover?: { title: string; description?: string };
		loading?: boolean;
		valueExtra?: Snippet;
		actions?: Snippet;
		footer?: Snippet;
		children?: Snippet;
	} = $props();
</script>

<Card.Root
	class="group relative overflow-hidden max-sm:py-0 transition-colors duration-200 rounded-lg bg-card border border-border flex flex-col justify-between"
>
	<Card.Content class="flex flex-col gap-3 p-4 sm:p-5 h-full justify-between">
		<!-- Top Row: Label, Popover, Badge / Icon -->
		<div class="flex items-center justify-between gap-2 min-w-0">
			<div class="flex items-center gap-1.5 min-w-0">
				<span class="text-muted-foreground text-xs font-medium truncate">
					{label}
				</span>
				{#if popover}
					<InfoPopover title={popover.title} description={popover.description} />
				{/if}
			</div>

			<div class="flex items-center gap-2 shrink-0">
				{#if badge}
					<StatusBadge
						text={badge.text}
						variant={badge.variant ?? "outline"}
						showDot={badge.showDot}
						pulse={badge.pulse}
					/>
				{/if}

				{#if Icon}
					<div
						class="flex size-8 items-center justify-center rounded-md border shrink-0 bg-muted border-transparent text-muted-foreground"
					>
						<Icon class="size-4" />
					</div>
				{/if}
			</div>
		</div>

		<!-- Main Value Section -->
		{#if loading}
			<div class="flex flex-col gap-1.5 my-1">
				<Skeleton class="h-8 w-28" />
				<Skeleton class="h-3.5 w-36" />
			</div>
		{:else if valueExtra}
			<div class="my-0.5">
				{@render valueExtra()}
			</div>
		{:else}
			<div class="flex flex-col gap-0.5 my-0.5 min-w-0">
				{#if value !== null && value !== undefined}
					<span
						class="text-foreground text-2xl font-semibold tabular-nums tracking-tight truncate"
						title={String(value)}
					>
						{value}
					</span>
				{/if}

				{#if subtext}
					<span class="text-muted-foreground text-xs font-medium truncate" title={subtext}>
						{subtext}
					</span>
				{/if}
			</div>
		{/if}

		{#if actions}
			<div class="mt-1">
				{@render actions()}
			</div>
		{/if}

		{#if children}
			{@render children()}
		{/if}

		<!-- Subdivided Footer Grid -->
		{#if footer}
			<div class="border-t border-border/40 pt-2.5 mt-2 grid grid-cols-2 gap-x-3 gap-y-1.5">
				{@render footer()}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
