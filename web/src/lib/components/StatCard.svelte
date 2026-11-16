<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { cn } from "$lib/utils";
	import InfoPopover from "./InfoPopover.svelte";
	import StatusBadge from "./StatusBadge.svelte";
	import Sparkline from "$lib/components/ui/sparkline.svelte";
	import type { Component, Snippet } from "svelte";

	export type StatCardColor =
		| "emerald"
		| "sky"
		| "indigo"
		| "teal"
		| "violet"
		| "amber"
		| "rose"
		| "primary"
		| "zinc";

	let {
		label,
		value = null,
		subtext = "",
		icon: Icon,
		color = "primary",
		badge,
		popover,
		sparkline,
		loading = false,
		href = "",
		footerCols = 2,
		class: className = "",
		headerRight,
		valueExtra,
		actions,
		footer,
		children,
	}: {
		label: string;
		value?: string | number | null;
		subtext?: string;
		icon?: Component<{ class?: string }>;
		color?: StatCardColor | string;
		badge?: { text: string; variant?: string; showDot?: boolean; pulse?: boolean };
		popover?: { title: string; description?: string };
		sparkline?: { data: number[]; color?: string; height?: number };
		loading?: boolean;
		href?: string;
		footerCols?: 2 | 3;
		class?: string;
		headerRight?: Snippet;
		valueExtra?: Snippet;
		actions?: Snippet;
		footer?: Snippet;
		children?: Snippet;
	} = $props();

	// Colour is for state only: amber/rose read as warning/danger, every other colour name is the
	// neutral icon chip (the names stay accepted so callers need not change at once).
	const colorStyles = $derived.by(() => {
		switch (color) {
			case "amber":
				return { box: "bg-warning/12 border-transparent text-warning", text: "text-warning", defaultSparkline: "var(--warning)" };
			case "rose":
				return { box: "bg-danger/12 border-transparent text-danger", text: "text-danger", defaultSparkline: "var(--danger)" };
			default:
				return { box: "bg-muted border-transparent text-muted-foreground", text: "text-foreground", defaultSparkline: "var(--chart-1)" };
		}
	});
</script>

<Card.Root
	class={cn(
		"group relative overflow-hidden max-sm:py-0 transition-colors duration-200 rounded-lg bg-card border border-border flex flex-col justify-between",
		href ? "cursor-pointer hover:border-primary/50" : "",
		className
	)}
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

				{#if headerRight}
					{@render headerRight()}
				{:else if Icon}
					<div
						class={cn(
							"flex size-8 items-center justify-center rounded-md border shrink-0",
							colorStyles.box
						)}
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

		<!-- Sparkline Slot -->
		{#if sparkline && sparkline.data?.length > 0}
			<div class="mt-2 pt-1 border-t border-border/40">
				<Sparkline
					data={sparkline.data}
					color={sparkline.color ?? colorStyles.defaultSparkline}
					height={sparkline.height ?? 26}
				/>
			</div>
		{/if}

		<!-- Subdivided Footer Grid -->
		{#if footer}
			<div
				class={cn(
					"border-t border-border/40 pt-2.5 mt-2 grid gap-x-3 gap-y-1.5",
					footerCols === 3 ? "grid-cols-3" : "grid-cols-2"
				)}
			>
				{@render footer()}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
