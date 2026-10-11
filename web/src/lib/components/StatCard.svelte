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

	const colorStyles = $derived.by(() => {
		switch (color) {
			case "emerald":
				return {
					box: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
					text: "text-emerald-400",
					defaultSparkline: "#10b981",
				};
			case "sky":
				return {
					box: "bg-sky-500/10 border-sky-500/20 text-sky-400",
					text: "text-sky-400",
					defaultSparkline: "#0ea5e9",
				};
			case "indigo":
				return {
					box: "bg-indigo-500/10 border-indigo-500/20 text-indigo-400",
					text: "text-indigo-400",
					defaultSparkline: "#6366f1",
				};
			case "teal":
				return {
					box: "bg-teal-500/10 border-teal-500/20 text-teal-400",
					text: "text-teal-400",
					defaultSparkline: "#14b8a6",
				};
			case "violet":
				return {
					box: "bg-violet-500/10 border-violet-500/20 text-violet-400",
					text: "text-violet-400",
					defaultSparkline: "#8b5cf6",
				};
			case "amber":
				return {
					box: "bg-amber-500/10 border-amber-500/20 text-amber-400",
					text: "text-amber-400",
					defaultSparkline: "#f59e0b",
				};
			case "rose":
				return {
					box: "bg-rose-500/10 border-rose-500/20 text-rose-400",
					text: "text-rose-400",
					defaultSparkline: "#f43f5e",
				};
			case "zinc":
				return {
					box: "bg-zinc-500/10 border-zinc-500/20 text-zinc-400",
					text: "text-zinc-400",
					defaultSparkline: "#71717a",
				};
			case "primary":
			default:
				return {
					box: "bg-primary/10 border-primary/20 text-primary",
					text: "text-primary",
					defaultSparkline: "hsl(var(--primary))",
				};
		}
	});
</script>

<Card.Root
	class={cn(
		"relative overflow-hidden transition-all hover:border-zinc-700/80 rounded-xl bg-card border border-border/60 shadow-xs flex flex-col justify-between",
		href ? "cursor-pointer group" : "",
		className
	)}
>
	<Card.Content class="flex flex-col gap-3 p-4 sm:p-5 h-full justify-between">
		<!-- Top Row: Label, Popover, Badge / Icon -->
		<div class="flex items-center justify-between gap-2 min-w-0">
			<div class="flex items-center gap-1.5 min-w-0">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider truncate">
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
							"flex size-8 items-center justify-center rounded-lg border shrink-0 transition-transform",
							colorStyles.box,
							href ? "group-hover:scale-105" : ""
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
						class="text-foreground text-2xl sm:text-3xl font-bold tabular-nums tracking-tight truncate"
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
