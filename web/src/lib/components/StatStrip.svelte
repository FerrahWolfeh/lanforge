<script lang="ts" module>
	import type { Component } from "svelte";

	export interface StatStripItem {
		label: string;
		/** null while loading (a skeleton is drawn). */
		value: string | number | null;
		/** "of N": shown small after the value, e.g. 5 of 151. */
		of?: string | number;
		icon?: Component<{ class?: string }>;
		/** 0..1: draws a usage bar under the label. */
		bar?: number;
		/** Bar colour: brand gradient by default; "danger" for adblock blocks, "warning" for a nearly full pool. */
		barTone?: "brand" | "danger" | "warning";
		href?: string;
		/** Value colour when the number itself is a state. */
		tone?: "warning" | "danger";
	}
</script>

<script lang="ts">
	import { cn } from "$lib/utils";
	import { Skeleton } from "$lib/components/ui/skeleton";

	/**
	 * A row of figures that replaces the old stat-card grids: one bordered strip, cells split by
	 * thin rules, an optional bar where a figure is "x of y". Wraps to two columns on phones.
	 */
	let { items, class: className = "" }: { items: StatStripItem[]; class?: string } = $props();

	const cols = $derived(
		items.length >= 5 ? "sm:grid-cols-5" : items.length === 4 ? "sm:grid-cols-4" : items.length === 3 ? "sm:grid-cols-3" : items.length === 2 ? "sm:grid-cols-2" : "sm:grid-cols-1"
	);
	const fmt = (v: string | number) => (typeof v === "number" ? v.toLocaleString() : v);
</script>

<div
	class={cn(
		"grid grid-cols-2 overflow-hidden rounded-lg border border-border bg-card",
		cols,
		className
	)}
>
	{#each items as item, i (item.label)}
		{@const Icon = item.icon}
		<svelte:element
			this={item.href ? "a" : "div"}
			href={item.href}
			class={cn(
				"flex min-w-0 flex-col gap-1 border-border px-4 py-3",
				// rules between cells: right edge except the row's last, bottom edge on the first row of the phone grid
				"border-r [&:nth-child(2n)]:border-r-0 sm:[&:nth-child(2n)]:border-r sm:last:border-r-0",
				items.length > 2 && i < 2 ? "border-b sm:border-b-0" : "",
				item.href ? "transition-colors hover:bg-accent/50" : ""
			)}
		>
			{#if item.value === null}
				<Skeleton class="h-6 w-16" />
			{:else}
				<span
					class={cn(
						"truncate text-lg font-semibold tabular-nums",
						item.tone === "warning" ? "text-warning" : item.tone === "danger" ? "text-danger" : "text-foreground"
					)}
				>
					{fmt(item.value)}{#if item.of !== undefined}<span class="text-xs font-normal text-muted-foreground"> / {fmt(item.of)}</span>{/if}
				</span>
			{/if}
			<span class="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
				{#if Icon}<Icon class="size-3.5 shrink-0" />{/if}
				<span class="line-clamp-2 sm:line-clamp-1">{item.label}</span>
			</span>
			{#if item.bar !== undefined}
				<span class="mt-0.5 block h-1 overflow-hidden rounded-full bg-muted" aria-hidden="true">
					<span
						class={cn(
							"block h-full rounded-full",
							item.barTone === "danger" ? "bg-danger" : item.barTone === "warning" ? "bg-warning" : "bg-brand-gradient"
						)}
						style={`width: ${Math.min(100, Math.max(item.bar > 0 ? 2 : 0, item.bar * 100))}%`}
					></span>
				</span>
			{/if}
		</svelte:element>
	{/each}
</div>
