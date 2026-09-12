<script lang="ts">
	import * as Popover from "$lib/components/ui/popover";
	import HelpCircleIcon from "@lucide/svelte/icons/help-circle";
	import type { Snippet } from "svelte";
	import { cn } from "$lib/utils";

	let {
		title = "",
		description = "",
		trigger,
		children,
		side = "bottom" as "top" | "right" | "bottom" | "left",
		align = "start" as "start" | "center" | "end",
		class: triggerClass = "",
		contentClass = "",
	}: {
		title?: string;
		description?: string;
		trigger?: Snippet;
		children?: Snippet;
		side?: "top" | "right" | "bottom" | "left";
		align?: "start" | "center" | "end";
		class?: string;
		contentClass?: string;
	} = $props();
</script>

<Popover.Root>
	<Popover.Trigger
		class={cn(
			"inline-flex size-5 items-center justify-center rounded-full text-muted-foreground/80 hover:text-foreground hover:bg-muted/60 transition-colors cursor-pointer shrink-0 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
			triggerClass,
		)}
		aria-label={title || "More information"}
	>
		{#if trigger}
			{@render trigger()}
		{:else}
			<HelpCircleIcon class="size-3.5" />
		{/if}
	</Popover.Trigger>
	<Popover.Content
		class={cn(
			"w-80 sm:w-96 p-4 text-xs flex flex-col gap-2.5 shadow-xl border border-border/70 bg-popover text-popover-foreground z-50",
			contentClass,
		)}
		{side}
		{align}
	>
		{#if title}
			<div class="flex items-center gap-1.5 font-semibold text-foreground text-sm border-b pb-2 border-border/40">
				<HelpCircleIcon class="size-4 text-primary shrink-0" />
				<span>{title}</span>
			</div>
		{/if}
		{#if description}
			<p class="text-muted-foreground leading-relaxed text-xs">
				{description}
			</p>
		{/if}
		{#if children}
			<div class="flex flex-col gap-2 pt-1 text-xs">
				{@render children()}
			</div>
		{/if}
	</Popover.Content>
</Popover.Root>
