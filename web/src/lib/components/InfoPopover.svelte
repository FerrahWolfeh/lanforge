<script lang="ts">
	import * as Popover from "$lib/components/ui/popover";
	import InfoIcon from "@lucide/svelte/icons/info";
	import type { Snippet } from "svelte";
	import { cn } from "$lib/utils";

	let {
		title = "",
		text = "",
		description = "",
		trigger,
		children,
		side = "top" as "top" | "right" | "bottom" | "left",
		align = "center" as "start" | "center" | "end",
		class: triggerClass = "",
		contentClass = "",
	}: {
		title?: string;
		text?: string;
		description?: string;
		trigger?: Snippet;
		children?: Snippet;
		side?: "top" | "right" | "bottom" | "left";
		align?: "start" | "center" | "end";
		class?: string;
		contentClass?: string;
	} = $props();

	const body = $derived(text || description);
</script>

<Popover.Root>
	<Popover.Trigger
		class={cn(
			"inline-flex size-4 items-center justify-center rounded-full text-muted-foreground/70 hover:text-foreground hover:bg-muted/50 transition-colors cursor-pointer shrink-0 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
			triggerClass,
		)}
		aria-label={title || body || "Information"}
	>
		{#if trigger}
			{@render trigger()}
		{:else}
			<InfoIcon class="size-3" />
		{/if}
	</Popover.Trigger>
	<Popover.Content
		class={cn(
			"w-64 sm:w-72 p-3 text-xs flex flex-col gap-1.5 shadow-lg border border-border/70 bg-popover text-popover-foreground z-50 rounded-lg",
			contentClass,
		)}
		{side}
		{align}
	>
		{#if title}
			<div class="flex items-center gap-1.5 font-semibold text-foreground text-xs">
				<InfoIcon class="size-3.5 text-sky-500 shrink-0" />
				<span>{title}</span>
			</div>
		{/if}
		{#if body}
			<p class="text-muted-foreground text-[11px] leading-relaxed">
				{body}
			</p>
		{/if}
		{#if children}
			<div class="flex flex-col gap-1.5 pt-0.5 text-[11px]">
				{@render children()}
			</div>
		{/if}
	</Popover.Content>
</Popover.Root>
