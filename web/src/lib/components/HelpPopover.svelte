<script lang="ts">
	import * as Popover from "$lib/components/ui/popover";
	import HelpCircleIcon from "@lucide/svelte/icons/help-circle";
	import type { Snippet } from "svelte";
	import { cn } from "$lib/utils";

	let {
		title = "",
		description = "",
		children,
		contentClass = "",
	}: {
		title?: string;
		description?: string;
		children?: Snippet;
		contentClass?: string;
	} = $props();
</script>

<Popover.Root>
	<Popover.Trigger
		class="inline-flex size-5 items-center justify-center rounded-full text-muted-foreground/80 hover:text-foreground hover:bg-muted/60 transition-colors cursor-pointer shrink-0 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
		aria-label={title || "More information"}
	>
		<HelpCircleIcon class="size-3.5" />
	</Popover.Trigger>
	<Popover.Content
		class={cn("w-80 sm:w-96 p-4 text-xs flex flex-col gap-2.5 shadow-xl border border-border/70 bg-popover text-popover-foreground z-50", contentClass)}
		side="bottom"
		align="start"
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
