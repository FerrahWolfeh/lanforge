<script lang="ts">
	import * as Popover from "$lib/components/ui/popover";
	import InfoIcon from "@lucide/svelte/icons/info";
	import type { Snippet } from "svelte";

	let {
		title = "",
		text = "",
		description = "",
		children,
	}: {
		title?: string;
		text?: string;
		description?: string;
		children?: Snippet;
	} = $props();

	const body = $derived(text || description);
</script>

<Popover.Root>
	<Popover.Trigger
		class="inline-flex size-4 items-center justify-center rounded-full text-muted-foreground/70 hover:text-foreground hover:bg-muted/50 transition-colors cursor-pointer shrink-0 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
		aria-label={title || body || "Information"}
	>
		<InfoIcon class="size-3" />
	</Popover.Trigger>
	<Popover.Content
		class="w-64 sm:w-72 p-3 text-xs flex flex-col gap-1.5 shadow-lg border border-border/70 bg-popover text-popover-foreground z-50 rounded-lg"
		side="top"
		align="center"
	>
		{#if title}
			<div class="flex items-center gap-1.5 font-semibold text-foreground text-xs">
				<InfoIcon class="size-3.5 text-muted-foreground shrink-0" />
				<span>{title}</span>
			</div>
		{/if}
		{#if body}
			<p class="text-muted-foreground text-xs leading-relaxed">
				{body}
			</p>
		{/if}
		{#if children}
			<div class="flex flex-col gap-1.5 pt-0.5 text-xs">
				{@render children()}
			</div>
		{/if}
	</Popover.Content>
</Popover.Root>
