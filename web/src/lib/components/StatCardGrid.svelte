<script lang="ts">
	import { cn } from "$lib/utils";
	import type { Snippet } from "svelte";

	let {
		cols = 4,
		class: className = "",
		children,
	}: {
		cols?: 2 | 3 | 4 | 5;
		class?: string;
		children?: Snippet;
	} = $props();

	const gridColsClass = $derived.by(() => {
		switch (cols) {
			case 2:
				return "grid-cols-1 sm:grid-cols-2";
			case 3:
				return "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3";
			case 5:
				return "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5";
			case 4:
			default:
				return "grid-cols-1 sm:grid-cols-2 lg:grid-cols-4";
		}
	});
</script>

<!-- Phones: three or more cards become one swipeable row with the next card peeking, so they
     do not push the page content several screens down; two cards simply stack. -->
<div
	class={cn(
		"grid gap-3.5 sm:gap-4",
		gridColsClass,
		cols >= 3 &&
			"max-sm:-mx-3 max-sm:flex max-sm:snap-x max-sm:snap-mandatory max-sm:overflow-x-auto max-sm:scroll-px-3 max-sm:px-3 max-sm:pb-1 max-sm:[scrollbar-width:none] max-sm:*:w-[85%] max-sm:*:shrink-0 max-sm:*:snap-start",
		className
	)}
>
	{#if children}
		{@render children()}
	{/if}
</div>
