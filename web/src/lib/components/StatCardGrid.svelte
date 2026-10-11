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

<div class={cn("grid gap-3.5 sm:gap-4", gridColsClass, className)}>
	{#if children}
		{@render children()}
	{/if}
</div>
