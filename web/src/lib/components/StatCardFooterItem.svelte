<script lang="ts">
	import { cn } from "$lib/utils";
	import type { Snippet } from "svelte";

	let {
		label,
		value,
		color = "",
		title = "",
		mono = true,
		class: className = "",
		valueSnippet,
	}: {
		label: string;
		value?: string | number;
		color?: string;
		title?: string;
		mono?: boolean;
		class?: string;
		valueSnippet?: Snippet;
	} = $props();
</script>

<div class={cn("flex flex-col gap-0.5 min-w-0", className)} {title}>
	<span class="text-[11px] text-muted-foreground truncate">{label}</span>
	{#if valueSnippet}
		{@render valueSnippet()}
	{:else}
		<span
			class={cn(
				"text-[11px] font-medium truncate text-foreground",
				mono ? "font-mono" : "",
				color
			)}
		>
			{value ?? "—"}
		</span>
	{/if}
</div>
