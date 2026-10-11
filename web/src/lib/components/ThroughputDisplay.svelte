<script lang="ts">
	import { cn, formatBps } from "$lib/utils";
	import ArrowDownIcon from "@lucide/svelte/icons/arrow-down";
	import ArrowUpIcon from "@lucide/svelte/icons/arrow-up";

	let {
		rxBps = 0,
		txBps = 0,
		size = "md",
		showIcons = true,
		class: className = "",
	}: {
		rxBps?: number;
		txBps?: number;
		size?: "sm" | "md" | "lg";
		showIcons?: boolean;
		class?: string;
	} = $props();

	const sizeClasses = $derived.by(() => {
		switch (size) {
			case "sm":
				return {
					text: "text-xs",
					arrow: "size-3",
					gap: "gap-1.5",
				};
			case "lg":
				return {
					text: "text-xl sm:text-2xl",
					arrow: "size-4 sm:size-5",
					gap: "gap-3",
				};
			case "md":
			default:
				return {
					text: "text-base",
					arrow: "size-3.5",
					gap: "gap-2",
				};
		}
	});
</script>

<div class={cn("inline-flex items-center font-mono font-bold tabular-nums text-foreground", sizeClasses.gap, className)}>
	<!-- Rx (Download) -->
	<div class="flex items-center gap-1 text-sky-400">
		{#if showIcons}
			<ArrowDownIcon class={cn("shrink-0", sizeClasses.arrow)} />
		{/if}
		<span class={sizeClasses.text}>{formatBps(rxBps)}</span>
	</div>

	<span class="text-muted-foreground/50 select-none font-normal">/</span>

	<!-- Tx (Upload) -->
	<div class="flex items-center gap-1 text-emerald-400">
		{#if showIcons}
			<ArrowUpIcon class={cn("shrink-0", sizeClasses.arrow)} />
		{/if}
		<span class={sizeClasses.text}>{formatBps(txBps)}</span>
	</div>
</div>
