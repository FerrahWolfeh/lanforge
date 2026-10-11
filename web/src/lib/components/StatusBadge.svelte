<script lang="ts">
	import { cn } from "$lib/utils";
	import StatusDot, { type StatusState } from "./StatusDot.svelte";
	import type { Snippet } from "svelte";

	export type StatusBadgeVariant =
		| "online"
		| "starting"
		| "dormant"
		| "error"
		| "warning"
		| "primary"
		| "sky"
		| "indigo"
		| "outline";

	let {
		text = "",
		variant = "outline",
		showDot = false,
		pulse = true,
		class: className = "",
		children,
	}: {
		text?: string;
		variant?: StatusBadgeVariant | string;
		showDot?: boolean;
		pulse?: boolean;
		class?: string;
		children?: Snippet;
	} = $props();

	const variantStyles = $derived.by(() => {
		switch (variant) {
			case "online":
			case "active":
				return "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";
			case "starting":
				return "border-amber-500/30 bg-amber-500/10 text-amber-400";
			case "warning":
				return "border-amber-500/30 bg-amber-500/10 text-amber-300";
			case "error":
			case "failed":
				return "border-rose-500/30 bg-rose-500/10 text-rose-400";
			case "sky":
				return "border-sky-500/30 bg-sky-500/10 text-sky-400";
			case "indigo":
				return "border-indigo-500/30 bg-indigo-500/10 text-indigo-400";
			case "primary":
				return "border-primary/30 bg-primary/10 text-primary";
			case "dormant":
			case "inactive":
				return "border-border/70 bg-muted/40 text-muted-foreground";
			case "outline":
			default:
				return "border-border text-muted-foreground";
		}
	});

	const dotState = $derived.by(() => {
		switch (variant) {
			case "online":
			case "active":
				return "online";
			case "starting":
				return "starting";
			case "error":
			case "failed":
				return "error";
			case "warning":
				return "warning";
			default:
				return "dormant";
		}
	});
</script>

<span
	class={cn(
		"inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0 font-mono text-[10px] uppercase font-semibold tracking-wider transition-colors select-none",
		variantStyles,
		className
	)}
>
	{#if showDot}
		<StatusDot state={dotState} size="sm" {pulse} />
	{/if}
	{#if children}
		{@render children()}
	{:else}
		{text}
	{/if}
</span>
