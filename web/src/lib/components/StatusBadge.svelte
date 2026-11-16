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
		pulse = false,
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
				return "border-transparent bg-success/12 text-success";
			case "starting":
			case "warning":
				return "border-transparent bg-warning/12 text-warning";
			case "error":
			case "failed":
				return "border-transparent bg-danger/12 text-danger";
			case "sky":
				return "border-transparent bg-info/12 text-info";
			case "indigo":
			case "primary":
				return "border-transparent bg-selected text-selected-foreground";
			case "dormant":
			case "inactive":
				return "border-transparent bg-muted text-muted-foreground";
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
		"inline-flex items-center gap-1.5 rounded-md border px-1.5 py-px text-xs font-medium whitespace-nowrap transition-colors select-none",
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
