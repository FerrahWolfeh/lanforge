<script lang="ts">
	import { cn } from "$lib/utils";

	export type StatusState =
		| "online"
		| "active"
		| "starting"
		| "dormant"
		| "inactive"
		| "offline"
		| "error"
		| "failed"
		| "warning";

	let {
		state = "online",
		size = "md",
		pulse = false,
		ping = false,
		class: className = "",
	}: {
		state?: StatusState | string;
		size?: "sm" | "md" | "lg";
		pulse?: boolean;
		ping?: boolean;
		class?: string;
	} = $props();

	const normalizedState = $derived((state || "dormant").toLowerCase());

	const dotStyles = $derived.by(() => {
		switch (normalizedState) {
			case "online":
			case "active":
				return "bg-success";
			case "starting":
				return "bg-warning animate-pulse";
			case "warning":
				return "bg-warning";
			case "error":
			case "failed":
				return "bg-danger";
			case "dormant":
			case "inactive":
			case "offline":
			default:
				return "bg-muted-foreground/50";
		}
	});

	const sizeClasses = $derived.by(() => {
		switch (size) {
			case "sm":
				return "size-1.5";
			case "lg":
				return "size-2.5";
			case "md":
			default:
				return "size-2";
		}
	});

	const isLive = $derived(
		normalizedState === "online" || normalizedState === "active"
	);
</script>

<span class={cn("relative inline-flex items-center justify-center shrink-0", className)}>
	{#if ping && isLive}
		<span
			class={cn(
				"absolute inline-flex rounded-full bg-success opacity-75 animate-ping",
				sizeClasses
			)}
		></span>
	{/if}
	<span
		class={cn(
			"rounded-full transition-colors",
			sizeClasses,
			dotStyles,
			pulse && isLive ? "animate-pulse" : ""
		)}
	></span>
</span>
