<script lang="ts" module>
	export type StatusTone = "ok" | "warning" | "danger" | "info";
</script>

<script lang="ts">
	import { cn } from "$lib/utils";
	import CircleCheckIcon from "@lucide/svelte/icons/circle-check";
	import TriangleAlertIcon from "@lucide/svelte/icons/triangle-alert";
	import CircleXIcon from "@lucide/svelte/icons/circle-x";
	import InfoIcon from "@lucide/svelte/icons/info";
	import type { Snippet } from "svelte";

	/**
	 * The one line at the top of a page that answers "is everything OK?": what is wrong and
	 * where to fix it, or that all is well. Only `ok` gets the brand-gradient hairline.
	 */
	let {
		tone = "ok",
		title,
		text = "",
		href,
		linkLabel = "Details",
		class: className = "",
		children,
	}: {
		tone?: StatusTone;
		/** Bold lead-in, e.g. "DNS is degraded:" */
		title?: string;
		text?: string;
		href?: string;
		linkLabel?: string;
		class?: string;
		children?: Snippet;
	} = $props();

	const Icon = $derived(
		tone === "ok" ? CircleCheckIcon : tone === "warning" ? TriangleAlertIcon : tone === "danger" ? CircleXIcon : InfoIcon
	);
	const toneClass = $derived(
		tone === "warning"
			? "bg-warning/10 border-warning/35 [&_svg.status-icon]:text-warning"
			: tone === "danger"
				? "bg-danger/10 border-danger/35 [&_svg.status-icon]:text-danger"
				: tone === "info"
					? "bg-card border-border [&_svg.status-icon]:text-info"
					: "bg-card border-border [&_svg.status-icon]:text-success"
	);
</script>

<div
	role={tone === "warning" || tone === "danger" ? "alert" : "status"}
	class={cn(
		"relative flex flex-wrap items-center gap-x-2.5 gap-y-1 overflow-hidden rounded-lg border px-3 py-2.5 text-sm",
		toneClass,
		className
	)}
>
	{#if tone === "ok"}
		<span class="bg-brand-gradient absolute inset-x-0 top-0 h-0.5" aria-hidden="true"></span>
	{/if}
	<Icon class="status-icon size-4 shrink-0" />
	<span class="min-w-0 flex-1">
		{#if title}<b class="font-semibold">{title}</b>{/if}
		{#if children}{@render children()}{:else}{text}{/if}
	</span>
	{#if href}
		<a {href} class="ml-auto text-sm font-medium text-selected-foreground hover:underline">{linkLabel} →</a>
	{/if}
</div>
