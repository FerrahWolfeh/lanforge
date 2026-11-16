<script lang="ts">
	import { cn } from "$lib/utils";
	import StatusDot from "./StatusDot.svelte";
	import type { Component, Snippet } from "svelte";

	let {
		title,
		description = "",
		icon: Icon,
		status,
		badge,
		actions,
		children,
		class: className = "",
	}: {
		title: string;
		description?: string;
		icon?: Component<{ class?: string }>;
		status?: { state: string; label?: string };
		badge?: Snippet;
		actions?: Snippet;
		children?: Snippet;
		class?: string;
	} = $props();
</script>

<div
	class={cn(
		"flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between pb-1",
		className
	)}
>
	<div class="flex items-center gap-3 min-w-0">
		{#if Icon}
			<div
				class="flex size-9 shrink-0 items-center justify-center rounded-lg bg-selected text-selected-foreground"
			>
				<Icon class="size-[18px]" />
			</div>
		{/if}

		<div class="flex flex-col min-w-0">
			<div class="flex items-center gap-2 flex-wrap">
				<h1 class="text-foreground text-xl font-semibold tracking-tight truncate">
					{title}
				</h1>

				{#if status}
					<div
						class="inline-flex items-center gap-1.5 rounded-full border border-border/80 bg-muted/40 px-2 py-0.5 text-xs text-muted-foreground"
					>
						<StatusDot state={status.state} size="sm" />
						{#if status.label}
							<span class="text-xs font-medium">{status.label}</span>
						{/if}
					</div>
				{/if}

				{#if badge}
					{@render badge()}
				{/if}
			</div>

			{#if description}
				<p class="text-muted-foreground text-sm mt-0.5 leading-normal">
					{description}
				</p>
			{/if}
		</div>
	</div>

	{#if actions}
		<div class="flex items-center gap-2 shrink-0 flex-wrap">
			{@render actions()}
		</div>
	{/if}

	{#if children}
		{@render children()}
	{/if}
</div>
