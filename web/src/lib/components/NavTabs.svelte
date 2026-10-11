<script lang="ts" module>
	import type { Component } from "svelte";

	export interface NavTabItem {
		label: string;
		href?: string;
		value?: string;
		icon?: Component<Record<string, unknown>>;
		badge?: string | number;
		badgeVariant?: "default" | "secondary" | "outline" | "destructive";
		exact?: boolean;
		disabled?: boolean;
		title?: string;
	}
</script>

<script lang="ts">
	import { page } from "$app/state";
	import { Badge } from "$lib/components/ui/badge";

	interface Props {
		tabs: NavTabItem[];
		value?: string;
		onValueChange?: (val: string) => void;
		class?: string;
		ariaLabel?: string;
	}

	let {
		tabs = [],
		value = $bindable(""),
		onValueChange,
		class: className = "",
		ariaLabel = "Module navigation",
	}: Props = $props();

	const currentPath = $derived(page.url.pathname);

	function isTabActive(tab: NavTabItem): boolean {
		if (tab.value !== undefined) {
			return value === tab.value;
		}
		if (!tab.href) return false;

		const target = tab.href;
		if (tab.exact !== undefined) {
			return tab.exact
				? currentPath === target || currentPath === `${target}/`
				: currentPath === target || currentPath.startsWith(`${target}/`);
		}

		// Auto-deduce exact match: if this tab's href is a prefix of any sibling tab in tabs,
		// require an exact match to prevent the root tab from staying active on sub-pages.
		const isPrefixOfOther = tabs.some(
			(other) => other !== tab && other.href && other.href.startsWith(`${target}/`),
		);
		if (isPrefixOfOther) {
			return currentPath === target || currentPath === `${target}/`;
		}

		return currentPath === target || currentPath.startsWith(`${target}/`);
	}
	let navEl = $state<HTMLElement | null>(null);
	let pillStyle = $state({ left: 0, top: 0, width: 0, height: 0, opacity: 0 });

	function updatePill() {
		if (!navEl) return;
		const activeEl = navEl.querySelector<HTMLElement>('[aria-current="page"], [aria-selected="true"]');
		if (activeEl) {
			pillStyle = {
				left: activeEl.offsetLeft,
				top: activeEl.offsetTop,
				width: activeEl.offsetWidth,
				height: activeEl.offsetHeight,
				opacity: 1,
			};
		} else {
			pillStyle = { ...pillStyle, opacity: 0 };
		}
	}

	$effect(() => {
		// Recompute pill position when currentPath, value, or tabs list changes
		currentPath;
		value;
		tabs;
		const handle = requestAnimationFrame(updatePill);
		return () => cancelAnimationFrame(handle);
	});
</script>

<svelte:window onresize={updatePill} />

<nav
	bind:this={navEl}
	class={[
		"relative flex items-center gap-1 rounded-xl bg-muted/70 border border-border/70 p-1 overflow-x-auto w-full no-scrollbar shadow-2xs",
		className,
	].join(" ")}
	aria-label={ariaLabel}
>
	<!-- Sliding Active Indicator Pill -->
	{#if pillStyle.opacity > 0}
		<div
			class="pointer-events-none absolute rounded-lg bg-background shadow-xs border border-border/50 transition-all duration-200 ease-out z-0"
			style="left: {pillStyle.left}px; top: {pillStyle.top}px; width: {pillStyle.width}px; height: {pillStyle.height}px; opacity: {pillStyle.opacity};"
		></div>
	{/if}

	{#each tabs as tab (tab.href ?? tab.value ?? tab.label)}
		{@const active = isTabActive(tab)}
		{#if tab.href}
			<a
				href={tab.disabled ? undefined : tab.href}
				title={tab.title ?? tab.label}
				aria-current={active ? "page" : undefined}
				class={[
					"relative z-10 flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs sm:text-sm font-medium transition-all shrink-0 select-none outline-none focus-visible:ring-2 focus-visible:ring-ring",
					active
						? "text-foreground font-semibold"
						: "text-muted-foreground hover:text-foreground hover:bg-background/30",
					tab.disabled ? "opacity-50 pointer-events-none cursor-not-allowed" : "",
				].join(" ")}
			>
				{#if tab.icon}
					<tab.icon class="size-4 shrink-0 transition-colors {active ? 'text-primary' : 'text-muted-foreground'}" />
				{/if}
				<span>{tab.label}</span>
				{#if tab.badge !== undefined && tab.badge !== null && tab.badge !== ""}
					<Badge
						variant={tab.badgeVariant ?? (active ? "default" : "secondary")}
						class="ml-1 text-[10px] px-1.5 py-0 font-mono h-4 leading-none"
					>
						{tab.badge}
					</Badge>
				{/if}
			</a>
		{:else}
			<button
				type="button"
				role="tab"
				aria-selected={active}
				disabled={tab.disabled}
				title={tab.title ?? tab.label}
				onclick={() => {
					if (!tab.disabled && tab.value !== undefined) {
						value = tab.value;
						onValueChange?.(tab.value);
					}
				}}
				class={[
					"relative z-10 flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs sm:text-sm font-medium transition-all shrink-0 select-none cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-ring",
					active
						? "text-foreground font-semibold"
						: "text-muted-foreground hover:text-foreground hover:bg-background/30",
					tab.disabled ? "opacity-50 pointer-events-none cursor-not-allowed" : "",
				].join(" ")}
			>
				{#if tab.icon}
					<tab.icon class="size-4 shrink-0 transition-colors {active ? 'text-primary' : 'text-muted-foreground'}" />
				{/if}
				<span>{tab.label}</span>
				{#if tab.badge !== undefined && tab.badge !== null && tab.badge !== ""}
					<Badge
						variant={tab.badgeVariant ?? (active ? "default" : "secondary")}
						class="ml-1 text-[10px] px-1.5 py-0 font-mono h-4 leading-none"
					>
						{tab.badge}
					</Badge>
				{/if}
			</button>
		{/if}
	{/each}
</nav>
