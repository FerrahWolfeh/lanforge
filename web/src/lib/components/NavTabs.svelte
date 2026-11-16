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

	// Which edges hide more tabs: drives the fade so a cut-off row reads as scrollable.
	let fadeLeft = $state(false);
	let fadeRight = $state(false);

	function updateFades() {
		if (!navEl) return;
		fadeLeft = navEl.scrollLeft > 2;
		fadeRight = navEl.scrollLeft + navEl.clientWidth < navEl.scrollWidth - 2;
	}

	function updatePill() {
		if (!navEl) return;
		const activeEl = navEl.querySelector<HTMLElement>('[aria-current="page"], [aria-current="true"]');
		// On a narrow screen the active tab may sit past the edge: bring it into view (row only,
		// never the page).
		if (activeEl) {
			const left = activeEl.offsetLeft;
			const right = left + activeEl.offsetWidth;
			if (left < navEl.scrollLeft) navEl.scrollLeft = left - 8;
			else if (right > navEl.scrollLeft + navEl.clientWidth) navEl.scrollLeft = right - navEl.clientWidth + 8;
		}
		updateFades();
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
	onscroll={updateFades}
	class={[
		"relative flex items-center gap-1 rounded-lg bg-card border border-border p-1 overflow-x-auto w-full no-scrollbar",
		className,
	].join(" ")}
	style:mask-image={fadeLeft || fadeRight
		? `linear-gradient(to right, ${fadeLeft ? "transparent, black 2rem" : "black"}, ${fadeRight ? "black calc(100% - 2rem), transparent" : "black"})`
		: undefined}
	aria-label={ariaLabel}
>
	<!-- Sliding Active Indicator Pill -->
	{#if pillStyle.opacity > 0}
		<div
			class="pointer-events-none absolute rounded-md bg-selected transition-all duration-200 ease-out z-0"
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
					"relative z-10 flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs sm:text-sm font-medium transition-all shrink-0 select-none outline-none focus-visible:ring-2 focus-visible:ring-ring",
					active
						? "text-selected-foreground font-semibold"
						: "text-muted-foreground hover:text-foreground hover:bg-background/30",
					tab.disabled ? "opacity-50 pointer-events-none cursor-not-allowed" : "",
				].join(" ")}
			>
				{#if tab.icon}
					<tab.icon class="size-4 shrink-0 transition-colors {active ? 'text-selected-foreground' : 'text-muted-foreground'}" />
				{/if}
				<span>{tab.label}</span>
				{#if tab.badge !== undefined && tab.badge !== null && tab.badge !== ""}
					<Badge
						variant={tab.badgeVariant ?? (active ? "default" : "secondary")}
						class="ml-1 text-xs px-1.5 py-0 h-4 leading-none tabular-nums"
					>
						{tab.badge}
					</Badge>
				{/if}
			</a>
		{:else}
			<button
				type="button"
				aria-current={active ? "true" : undefined}
				disabled={tab.disabled}
				title={tab.title ?? tab.label}
				onclick={() => {
					if (!tab.disabled && tab.value !== undefined) {
						value = tab.value;
						onValueChange?.(tab.value);
					}
				}}
				class={[
					"relative z-10 flex items-center gap-2 rounded-md px-3.5 py-1.5 text-xs sm:text-sm font-medium transition-all shrink-0 select-none cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-ring",
					active
						? "text-selected-foreground font-semibold"
						: "text-muted-foreground hover:text-foreground hover:bg-background/30",
					tab.disabled ? "opacity-50 pointer-events-none cursor-not-allowed" : "",
				].join(" ")}
			>
				{#if tab.icon}
					<tab.icon class="size-4 shrink-0 transition-colors {active ? 'text-selected-foreground' : 'text-muted-foreground'}" />
				{/if}
				<span>{tab.label}</span>
				{#if tab.badge !== undefined && tab.badge !== null && tab.badge !== ""}
					<Badge
						variant={tab.badgeVariant ?? (active ? "default" : "secondary")}
						class="ml-1 text-xs px-1.5 py-0 h-4 leading-none tabular-nums"
					>
						{tab.badge}
					</Badge>
				{/if}
			</button>
		{/if}
	{/each}
</nav>
