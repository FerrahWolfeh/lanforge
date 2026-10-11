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
</script>

<nav
	class={[
		"flex items-center gap-1 rounded-xl bg-muted/70 border border-border/70 p-1 overflow-x-auto w-full no-scrollbar shadow-2xs",
		className,
	].join(" ")}
	aria-label={ariaLabel}
>
	{#each tabs as tab (tab.href ?? tab.value ?? tab.label)}
		{@const active = isTabActive(tab)}
		{#if tab.href}
			<a
				href={tab.disabled ? undefined : tab.href}
				title={tab.title ?? tab.label}
				aria-current={active ? "page" : undefined}
				class={[
					"flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs sm:text-sm font-medium transition-all shrink-0 select-none outline-none focus-visible:ring-2 focus-visible:ring-ring",
					active
						? "bg-background text-foreground shadow-xs font-semibold border border-border/50"
						: "text-muted-foreground hover:text-foreground hover:bg-background/40",
					tab.disabled ? "opacity-50 pointer-events-none cursor-not-allowed" : "",
				].join(" ")}
			>
				{#if tab.icon}
					<tab.icon class="size-4 shrink-0 {active ? 'text-primary' : 'text-muted-foreground'}" />
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
					"flex items-center gap-2 rounded-lg px-3.5 py-1.5 text-xs sm:text-sm font-medium transition-all shrink-0 select-none cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-ring",
					active
						? "bg-background text-foreground shadow-xs font-semibold border border-border/50"
						: "text-muted-foreground hover:text-foreground hover:bg-background/40",
					tab.disabled ? "opacity-50 pointer-events-none cursor-not-allowed" : "",
				].join(" ")}
			>
				{#if tab.icon}
					<tab.icon class="size-4 shrink-0 {active ? 'text-primary' : 'text-muted-foreground'}" />
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
