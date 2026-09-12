<script lang="ts">
	import { page } from "$app/stores";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import LayersIcon from "@lucide/svelte/icons/layers";

	let { children } = $props();

	const tabs = [
		{ label: "Active Leases", href: "/dhcp/leases", icon: NetworkIcon },
		{ label: "Scopes & Pools", href: "/dhcp/pools", icon: LayersIcon },
		{ label: "Server Options", href: "/dhcp/server", icon: SlidersIcon },
	];

	function isTabActive(href: string) {
		const p = $page.url.pathname;
		return p === href || (href !== "/dhcp" && p.startsWith(href));
	}
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- DHCP Section Header -->
	<div class="flex flex-col gap-4 border-b pb-4">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div class="flex items-center gap-3">
				<div class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0">
					<ServerIcon class="size-6" />
				</div>
				<div>
					<h1 class="text-2xl font-bold tracking-tight">DHCP Server</h1>
					<p class="text-sm text-muted-foreground mt-0.5">
						Dynamic IPv4 &amp; IPv6 address allocation, pool scopes, and network boot parameters.
					</p>
				</div>
			</div>
		</div>

		<!-- Nav Tabs (Horizontal Scroll on Mobile) -->
		<nav class="flex items-center gap-1 rounded-lg bg-muted/60 p-1 overflow-x-auto w-full no-scrollbar">
			{#each tabs as tab (tab.href)}
				<a
					href={tab.href}
					class={[
						"flex items-center gap-2 rounded-md px-3.5 py-1.5 text-sm font-medium transition-colors shrink-0",
						isTabActive(tab.href)
							? "bg-background text-foreground shadow-sm font-semibold"
							: "text-muted-foreground hover:text-foreground hover:bg-background/50",
					].join(" ")}
				>
					<tab.icon class="size-4" />
					<span>{tab.label}</span>
				</a>
			{/each}
		</nav>
	</div>

	<!-- Tab Content Slot -->
	{@render children()}
</div>
