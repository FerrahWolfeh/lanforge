<script lang="ts">
	import { page } from "$app/stores";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";

	let { children } = $props();

	const tabs = [
		{ label: "Active Leases", href: "/dhcp/leases", icon: NetworkIcon },
		{ label: "Pool Utilization", href: "/dhcp/pools", icon: ActivityIcon },
		{ label: "Options & Scopes", href: "/dhcp/options", icon: SlidersIcon },
	];

	function isTabActive(href: string) {
		const p = $page.url.pathname;
		return p === href || (href !== "/dhcp" && p.startsWith(href));
	}
</script>

<div class="flex flex-col gap-6">
	<!-- DHCP Section Header -->
	<div
		class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between border-b pb-4"
	>
		<div>
			<div class="flex items-center gap-2">
				<ServerIcon class="h-6 w-6 text-primary" />
				<h1 class="text-2xl font-bold tracking-tight">DHCP Server</h1>
			</div>
			<p class="text-sm text-muted-foreground mt-1">
				Dynamic IPv4 & IPv6 address allocation, lease lifetime
				monitoring, and pool management.
			</p>
		</div>

		<!-- Nav Tabs -->
		<nav class="flex items-center gap-1 rounded-lg bg-muted/60 p-1">
			{#each tabs as tab (tab.href)}
				<a
					href={tab.href}
					class={[
						"flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
						isTabActive(tab.href)
							? "bg-background text-foreground shadow-sm"
							: "text-muted-foreground hover:text-foreground hover:bg-background/50",
					].join(" ")}
				>
					<tab.icon class="h-4 w-4" />
					<span>{tab.label}</span>
				</a>
			{/each}
		</nav>
	</div>

	<!-- Tab Content Slot -->
	{@render children()}
</div>
