<script lang="ts">
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import LayersIcon from "@lucide/svelte/icons/layers";

	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";

	let { children } = $props();

	const tabs: NavTabItem[] = [
		{ label: "Active Leases", href: "/dhcp/leases", icon: NetworkIcon },
		{ label: "Scopes & Pools", href: "/dhcp/pools", icon: LayersIcon },
		{ label: "Server Options", href: "/dhcp/server", icon: SlidersIcon },
	];
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- DHCP Section Header -->
	<div class="flex flex-col gap-4 border-b pb-4">
		<PageHeader
			title="DHCP Server"
			description="Dynamic IPv4 & IPv6 address allocation, pool scopes, and network boot parameters."
			icon={ServerIcon}
		/>

		<!-- Nav Tabs (Horizontal Scroll on Mobile) -->
		<NavTabs {tabs} ariaLabel="DHCP server navigation" />
	</div>

	<!-- Tab Content Slot -->
	{@render children()}
</div>
