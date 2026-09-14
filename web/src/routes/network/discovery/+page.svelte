<script lang="ts">
	import { onMount } from "svelte";
	import { Button } from "$lib/components/ui/button";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import { toast } from "svelte-sonner";
	import {
		serviceBanners,
		transientHostList,
		scan,
	} from "$lib/api/client";
	import type { ServiceBanner, TransientHostEntry } from "$lib/api/types";

	import DiscoveryServiceCard from "./components/DiscoveryServiceCard.svelte";
	import TransientHostsTable from "./components/TransientHostsTable.svelte";
	import DiscoveryTuningCard from "./components/DiscoveryTuningCard.svelte";
	import DevicePromoteModal from "../devices/components/DevicePromoteModal.svelte";
	import HelpPopover from "$lib/components/HelpPopover.svelte";

	let loading = $state(true);
	let scanning = $state(false);
	let banners = $state<ServiceBanner[]>([]);
	let transientHosts = $state<TransientHostEntry[]>([]);

	// Promote Modal
	let promoteOpen = $state(false);
	let promoteMac = $state("");
	let promoteHostname = $state("");
	let promoteV4 = $state("");
	let promoteV6Suffix = $state("");

	async function loadAll() {
		loading = true;
		try {
			const [bannersRes, transientRes] = await Promise.allSettled([
				serviceBanners(),
				transientHostList(),
			]);
			if (bannersRes.status === "fulfilled") {
				banners = bannersRes.value;
			}
			if (transientRes.status === "fulfilled") {
				transientHosts = transientRes.value;
			}
		} catch {
			toast.error("Failed to load discovery data");
		} finally {
			loading = false;
		}
	}

	async function handleScan() {
		scanning = true;
		try {
			await scan();
			await loadAll();
			toast.success("Neighbor discovery refreshed");
		} catch (err: any) {
			toast.error(err?.message || "Failed to refresh discovery data");
		} finally {
			scanning = false;
		}
	}

	function handlePromoteTransient(host: TransientHostEntry) {
		promoteMac = "";
		promoteHostname = host.hostname || "";
		if (host.ip.includes(":")) {
			promoteV4 = "";
			promoteV6Suffix = host.ip;
		} else {
			promoteV4 = host.ip;
			promoteV6Suffix = "";
		}
		promoteOpen = true;
	}

	onMount(loadAll);
</script>

<svelte:head>
	<title>Discovery & Monitor — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Header -->
	<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<div class="flex items-center gap-2">
				<h1 class="text-foreground text-2xl font-bold tracking-tight">
					Discovery & Neighbor Monitor
				</h1>
				<HelpPopover
					title="Discovery Architecture"
					description="Mechanisms used to discover and maintain LAN neighbor state."
				>
					<DiscoveryTuningCard />
				</HelpPopover>
			</div>
			<p class="text-muted-foreground text-xs sm:text-sm">
				Netlink ARP/NDP snooper, mDNS prober, and active neighbor discovery
			</p>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={loadAll}
				disabled={loading}
				class="h-8 text-xs gap-1.5"
			>
				<RefreshCwIcon class="size-3.5 {loading ? 'animate-spin' : ''}" />
				<span>Refresh</span>
			</Button>

			<Button
				size="sm"
				onclick={handleScan}
				disabled={scanning}
				class="h-8 text-xs gap-1.5"
			>
				{#if scanning}
					<span class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
				{:else}
					<ZapIcon class="size-3.5 text-amber-300" />
				{/if}
				<span>Scan Network</span>
			</Button>
		</div>
	</div>

	<!-- Discovery & mDNS Service Life-cycle -->
	<DiscoveryServiceCard {banners} onReload={loadAll} />

	<!-- Discovered Transient Hosts -->
	<TransientHostsTable
		hosts={transientHosts}
		{loading}
		onPromote={handlePromoteTransient}
	/>
</div>

<DevicePromoteModal
	bind:open={promoteOpen}
	mac={promoteMac}
	hostname={promoteHostname}
	v4={promoteV4}
	v6Suffix={promoteV6Suffix}
	onPromoted={loadAll}
/>
