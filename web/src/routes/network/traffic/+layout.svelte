<script lang="ts">
	import SlidersHorizontalIcon from "@lucide/svelte/icons/sliders-horizontal";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { trafficStatus } from "$lib/api/client";
	import type { TrafficStatusResponse } from "$lib/api/types";
	import { onMount } from "svelte";
	import { createPolling } from "$lib/utils/polling";

	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";

	let { children } = $props();

	let status = $state<TrafficStatusResponse | null>(null);
	let loading = $state(false);

	const tabs: NavTabItem[] = [
		{ label: "Overview", href: "/network/traffic", icon: ActivityIcon },
		{ label: "Bufferbloat (CAKE)", href: "/network/traffic/sqm", icon: GaugeIcon },
		{ label: "Hardware Tuning", href: "/network/traffic/tuning", icon: CpuIcon },
	];

	async function fetchStatus() {
		loading = true;
		try {
			status = await trafficStatus();
		} catch {
			// Ignore in background
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		fetchStatus();
		const stopPolling = createPolling(() => {
			trafficStatus().then((s) => (status = s)).catch(() => {});
		}, 4000);
		return () => {
			stopPolling();
		};
	});
</script>

<svelte:head>
	<title>Traffic & SQM — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 w-full pb-24">
	<!-- Page Header -->
	<PageHeader
		title="Traffic & Network Tuning"
		description="Hardware network interface optimization, kernel offloads, and CAKE bufferbloat management."
		icon={SlidersHorizontalIcon}
	>
		{#snippet badge()}
			{#if status?.sqm_active}
				<StatusBadge
					variant="online"
					showDot={true}
					pulse={true}
					text={`CAKE Active (${status.download_mbps}M / ${status.upload_mbps}M)`}
				/>
			{:else if status?.tuning_applied}
				<StatusBadge variant="primary" text="NICs Tuned" />
			{:else}
				<StatusBadge variant="dormant" text="Dormant" />
			{/if}
		{/snippet}
		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				onclick={fetchStatus}
				disabled={loading}
				class="h-8 gap-1.5 text-xs transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={`size-3.5 ${loading ? "animate-spin" : ""}`} />
				<span>Refresh</span>
			</Button>
		{/snippet}
	</PageHeader>

	<!-- Navigation Tabs Bar -->
	<NavTabs {tabs} ariaLabel="Traffic & SQM navigation" />

	<!-- Page Content -->
	{@render children()}
</div>
