<script lang="ts">
	import { page } from "$app/state";
	import SlidersHorizontalIcon from "@lucide/svelte/icons/sliders-horizontal";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { trafficStatus } from "$lib/api/client";
	import type { TrafficStatusResponse } from "$lib/api/types";
	import { onMount, onDestroy } from "svelte";

	let { children } = $props();

	let status = $state<TrafficStatusResponse | null>(null);
	let loading = $state(false);
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	const tabs = [
		{ label: "Overview", href: "/network/traffic", icon: ActivityIcon },
		{ label: "Bufferbloat (CAKE)", href: "/network/traffic/sqm", icon: GaugeIcon },
		{ label: "Hardware Tuning", href: "/network/traffic/tuning", icon: CpuIcon },
	];

	function isTabActive(href: string) {
		const p: string = page.url.pathname;
		if (href === "/network/traffic") return p === "/network/traffic" || p === "/network/traffic/";
		return p === href || p.startsWith(href + "/");
	}

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
		refreshInterval = setInterval(() => {
			if (typeof document !== "undefined" && document.hidden) return;
			trafficStatus().then((s) => (status = s)).catch(() => {});
		}, 4000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});
</script>

<svelte:head>
	<title>Traffic & SQM — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 w-full pb-24">
	<!-- Page Header -->
	<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
		<div class="flex items-center gap-3.5">
			<div class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0">
				<SlidersHorizontalIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-1">
				<div class="flex flex-wrap items-center gap-2.5">
					<h1 class="text-2xl font-bold tracking-tight">Traffic & Network Tuning</h1>
					{#if status?.sqm_active}
						<Badge
							variant="outline"
							class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
						>
							<span class="relative flex size-2 mr-1.5">
								<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
								<span class="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
							</span>
							CAKE Active ({status.download_mbps}M / {status.upload_mbps}M)
						</Badge>
					{:else if status?.tuning_applied}
						<Badge
							variant="outline"
							class="border-primary/25 bg-primary/10 text-primary font-medium text-xs"
						>
							NICs Tuned
						</Badge>
					{:else}
						<Badge variant="secondary" class="text-muted-foreground text-xs font-medium">
							Dormant
						</Badge>
					{/if}
				</div>
				<p class="text-xs sm:text-sm text-muted-foreground">
					Hardware network interface optimization, kernel offloads, and CAKE bufferbloat management.
				</p>
			</div>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={fetchStatus}
				disabled={loading}
				class="h-9 gap-1.5 text-xs transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={`size-3.5 ${loading ? "animate-spin" : ""}`} />
				<span>Refresh</span>
			</Button>
		</div>
	</div>

	<!-- Navigation Tabs Bar (Consistent with Adblock layout) -->
	<nav class="flex items-center gap-1 rounded-lg bg-muted/60 p-1 overflow-x-auto">
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

	<!-- Page Content -->
	{@render children()}
</div>
