<script lang="ts">
	import { trafficStatus, trafficTelemetry } from "$lib/api/client";
	import type { TrafficStatusResponse, TrafficTelemetryResponse } from "$lib/api/types";
	import { onMount, onDestroy } from "svelte";

	import TrafficStatsCards from "./components/TrafficStatsCards.svelte";
	import TrafficActivityChart from "$lib/components/TrafficActivityChart.svelte";

	let status = $state<TrafficStatusResponse | null>(null);
	let telemetry = $state<TrafficTelemetryResponse | null>(null);
	let loading = $state(true);
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	async function loadData() {
		try {
			const [s, t] = await Promise.all([
				trafficStatus().catch(() => null),
				trafficTelemetry().catch(() => null),
			]);
			status = s;
			telemetry = t;
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		loadData();
		refreshInterval = setInterval(() => {
			if (typeof document !== "undefined" && document.hidden) return;
			Promise.allSettled([trafficStatus(), trafficTelemetry()]).then(([sRes, tRes]) => {
				if (sRes.status === "fulfilled") status = sRes.value;
				if (tRes.status === "fulfilled") telemetry = tRes.value;
			});
		}, 2500);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- Real-Time Bandwidth & Throughput Chart -->
	<TrafficActivityChart
		telemetryData={telemetry}
		trafficStatus={status}
		title="Live Traffic & Throughput Stream"
		description="Continuous instantaneous throughput sampled every 2.5 seconds directly from the kernel"
		{loading}
	/>

	<!-- Core Telemetry Status Cards & Interfaces Table -->
	<TrafficStatsCards {status} {telemetry} />
</div>
