<script lang="ts">
	import { trafficTelemetryFeed } from "$lib/api/client";
	import type { TrafficTelemetryResponse } from "$lib/api/types";
	import { onMount } from "svelte";
	import { createPolling } from "$lib/utils/polling";
	import { useTrafficStatus } from "./trafficStatusContext.svelte";

	import TrafficStatsCards from "./components/TrafficStatsCards.svelte";
	import TrafficActivityChart from "$lib/components/TrafficActivityChart.svelte";

	const trafficTelemetry = trafficTelemetryFeed();

	const shared = useTrafficStatus();
	const status = $derived(shared.value);
	let telemetry = $state<TrafficTelemetryResponse | null>(null);
	let loading = $state(true);

	async function loadData() {
		try {
			telemetry = await trafficTelemetry().catch(() => null);
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		loadData();
		const stopPolling = createPolling(
			() =>
				trafficTelemetry()
					.then((t) => (telemetry = t))
					.catch(() => {}),
			2500
		);
		return () => {
			stopPolling();
		};
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
