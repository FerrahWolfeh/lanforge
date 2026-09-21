<script lang="ts">
	import FloatingSaveBar from "$lib/components/FloatingSaveBar.svelte";
	import {
		trafficStatus,
		trafficTelemetry,
		trafficConfig,
		trafficUpdateConfig,
		getSetupStatus,
		pppoeConfig,
	} from "$lib/api/client";
	import type {
		TrafficConfig,
		TrafficStatusResponse,
		TrafficTelemetryResponse,
		NetworkInterfaceInfo,
		SetupStatusResponse,
		PppoeConfig,
		SqmOverhead,
		SqmDiffserv,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	import TrafficSqmTab from "../components/TrafficSqmTab.svelte";

	let status = $state<TrafficStatusResponse | null>(null);
	let telemetry = $state<TrafficTelemetryResponse | null>(null);
	let serverConfig = $state<TrafficConfig | null>(null);
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);
	let setupStatus = $state<SetupStatusResponse | null>(null);
	let pppoeCfg = $state<PppoeConfig | null>(null);

	let loading = $state(true);
	let saving = $state(false);
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	// Editable reactive form fields (SQM)
	let sqmEnabled = $state(false);
	let sqmInterface = $state("auto");
	let sqmDownloadMbps = $state(0);
	let sqmUploadMbps = $state(0);
	let sqmOverhead = $state<SqmOverhead>("auto");
	let sqmDiffserv = $state<SqmDiffserv>("diffserv4");
	let sqmPerHostIsolation = $state(true);
	let sqmRttMs = $state<number | null>(null);
	let sqmIngressDevice = $state("ifb4lanforge");

	function syncFormFromConfig(c: TrafficConfig) {
		sqmEnabled = c.sqm.enabled;
		sqmInterface = c.sqm.interface || "auto";
		sqmDownloadMbps = c.sqm.download_mbps;
		sqmUploadMbps = c.sqm.upload_mbps;
		sqmOverhead = c.sqm.overhead || "auto";
		sqmDiffserv = c.sqm.diffserv || "diffserv4";
		sqmPerHostIsolation = c.sqm.per_host_isolation ?? true;
		sqmRttMs = c.sqm.rtt_ms ?? null;
		sqmIngressDevice = c.sqm.ingress_device || "ifb4lanforge";
	}

	// Physical LAN port
	const detectedLan = $derived(
		setupStatus?.detected_lan_iface ||
		status?.tuned_interfaces?.find((i) => i.startsWith("lan") || i === "eth0") ||
		"lan0"
	);

	// Physical WAN port
	const physicalWan = $derived.by(() => {
		if (pppoeCfg?.wan_iface) return pppoeCfg.wan_iface;
		const tunedWan = status?.tuned_interfaces?.find((i) => i !== detectedLan && !i.startsWith("ppp"));
		if (tunedWan) return tunedWan;
		const found = availableInterfaces.find((i) => i.is_physical && i.name !== detectedLan && !i.name.startsWith("ppp"));
		return found?.name || "wan0";
	});

	// Shaping WAN port (prefers active PPPoE session e.g. ppp0, otherwise physical WAN)
	const shapingWan = $derived(
		status?.wan_interface || (pppoeCfg?.enabled ? "ppp0" : physicalWan)
	);

	// Dirty tracking
	const isDirty = $derived.by(() => {
		if (!serverConfig) return false;
		if (sqmEnabled !== serverConfig.sqm.enabled) return true;
		if (Number(sqmDownloadMbps) !== serverConfig.sqm.download_mbps) return true;
		if (Number(sqmUploadMbps) !== serverConfig.sqm.upload_mbps) return true;
		if (sqmInterface !== serverConfig.sqm.interface) return true;
		if (sqmOverhead !== serverConfig.sqm.overhead) return true;
		if (sqmDiffserv !== serverConfig.sqm.diffserv) return true;
		if (sqmPerHostIsolation !== serverConfig.sqm.per_host_isolation) return true;
		if (sqmRttMs !== (serverConfig.sqm.rtt_ms ?? null)) return true;
		if (sqmIngressDevice !== serverConfig.sqm.ingress_device) return true;
		return false;
	});

	const changeCount = $derived.by(() => {
		if (!isDirty || !serverConfig) return 0;
		let count = 0;
		if (sqmEnabled !== serverConfig.sqm.enabled) count++;
		if (Number(sqmDownloadMbps) !== serverConfig.sqm.download_mbps) count++;
		if (Number(sqmUploadMbps) !== serverConfig.sqm.upload_mbps) count++;
		if (sqmInterface !== serverConfig.sqm.interface) count++;
		if (sqmOverhead !== serverConfig.sqm.overhead) count++;
		if (sqmDiffserv !== serverConfig.sqm.diffserv) count++;
		if (sqmPerHostIsolation !== serverConfig.sqm.per_host_isolation) count++;
		if (sqmRttMs !== (serverConfig.sqm.rtt_ms ?? null)) count++;
		if (sqmIngressDevice !== serverConfig.sqm.ingress_device) count++;
		return Math.max(count, 1);
	});

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const [s, c, setupRes, pppoeRes, telemRes] = await Promise.all([
				trafficStatus().catch(() => null),
				trafficConfig().catch(() => null),
				getSetupStatus().catch(() => null),
				pppoeConfig().catch(() => null),
				trafficTelemetry().catch(() => null),
			]);
			status = s;
			setupStatus = setupRes;
			pppoeCfg = pppoeRes;
			telemetry = telemRes;

			if (setupRes?.interfaces) {
				availableInterfaces = setupRes.interfaces;
			}
			if (c) {
				if (!serverConfig || !isDirty) {
					serverConfig = c;
					syncFormFromConfig(c);
				} else {
					serverConfig = c;
				}
			}
		} catch {
			if (!silent) toast.error("Failed to load SQM configuration");
		} finally {
			if (!silent) loading = false;
		}
	}

	function handleDiscard() {
		if (!serverConfig) return;
		syncFormFromConfig(serverConfig);
		toast.info("Changes discarded");
	}

	async function handleSave() {
		if (!isDirty || !serverConfig) return;
		saving = true;
		try {
			const payload: TrafficConfig = {
				sqm: {
					enabled: sqmEnabled,
					interface: sqmInterface === "auto" ? "" : sqmInterface,
					download_mbps: Number(sqmDownloadMbps) || 0,
					upload_mbps: Number(sqmUploadMbps) || 0,
					overhead: sqmOverhead,
					diffserv: sqmDiffserv,
					per_host_isolation: sqmPerHostIsolation,
					rtt_ms: sqmRttMs ? Number(sqmRttMs) : null,
					ingress_device: sqmIngressDevice || "ifb4lanforge",
					raw_cake_args: serverConfig.sqm.raw_cake_args ?? null,
				},
				tuning: serverConfig.tuning,
			};

			await trafficUpdateConfig(payload);
			serverConfig = payload;
			syncFormFromConfig(payload);
			toast.success("SQM CAKE configuration applied successfully");

			setTimeout(async () => {
				const [s, t] = await Promise.all([
					trafficStatus().catch(() => null),
					trafficTelemetry().catch(() => null),
				]);
				if (s) status = s;
				if (t) telemetry = t;
			}, 600);
		} catch (err) {
			toast.error(`Failed to save: ${err instanceof Error ? err.message : String(err)}`);
		} finally {
			saving = false;
		}
	}

	onMount(() => {
		loadAll(false);
		refreshInterval = setInterval(() => {
			if (typeof document !== "undefined" && document.hidden) return;
			Promise.allSettled([trafficStatus(), trafficTelemetry()]).then(([sRes, tRes]) => {
				if (sRes.status === "fulfilled") status = sRes.value;
				if (tRes.status === "fulfilled") telemetry = tRes.value;
			});
		}, 3000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});
</script>

<div class="flex flex-col gap-6 w-full">
	{#if loading && !serverConfig}
		<div class="flex items-center justify-center p-12 text-muted-foreground text-sm">
			<RefreshCwIcon class="size-5 animate-spin mr-2" />
			Loading SQM configuration...
		</div>
	{:else if serverConfig}
		<TrafficSqmTab
			bind:enabled={sqmEnabled}
			bind:downloadMbps={sqmDownloadMbps}
			bind:uploadMbps={sqmUploadMbps}
			bind:interface={sqmInterface}
			bind:overhead={sqmOverhead}
			bind:diffserv={sqmDiffserv}
			bind:perHostIsolation={sqmPerHostIsolation}
			bind:rttMs={sqmRttMs}
			bind:ingressDevice={sqmIngressDevice}
			{availableInterfaces}
			detectedWan={shapingWan}
			{telemetry}
		/>
	{/if}

	<!-- Floating Save / Discard Bar -->
	<FloatingSaveBar
		show={isDirty}
		count={changeCount}
		{saving}
		onDiscard={handleDiscard}
		onSave={handleSave}
	/>
</div>
