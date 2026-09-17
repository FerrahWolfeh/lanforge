<script lang="ts">
	import * as Tabs from "$lib/components/ui/tabs";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import FloatingSaveBar from "$lib/components/FloatingSaveBar.svelte";
	import {
		trafficStatus,
		trafficConfig,
		trafficUpdateConfig,
		getSetupStatus,
		pppoeConfig,
	} from "$lib/api/client";
	import type {
		TrafficConfig,
		TrafficStatusResponse,
		NetworkInterfaceInfo,
		SetupStatusResponse,
		PppoeConfig,
		SqmOverhead,
		SqmDiffserv,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";

	import SlidersHorizontalIcon from "@lucide/svelte/icons/sliders-horizontal";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";

	import TrafficStatsCards from "./components/TrafficStatsCards.svelte";
	import TrafficSqmTab from "./components/TrafficSqmTab.svelte";
	import TrafficTuningTab from "./components/TrafficTuningTab.svelte";

	// Page state
	let status = $state<TrafficStatusResponse | null>(null);
	let serverConfig = $state<TrafficConfig | null>(null);
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);
	let setupStatus = $state<SetupStatusResponse | null>(null);
	let pppoeCfg = $state<PppoeConfig | null>(null);

	let loading = $state(true);
	let saving = $state(false);
	let activeTab = $state("sqm");
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

	// Editable reactive form fields (Tuning)
	let tuningEnabled = $state(false);
	let tuningInterfaces = $state<string[]>([]);
	let tuningCpuMask = $state("auto");
	let tuningRxRing = $state("auto");
	let tuningTxRing = $state("auto");
	let tuningDisableEee = $state(true);
	let tuningUdpGroForwarding = $state(true);
	let tuningRpsFlowEntries = $state(32768);
	let tuningRpsFlowCnt = $state(4096);

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

		tuningEnabled = c.tuning.enabled;
		tuningInterfaces = [...(c.tuning.interfaces || [])];
		tuningCpuMask = c.tuning.cpu_mask || "auto";
		tuningRxRing = c.tuning.rx_ring || "auto";
		tuningTxRing = c.tuning.tx_ring || "auto";
		tuningDisableEee = c.tuning.disable_eee ?? true;
		tuningUdpGroForwarding = c.tuning.udp_gro_forwarding ?? true;
		tuningRpsFlowEntries = c.tuning.rps_flow_entries || 32768;
		tuningRpsFlowCnt = c.tuning.rps_flow_cnt || 4096;
	}

	// Physical LAN port
	const detectedLan = $derived(
		setupStatus?.detected_lan_iface ||
		status?.tuned_interfaces?.find((i) => i.startsWith("lan") || i === "eth0") ||
		"lan0"
	);

	// Physical WAN port (for hardware NIC tuning: RPS, ethtool, EEE)
	const physicalWan = $derived.by(() => {
		if (pppoeCfg?.wan_iface) return pppoeCfg.wan_iface;
		const tunedWan = status?.tuned_interfaces?.find((i) => i !== detectedLan && !i.startsWith("ppp"));
		if (tunedWan) return tunedWan;
		const found = availableInterfaces.find((i) => i.is_physical && i.name !== detectedLan && !i.name.startsWith("ppp"));
		return found?.name || "wan0";
	});

	// Shaping WAN port (for SQM CAKE: prefers active PPPoE session e.g. ppp0, otherwise physical WAN)
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

		if (tuningEnabled !== serverConfig.tuning.enabled) return true;
		if (tuningCpuMask !== serverConfig.tuning.cpu_mask) return true;
		if (tuningRxRing !== serverConfig.tuning.rx_ring) return true;
		if (tuningTxRing !== serverConfig.tuning.tx_ring) return true;
		if (tuningDisableEee !== serverConfig.tuning.disable_eee) return true;
		if (tuningUdpGroForwarding !== serverConfig.tuning.udp_gro_forwarding) return true;
		if (Number(tuningRpsFlowEntries) !== serverConfig.tuning.rps_flow_entries) return true;
		if (Number(tuningRpsFlowCnt) !== serverConfig.tuning.rps_flow_cnt) return true;
		if (JSON.stringify(tuningInterfaces) !== JSON.stringify(serverConfig.tuning.interfaces)) return true;

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

		if (tuningEnabled !== serverConfig.tuning.enabled) count++;
		if (tuningCpuMask !== serverConfig.tuning.cpu_mask) count++;
		if (tuningRxRing !== serverConfig.tuning.rx_ring) count++;
		if (tuningTxRing !== serverConfig.tuning.tx_ring) count++;
		if (tuningDisableEee !== serverConfig.tuning.disable_eee) count++;
		if (tuningUdpGroForwarding !== serverConfig.tuning.udp_gro_forwarding) count++;
		if (Number(tuningRpsFlowEntries) !== serverConfig.tuning.rps_flow_entries) count++;
		if (Number(tuningRpsFlowCnt) !== serverConfig.tuning.rps_flow_cnt) count++;
		if (JSON.stringify(tuningInterfaces) !== JSON.stringify(serverConfig.tuning.interfaces)) count++;
		return Math.max(count, 1);
	});

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const [s, c, setupRes, pppoeRes] = await Promise.all([
				trafficStatus().catch(() => null),
				trafficConfig().catch(() => null),
				getSetupStatus().catch(() => null),
				pppoeConfig().catch(() => null),
			]);
			status = s;
			setupStatus = setupRes;
			pppoeCfg = pppoeRes;

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
			if (!silent) toast.error("Failed to load traffic and SQM configuration");
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
		if (!isDirty) return;
		saving = true;
		try {
			const payload: TrafficConfig = {
				sqm: {
					enabled: sqmEnabled,
					interface: sqmInterface.trim() || "auto",
					download_mbps: Number(sqmDownloadMbps) || 0,
					upload_mbps: Number(sqmUploadMbps) || 0,
					overhead: sqmOverhead,
					diffserv: sqmDiffserv,
					per_host_isolation: sqmPerHostIsolation,
					rtt_ms: sqmRttMs ? Number(sqmRttMs) : null,
					ingress_device: sqmIngressDevice.trim() || "ifb4lanforge",
					raw_cake_args: serverConfig?.sqm.raw_cake_args ?? null,
				},
				tuning: {
					enabled: tuningEnabled,
					interfaces: [...tuningInterfaces],
					cpu_mask: tuningCpuMask.trim() || "auto",
					rps_flow_entries: Number(tuningRpsFlowEntries) || 32768,
					rps_flow_cnt: Number(tuningRpsFlowCnt) || 4096,
					rx_ring: tuningRxRing.trim() || "auto",
					tx_ring: tuningTxRing.trim() || "auto",
					disable_eee: tuningDisableEee,
					udp_gro_forwarding: tuningUdpGroForwarding,
				},
			};

			await trafficUpdateConfig(payload);
			serverConfig = structuredClone(payload);
			toast.success("Traffic configuration saved and applied");
			setTimeout(() => {
				loadAll(true);
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
			trafficStatus()
				.then((s) => {
					status = s;
				})
				.catch(() => {});
		}, 5000);
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
					<h1 class="text-2xl font-bold tracking-tight">Traffic & SQM</h1>
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
					Hardware network interface optimization and CAKE bufferbloat management.
				</p>
			</div>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll(false)}
				disabled={loading}
				class="h-9 gap-1.5 text-xs transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={`size-3.5 ${loading ? "animate-spin" : ""}`} />
				<span>Refresh</span>
			</Button>
		</div>
	</div>

	<!-- Top Telemetry Status Cards (3-column layout) -->
	<TrafficStatsCards {status} />

	{#if loading && !serverConfig}
		<div class="flex items-center justify-center p-12 text-muted-foreground text-sm">
			<RefreshCwIcon class="size-5 animate-spin mr-2" />
			Loading configuration...
		</div>
	{:else if serverConfig}
		<!-- Main Tabs -->
		<Tabs.Root bind:value={activeTab} class="flex flex-col gap-4">
			<Tabs.List class="grid grid-cols-2 max-w-xs h-9">
				<Tabs.Trigger value="sqm" class="gap-2 text-xs">
					<GaugeIcon class="size-4" />
					<span>Bufferbloat (CAKE)</span>
				</Tabs.Trigger>
				<Tabs.Trigger value="tuning" class="gap-2 text-xs">
					<CpuIcon class="size-4" />
					<span>NIC Tuning</span>
				</Tabs.Trigger>
			</Tabs.List>

			<!-- SQM Tab -->
			<Tabs.Content value="sqm">
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
				/>
			</Tabs.Content>

			<!-- NIC Tuning Tab -->
			<Tabs.Content value="tuning">
				<TrafficTuningTab
					bind:enabled={tuningEnabled}
					bind:interfaces={tuningInterfaces}
					bind:cpuMask={tuningCpuMask}
					bind:rxRing={tuningRxRing}
					bind:txRing={tuningTxRing}
					bind:disableEee={tuningDisableEee}
					bind:udpGroForwarding={tuningUdpGroForwarding}
					bind:rpsFlowEntries={tuningRpsFlowEntries}
					bind:rpsFlowCnt={tuningRpsFlowCnt}
					{availableInterfaces}
					effectiveCpuMask={status?.effective_cpu_mask}
					{detectedLan}
					detectedWan={physicalWan}
				/>
			</Tabs.Content>
		</Tabs.Root>
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
