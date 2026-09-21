<script lang="ts">
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
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	import TrafficTuningTab from "../components/TrafficTuningTab.svelte";

	let status = $state<TrafficStatusResponse | null>(null);
	let serverConfig = $state<TrafficConfig | null>(null);
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);
	let setupStatus = $state<SetupStatusResponse | null>(null);
	let pppoeCfg = $state<PppoeConfig | null>(null);

	let loading = $state(true);
	let saving = $state(false);

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

	// Physical WAN port
	const physicalWan = $derived.by(() => {
		if (pppoeCfg?.wan_iface) return pppoeCfg.wan_iface;
		const tunedWan = status?.tuned_interfaces?.find((i) => i !== detectedLan && !i.startsWith("ppp"));
		if (tunedWan) return tunedWan;
		const found = availableInterfaces.find((i) => i.is_physical && i.name !== detectedLan && !i.name.startsWith("ppp"));
		return found?.name || "wan0";
	});

	// Dirty tracking
	const isDirty = $derived.by(() => {
		if (!serverConfig) return false;
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
			if (!silent) toast.error("Failed to load hardware tuning configuration");
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
				sqm: serverConfig.sqm,
				tuning: {
					enabled: tuningEnabled,
					interfaces: tuningInterfaces,
					cpu_mask: tuningCpuMask || "auto",
					rx_ring: tuningRxRing || "auto",
					tx_ring: tuningTxRing || "auto",
					disable_eee: tuningDisableEee,
					udp_gro_forwarding: tuningUdpGroForwarding,
					rps_flow_entries: Number(tuningRpsFlowEntries) || 32768,
					rps_flow_cnt: Number(tuningRpsFlowCnt) || 4096,
				},
			};

			await trafficUpdateConfig(payload);
			serverConfig = payload;
			syncFormFromConfig(payload);
			toast.success("Hardware NIC tuning applied successfully");

			setTimeout(async () => {
				const s = await trafficStatus().catch(() => null);
				if (s) status = s;
			}, 600);
		} catch (err) {
			toast.error(`Failed to save: ${err instanceof Error ? err.message : String(err)}`);
		} finally {
			saving = false;
		}
	}

	onMount(() => {
		loadAll(false);
	});
</script>

<div class="flex flex-col gap-6 w-full">
	{#if loading && !serverConfig}
		<div class="flex items-center justify-center p-12 text-muted-foreground text-sm">
			<RefreshCwIcon class="size-5 animate-spin mr-2" />
			Loading tuning configuration...
		</div>
	{:else if serverConfig}
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
