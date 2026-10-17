<script lang="ts">
	import * as Tabs from "$lib/components/ui/tabs";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import {
		pppoeStatus,
		pppoeConfig,
		pppoeUpdateConfig,
		pppoeReconnect,
		pppoeDisconnect,
		getSetupStatus,
	} from "$lib/api/client";
	import type {
		PppoeConfig,
		PppoeStatusResponse,
		PppoeDataplane,
		PppoeAuthMethod,
		NetworkInterfaceInfo,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";
	import { createPolling } from "$lib/utils/polling";

	import PlugZapIcon from "@lucide/svelte/icons/plug-zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PlayIcon from "@lucide/svelte/icons/play";
	import KeyIcon from "@lucide/svelte/icons/key";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";

	import PppoeStatsCards from "./components/PppoeStatsCards.svelte";
	import PppoeConnectionTab from "./components/PppoeConnectionTab.svelte";
	import PppoeAccelerationTab from "./components/PppoeAccelerationTab.svelte";
	import PppoeTimersTab from "./components/PppoeTimersTab.svelte";
	import PppoeEbpfModal from "./components/PppoeEbpfModal.svelte";
	import FloatingSaveBar from "$lib/components/FloatingSaveBar.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";

	// Page state
	let status = $state<PppoeStatusResponse | null>(null);
	let config = $state<PppoeConfig | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let reconnecting = $state(false);
	let disconnecting = $state(false);
	let showEbpfWarningDialog = $state(false);
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);
	let activeTab = $state("connection");

	// Derived list of selectable interfaces ensuring currently selected iface is present
	let interfaceOptions = $derived.by(() => {
		const list = [...availableInterfaces];
		if (formWanIface && !list.some((i) => i.name === formWanIface)) {
			list.unshift({
				name: formWanIface,
				mac: null,
				is_physical: false,
				is_up: true,
				carrier_up: true,
				ips: [],
				bus_type: "configured",
			});
		}
		return list;
	});

	// Editable form fields
	let formEnabled = $state(false);
	let formDataplane = $state<PppoeDataplane>("kernel");
	let formWanIface = $state("eth1");
	let formUsername = $state("");
	let formPassword = $state("");
	let formAuth = $state<PppoeAuthMethod>("chap_md5");
	let formServiceName = $state("");
	let formAcName = $state("");
	let formMru = $state(1492);
	let formEchoInterval = $state(20);
	let formEchoMaxFailures = $state(5);
	let formReconnectDelay = $state(10);
	let formSendPadt = $state(true);
	let formPadiRetries = $state(5);
	let formPadiTimeout = $state(3);

	// Terminal ONT Probe form fields
	let formProbeEnabled = $state(false);
	let formProbeTargetIp = $state("192.168.1.1");
	let formProbeSenderIp = $state("");
	let formProbeIface = $state("");
	let formProbeTimeoutMs = $state(1000);
	let formProbePollIntervalSecs = $state(2);
	let formProbeMaxWaitSecs = $state(10);

	// Dirty tracking
	let isDirty = $derived.by(() => {
		if (!config) return false;
		if (formEnabled !== config.enabled) return true;
		if (formDataplane !== (config.dataplane ?? "kernel")) return true;
		const defaultWan = availableInterfaces[0]?.name || "eth1";
		if (formWanIface !== (config.wan_iface || defaultWan)) return true;
		if (formUsername !== config.username) return true;
		if (formPassword !== config.password) return true;

		const cfgAuth = String(config.auth || "chap_md5").toLowerCase();
		const normCfgAuth = cfgAuth === "chapmd5" ? "chap_md5" : cfgAuth;
		if (formAuth !== normCfgAuth) return true;

		if (formServiceName !== (config.service_name ?? "")) return true;
		if (formAcName !== (config.ac_name ?? "")) return true;
		if (Number(formMru) !== config.mru) return true;
		if (Number(formEchoInterval) !== config.lcp_echo_interval_secs) return true;
		if (Number(formEchoMaxFailures) !== config.lcp_echo_max_failures) return true;
		if (Number(formReconnectDelay) !== config.reconnect_delay_secs) return true;
		if (formSendPadt !== config.send_padt_on_shutdown) return true;
		if (Number(formPadiRetries) !== config.discovery_padi_retries) return true;
		if (Number(formPadiTimeout) !== config.discovery_padi_timeout_secs) return true;

		const tp = config.terminal_probe;
		if (formProbeEnabled !== (tp?.enabled ?? false)) return true;
		if (formProbeTargetIp !== (tp?.target_ip ?? "192.168.1.1")) return true;
		if (formProbeSenderIp !== (tp?.sender_ip ?? "")) return true;
		if (formProbeIface !== (tp?.iface ?? "")) return true;
		if (Number(formProbeTimeoutMs) !== (tp?.timeout_ms ?? 1000)) return true;
		if (Number(formProbePollIntervalSecs) !== (tp?.poll_interval_secs ?? 2)) return true;
		if (Number(formProbeMaxWaitSecs) !== (tp?.max_wait_secs ?? 10)) return true;

		return false;
	});

	function syncFormFromConfig(c: PppoeConfig) {
		formEnabled = c.enabled;
		formDataplane = c.dataplane ?? "kernel";
		formWanIface = c.wan_iface || availableInterfaces[0]?.name || "eth1";
		formUsername = c.username;
		formPassword = c.password;
		const rawAuth = String(c.auth || "chap_md5").toLowerCase();
		formAuth = (rawAuth === "chapmd5" ? "chap_md5" : rawAuth) as PppoeAuthMethod;
		formServiceName = c.service_name ?? "";
		formAcName = c.ac_name ?? "";
		formMru = c.mru;
		formEchoInterval = c.lcp_echo_interval_secs;
		formEchoMaxFailures = c.lcp_echo_max_failures;
		formReconnectDelay = c.reconnect_delay_secs;
		formSendPadt = c.send_padt_on_shutdown;
		formPadiRetries = c.discovery_padi_retries;
		formPadiTimeout = c.discovery_padi_timeout_secs;

		const tp = c.terminal_probe;
		formProbeEnabled = tp?.enabled ?? false;
		formProbeTargetIp = tp?.target_ip ?? "192.168.1.1";
		formProbeSenderIp = tp?.sender_ip ?? "";
		formProbeIface = tp?.iface ?? "";
		formProbeTimeoutMs = tp?.timeout_ms ?? 1000;
		formProbePollIntervalSecs = tp?.poll_interval_secs ?? 2;
		formProbeMaxWaitSecs = tp?.max_wait_secs ?? 10;
	}

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const fetchSetup = !silent || availableInterfaces.length === 0;
			const [s, c, setupRes] = await Promise.all([
				pppoeStatus().catch(() => null),
				pppoeConfig().catch(() => null),
				fetchSetup ? getSetupStatus().catch(() => null) : Promise.resolve(null),
			]);
			status = s;

			if (setupRes?.interfaces) {
				availableInterfaces = setupRes.interfaces;
			}

			if (c) {
				if (!config || !isDirty) {
					config = c;
					syncFormFromConfig(c);
				} else {
					config = c;
				}
			}
		} catch {
			if (!silent) toast.error("Failed to load PPPoE configuration");
		} finally {
			if (!silent) loading = false;
		}
	}

	function handleDiscard() {
		if (config) {
			syncFormFromConfig(config);
			toast.info("Changes reverted to active configuration");
		}
	}

	async function handleSave() {
		if (!isDirty) return;
		saving = true;
		try {
			const payload: PppoeConfig = {
				enabled: formEnabled,
				dataplane: formDataplane,
				wan_iface: formWanIface.trim(),
				username: formUsername.trim(),
				password: formPassword,
				service_name: formServiceName.trim() ? formServiceName.trim() : null,
				ac_name: formAcName.trim() ? formAcName.trim() : null,
				auth: formAuth,
				mru: Number(formMru) || 1492,
				lcp_echo_interval_secs: Number(formEchoInterval) || 20,
				lcp_echo_max_failures: Number(formEchoMaxFailures) || 5,
				reconnect_delay_secs: Number(formReconnectDelay) || 10,
				send_padt_on_shutdown: formSendPadt,
				discovery_padi_retries: Number(formPadiRetries) || 5,
				discovery_padi_timeout_secs: Number(formPadiTimeout) || 3,
				terminal_probe: {
					enabled: formProbeEnabled,
					target_ip: formProbeTargetIp.trim() || "192.168.1.1",
					sender_ip: formProbeSenderIp.trim() ? formProbeSenderIp.trim() : null,
					iface: formProbeIface.trim() ? formProbeIface.trim() : null,
					timeout_ms: Number(formProbeTimeoutMs) || 1000,
					poll_interval_secs: Number(formProbePollIntervalSecs) || 2,
					max_wait_secs: Number(formProbeMaxWaitSecs) || 10,
				},
				nftables: config?.nftables ?? {
					enabled: true,
					table_name: "lanforge_pppoe",
					flow_offload: true,
					mss_clamping: true,
					bypass_dns: true,
					bypass_vowifi: true,
					masquerade: true,
					custom_rules_file: null,
				},
			};

			await pppoeUpdateConfig(payload);
			toast.success("PPPoE configuration saved and reloaded");
			await loadAll(true);
		} catch {
			toast.error("Failed to save PPPoE configuration");
		} finally {
			saving = false;
		}
	}

	async function handleConnectOrReconnect() {
		reconnecting = true;
		try {
			await pppoeReconnect();
			toast.success(
				status?.state === "connected"
					? "PPPoE reconnection triggered"
					: "PPPoE connection initiated",
			);
			await loadAll(true);
		} catch {
			toast.error("Failed to trigger PPPoE connection");
		} finally {
			reconnecting = false;
		}
	}

	async function handleDisconnect() {
		disconnecting = true;
		try {
			await pppoeDisconnect();
			toast.success("PPPoE disconnection triggered");
			await loadAll(true);
		} catch {
			toast.error("Failed to disconnect PPPoE session");
		} finally {
			disconnecting = false;
		}
	}

	function handleDataplaneSelect(mode: PppoeDataplane) {
		if (mode === "ebpf" && formDataplane !== "ebpf") {
			showEbpfWarningDialog = true;
		} else {
			formDataplane = mode;
		}
	}

	onMount(() => {
		loadAll();
		const stopPolling = createPolling(() => loadAll(true), 4000);
		return () => {
			stopPolling();
		};
	});
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- Page Header -->
	<PageHeader
		title="PPPoE WAN Concentrator"
		description="Carrier broadband link orchestration, credentials, MSS clamping, and eBPF Fast-Path."
		icon={PlugZapIcon}
	>
		{#snippet badge()}
			{#if status?.state === "connected"}
				<StatusBadge
					variant="online"
					showDot={true}
					pulse={true}
					text="Connected"
				/>
			{:else if status?.state === "reconnecting"}
				<StatusBadge
					variant="starting"
					showDot={true}
					pulse={true}
					text="Reconnecting"
				/>
			{:else if status?.state === "authenticating"}
				<StatusBadge
					variant="warning"
					showDot={true}
					pulse={true}
					text="Authenticating"
				/>
			{:else if status?.state === "discovering"}
				<StatusBadge
					variant="starting"
					showDot={true}
					pulse={true}
					text="Discovering BNG"
				/>
			{:else if status?.state === "waiting_for_carrier"}
				<StatusBadge
					variant="warning"
					showDot={true}
					pulse={true}
					text="Waiting for Carrier"
				/>
			{:else if status?.state === "waiting_for_terminal"}
				<StatusBadge
					variant="warning"
					showDot={true}
					pulse={true}
					text="Waiting for ONT"
				/>
			{:else}
				<StatusBadge
					variant="dormant"
					text="Disconnected"
				/>
			{/if}
		{/snippet}

		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading}
				class="h-8 text-xs gap-1.5 transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={loading ? "animate-spin size-3.5" : "size-3.5"} data-icon="inline-start" />
				<span>Refresh</span>
			</Button>

			<Button
				variant={status?.state === "connected" ? "outline" : "default"}
				size="sm"
				onclick={handleConnectOrReconnect}
				disabled={reconnecting || loading}
				class="h-8 text-xs gap-1.5 transition-transform duration-150 active:scale-95 transform-gpu shadow-sm"
			>
				{#if reconnecting}
					<RefreshCwIcon class="animate-spin size-3.5" data-icon="inline-start" />
					<span>Connecting...</span>
				{:else if status?.state === "connected"}
					<RefreshCwIcon class="size-3.5" data-icon="inline-start" />
					<span>Reconnect</span>
				{:else}
					<PlayIcon class="size-3.5" data-icon="inline-start" />
					<span>Connect</span>
				{/if}
			</Button>

			<Button
				variant="destructive"
				size="sm"
				onclick={handleDisconnect}
				disabled={disconnecting || loading || status?.state === "disconnected"}
				class="h-8 text-xs gap-1.5 transition-transform duration-150 active:scale-95 transform-gpu"
			>
				{#if disconnecting}
					<RefreshCwIcon class="animate-spin size-3.5" data-icon="inline-start" />
					<span>Disconnecting...</span>
				{:else}
					<XCircleIcon class="size-3.5" data-icon="inline-start" />
					<span>Disconnect</span>
				{/if}
			</Button>
		{/snippet}
	</PageHeader>

	<!-- Top Stats Overview Grid -->
	<PppoeStatsCards
		{status}
		{config}
		{formDataplane}
		{formWanIface}
		{formAuth}
		{formServiceName}
	/>

	<!-- Configuration Tabs -->
	<Tabs.Root bind:value={activeTab} class="w-full">
		<Tabs.List class="flex w-full overflow-x-auto justify-start sm:inline-flex sm:w-auto p-1 mb-4 no-scrollbar">
			<Tabs.Trigger value="connection">Uplink & Credentials</Tabs.Trigger>
			{#if capabilitiesState.isCompiled("ebpf")}
				<Tabs.Trigger value="acceleration">Dataplane & Acceleration</Tabs.Trigger>
			{/if}
			<Tabs.Trigger value="timers">Parameters & Timers</Tabs.Trigger>
		</Tabs.List>

		<Tabs.Content value="connection">
			<PppoeConnectionTab
				bind:formEnabled
				bind:formWanIface
				bind:formAuth
				bind:formUsername
				bind:formPassword
				bind:formServiceName
				bind:formAcName
				{interfaceOptions}
				bind:formProbeEnabled
				bind:formProbeTargetIp
				bind:formProbeSenderIp
				bind:formProbeIface
				bind:formProbeTimeoutMs
				bind:formProbePollIntervalSecs
				bind:formProbeMaxWaitSecs
			/>
		</Tabs.Content>

		{#if capabilitiesState.isCompiled("ebpf")}
			<Tabs.Content value="acceleration">
				<PppoeAccelerationTab
					bind:formDataplane
					onSelectEbpf={() => handleDataplaneSelect("ebpf")}
				/>
			</Tabs.Content>
		{/if}

		<Tabs.Content value="timers">
			<PppoeTimersTab
				bind:formMru
				bind:formEchoInterval
				bind:formEchoMaxFailures
				bind:formReconnectDelay
				bind:formSendPadt
				bind:formPadiRetries
				bind:formPadiTimeout
			/>
		</Tabs.Content>
	</Tabs.Root>

	<!-- eBPF Modal Dialog -->
	<PppoeEbpfModal
		bind:open={showEbpfWarningDialog}
		onConfirm={() => { formDataplane = "ebpf"; }}
	/>

	<!-- Floating GPU-Accelerated Save/Discard Action Island -->
	<FloatingSaveBar
		show={isDirty}
		title="Unsaved PPPoE Changes"
		description="Configuration differs from active runtime parameters"
		saveLabel="Save Configuration"
		{saving}
		disabled={loading}
		onDiscard={handleDiscard}
		onSave={handleSave}
	/>
</div>
