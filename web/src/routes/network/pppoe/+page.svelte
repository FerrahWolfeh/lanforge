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
	import { onMount, onDestroy } from "svelte";
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";

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
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

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
	}

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const [s, c, setupRes] = await Promise.all([
				pppoeStatus().catch(() => null),
				pppoeConfig().catch(() => null),
				getSetupStatus().catch(() => null),
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
		refreshInterval = setInterval(() => {
			loadAll(true);
		}, 4000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- Page Header -->
	<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
		<div class="flex items-center gap-3.5">
			<div class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0">
				<PlugZapIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-1">
				<div class="flex flex-wrap items-center gap-2.5">
					<h1 class="text-2xl font-bold tracking-tight">PPPoE WAN Concentrator</h1>
					{#if status?.state === "connected"}
						<Badge
							variant="outline"
							class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
						>
							<span class="relative flex size-2 mr-1.5">
								<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
								<span class="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
							</span>
							Connected
						</Badge>
					{:else if status?.state === "reconnecting"}
						<Badge
							variant="outline"
							class="border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 font-medium text-xs"
						>
							<RefreshCwIcon class="size-3 mr-1 animate-spin" />
							Reconnecting
						</Badge>
					{:else if status?.state === "authenticating"}
						<Badge
							variant="outline"
							class="border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 font-medium text-xs"
						>
							<KeyIcon class="size-3 mr-1 animate-pulse" />
							Authenticating
						</Badge>
					{:else}
						<Badge variant="secondary" class="text-muted-foreground text-xs font-medium">
							Disconnected
						</Badge>
					{/if}
				</div>
				<p class="text-sm text-muted-foreground">
					Carrier broadband link orchestration, credentials, MSS clamping, and eBPF Fast-Path.
				</p>
			</div>
		</div>

		<div class="flex flex-wrap items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={loading ? "animate-spin size-3.5" : "size-3.5"} data-icon="inline-start" />
				Refresh
			</Button>
			<Button
				variant={status?.state === "connected" ? "outline" : "default"}
				size="sm"
				onclick={handleConnectOrReconnect}
				disabled={reconnecting || loading}
				class="transition-transform duration-150 active:scale-95 transform-gpu shadow-sm"
			>
				{#if reconnecting}
					<RefreshCwIcon class="animate-spin size-3.5" data-icon="inline-start" />
					Connecting...
				{:else if status?.state === "connected"}
					<RefreshCwIcon class="size-3.5" data-icon="inline-start" />
					Reconnect
				{:else}
					<PlayIcon class="size-3.5" data-icon="inline-start" />
					Connect
				{/if}
			</Button>
			<Button
				variant="destructive"
				size="sm"
				onclick={handleDisconnect}
				disabled={disconnecting || loading || status?.state === "disconnected"}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				{#if disconnecting}
					<RefreshCwIcon class="animate-spin size-3.5" data-icon="inline-start" />
					Disconnecting...
				{:else}
					<XCircleIcon class="size-3.5" data-icon="inline-start" />
					Disconnect
				{/if}
			</Button>
		</div>
	</div>

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
			<Tabs.Trigger value="acceleration">Dataplane & Acceleration</Tabs.Trigger>
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
			/>
		</Tabs.Content>

		<Tabs.Content value="acceleration">
			<PppoeAccelerationTab
				bind:formDataplane
				onSelectEbpf={() => handleDataplaneSelect("ebpf")}
			/>
		</Tabs.Content>

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
