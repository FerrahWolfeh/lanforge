<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Tabs from "$lib/components/ui/tabs";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import * as Select from "$lib/components/ui/select";
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
	import ZapIcon from "@lucide/svelte/icons/zap";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import KeyIcon from "@lucide/svelte/icons/key";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ServerIcon from "@lucide/svelte/icons/server";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";

	// Page state
	let status = $state<PppoeStatusResponse | null>(null);
	let config = $state<PppoeConfig | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let reconnecting = $state(false);
	let disconnecting = $state(false);
	let showPassword = $state(false);
	let showEbpfWarningDialog = $state(false);
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);
	let activeTab = $state("uplink");
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

	// Editable form fields (cloned from config)
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

	// nftables form fields
	let formNftEnabled = $state(true);
	let formNftFlowOffload = $state(true);
	let formNftMssClamping = $state(true);
	let formNftBypassDns = $state(true);
	let formNftBypassVowifi = $state(true);
	let formNftMasquerade = $state(true);

	function formatAuthMethod(
		auth: PppoeAuthMethod | string | null | undefined,
	): string {
		if (!auth) return "None";
		switch (auth.toLowerCase()) {
			case "chap_md5":
			case "chapmd5":
			case "chap":
				return "CHAP-MD5";
			case "pap":
				return "PAP";
			case "none":
				return "None";
			default:
				return auth.toUpperCase();
		}
	}

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
		if (Number(formEchoInterval) !== config.lcp_echo_interval_secs)
			return true;
		if (Number(formEchoMaxFailures) !== config.lcp_echo_max_failures)
			return true;
		if (Number(formReconnectDelay) !== config.reconnect_delay_secs)
			return true;
		if (formSendPadt !== config.send_padt_on_shutdown) return true;
		if (Number(formPadiRetries) !== config.discovery_padi_retries)
			return true;
		if (Number(formPadiTimeout) !== config.discovery_padi_timeout_secs)
			return true;

		if (formNftEnabled !== (config.nftables?.enabled ?? true)) return true;
		if (formNftFlowOffload !== (config.nftables?.flow_offload ?? true))
			return true;
		if (formNftMssClamping !== (config.nftables?.mss_clamping ?? true))
			return true;
		if (formNftBypassDns !== (config.nftables?.bypass_dns ?? true))
			return true;
		if (formNftBypassVowifi !== (config.nftables?.bypass_vowifi ?? true))
			return true;
		if (formNftMasquerade !== (config.nftables?.masquerade ?? true))
			return true;

		return false;
	});

	function syncFormFromConfig(c: PppoeConfig) {
		formEnabled = c.enabled;
		formDataplane = c.dataplane ?? "kernel";
		formWanIface = c.wan_iface || availableInterfaces[0]?.name || "eth1";
		formUsername = c.username;
		formPassword = c.password;
		const rawAuth = String(c.auth || "chap_md5").toLowerCase();
		formAuth = (
			rawAuth === "chapmd5" ? "chap_md5" : rawAuth
		) as PppoeAuthMethod;
		formServiceName = c.service_name ?? "";
		formAcName = c.ac_name ?? "";
		formMru = c.mru;
		formEchoInterval = c.lcp_echo_interval_secs;
		formEchoMaxFailures = c.lcp_echo_max_failures;
		formReconnectDelay = c.reconnect_delay_secs;
		formSendPadt = c.send_padt_on_shutdown;
		formPadiRetries = c.discovery_padi_retries;
		formPadiTimeout = c.discovery_padi_timeout_secs;

		formNftEnabled = c.nftables?.enabled ?? true;
		formNftFlowOffload = c.nftables?.flow_offload ?? true;
		formNftMssClamping = c.nftables?.mss_clamping ?? true;
		formNftBypassDns = c.nftables?.bypass_dns ?? true;
		formNftBypassVowifi = c.nftables?.bypass_vowifi ?? true;
		formNftMasquerade = c.nftables?.masquerade ?? true;
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
				// Only overwrite form fields on initial load or if user hasn't made dirty edits
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
				service_name: formServiceName.trim()
					? formServiceName.trim()
					: null,
				ac_name: formAcName.trim() ? formAcName.trim() : null,
				auth: formAuth,
				mru: Number(formMru) || 1492,
				lcp_echo_interval_secs: Number(formEchoInterval) || 20,
				lcp_echo_max_failures: Number(formEchoMaxFailures) || 5,
				reconnect_delay_secs: Number(formReconnectDelay) || 10,
				send_padt_on_shutdown: formSendPadt,
				discovery_padi_retries: Number(formPadiRetries) || 5,
				discovery_padi_timeout_secs: Number(formPadiTimeout) || 3,
				nftables: {
					enabled: formNftEnabled,
					table_name:
						config?.nftables?.table_name ?? "lanforge_pppoe",
					flow_offload: formNftFlowOffload,
					mss_clamping: formNftMssClamping,
					bypass_dns: formNftBypassDns,
					bypass_vowifi: formNftBypassVowifi,
					masquerade: formNftMasquerade,
					custom_rules_file:
						config?.nftables?.custom_rules_file ?? null,
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

	function formatUptime(seconds: number | null | undefined): string {
		if (!seconds || seconds <= 0) return "0s";
		const days = Math.floor(seconds / 86400);
		const hours = Math.floor((seconds % 86400) / 3600);
		const minutes = Math.floor((seconds % 3600) / 60);
		const sec = seconds % 60;

		if (days > 0) return `${days}d ${hours}h ${minutes}m`;
		if (hours > 0) return `${hours}h ${minutes}m`;
		if (minutes > 0) return `${minutes}m ${sec}s`;
		return `${sec}s`;
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
	<div
		class="flex flex-col sm:flex-row sm:items-center justify-between gap-4"
	>
		<div class="flex items-center gap-3.5">
			<div
				class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0"
			>
				<PlugZapIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-1">
				<div class="flex flex-wrap items-center gap-2.5">
					<h1 class="text-2xl font-bold tracking-tight">
						PPPoE WAN Concentrator
					</h1>
					{#if status?.state === "connected"}
						<Badge
							variant="outline"
							class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
						>
							<span class="relative flex size-2 mr-1.5">
								<span
									class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"
								></span>
								<span
									class="relative inline-flex rounded-full size-2 bg-emerald-500"
								></span>
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
						<Badge
							variant="secondary"
							class="text-muted-foreground text-xs font-medium"
						>
							Disconnected
						</Badge>
					{/if}
				</div>
				<p class="text-sm text-muted-foreground">
					Carrier broadband link orchestration, credentials, MSS
					clamping, and eBPF Fast-Path.
				</p>
			</div>
		</div>

		<div class="flex items-center gap-2 shrink-0">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon
					class={loading ? "animate-spin" : ""}
					data-icon="inline-start"
				/>
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
					<RefreshCwIcon
						class="animate-spin"
						data-icon="inline-start"
					/>
					Connecting...
				{:else if status?.state === "connected"}
					<RefreshCwIcon data-icon="inline-start" />
					Reconnect
				{:else}
					<PlayIcon data-icon="inline-start" />
					Connect
				{/if}
			</Button>
			<Button
				variant="destructive"
				size="sm"
				onclick={handleDisconnect}
				disabled={disconnecting ||
					loading ||
					status?.state === "disconnected"}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<XCircleIcon data-icon="inline-start" />
				Disconnect
			</Button>
		</div>
	</div>

	<!-- Status Overview Bento Grid (Balanced 3-Column Layout) -->
	{#if loading && !status}
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
			<Skeleton class="h-36 rounded-2xl" />
			<Skeleton class="h-36 rounded-2xl" />
			<Skeleton class="h-36 rounded-2xl" />
		</div>
	{:else}
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
			<!-- Session & Uplink Card -->
			<Card.Root class="relative overflow-hidden">
				<Card.Header class="pb-2">
					<Card.Description
						class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider"
					>
						<span>Session & Uplink</span>
						<ActivityIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title
						class="flex items-center gap-2 text-lg font-bold"
					>
						{#if status?.state === "connected"}
							<CheckCircleIcon
								class="size-5 text-emerald-500 shrink-0"
							/>
							<span class="font-mono text-foreground"
								>{status.interface ?? "ppp0"}</span
							>
							<span
								class="text-xs font-normal text-muted-foreground"
								>via {status.wan_iface ?? formWanIface}</span
							>
						{:else if status?.state === "reconnecting"}
							<RefreshCwIcon
								class="size-5 text-amber-500 shrink-0 animate-spin"
							/>
							<span
								class="text-base text-amber-600 dark:text-amber-400"
								>Reconnecting...</span
							>
						{:else if status?.state === "authenticating"}
							<KeyIcon
								class="size-5 text-amber-500 shrink-0 animate-pulse"
							/>
							<span
								class="text-base text-amber-600 dark:text-amber-400"
								>Authenticating...</span
							>
						{:else}
							<XCircleIcon
								class="size-5 text-muted-foreground shrink-0"
							/>
							<span
								class="text-base text-muted-foreground font-normal"
								>Offline / Idle</span
							>
						{/if}
					</Card.Title>
				</Card.Header>
				<Card.Content class="flex flex-col gap-2.5 pt-1 text-xs">
					<div
						class="grid grid-cols-2 gap-x-4 gap-y-2 border-t pt-2.5"
					>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>Uptime</span
							>
							<span class="font-medium text-foreground"
								>{formatUptime(status?.uptime_secs)}</span
							>
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>Dataplane</span
							>
							<div>
								{#if (status?.dataplane ?? formDataplane) === "ebpf"}
									<Badge
										variant="outline"
										class="border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-400 font-mono text-[10px] px-1.5 py-0"
									>
										<ZapIcon
											class="size-2.5 mr-1 text-amber-500"
										/>
										eBPF TC+XDP
									</Badge>
								{:else}
									<Badge
										variant="secondary"
										class="font-mono text-[10px] px-1.5 py-0"
									>
										<CpuIcon
											class="size-2.5 mr-1 text-blue-500"
										/>
										Linux Kernel
									</Badge>
								{/if}
							</div>
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>Session ID</span
							>
							<span class="font-mono text-foreground"
								>{status?.session_id
									? `0x${status.session_id.toString(16).padStart(4, "0")}`
									: "—"}</span
							>
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>Physical Port</span
							>
							<span class="font-mono text-foreground font-medium"
								>{status?.wan_iface ?? formWanIface}</span
							>
						</div>
					</div>

					{#if status?.reconnect_attempts && status.reconnect_attempts > 0}
						<div
							class="flex items-center gap-1.5 rounded-md bg-amber-500/10 px-2 py-1 text-[11px] text-amber-600 dark:text-amber-400"
						>
							<RefreshCwIcon
								class="size-3 shrink-0 animate-spin"
							/>
							<span
								>Reconnect attempts: {status.reconnect_attempts}</span
							>
						</div>
					{/if}
					{#if status?.last_error}
						<div
							class="flex items-center gap-1.5 rounded-md bg-destructive/10 px-2 py-1 text-[11px] text-destructive"
						>
							<AlertCircleIcon class="size-3 shrink-0" />
							<span class="truncate">{status.last_error}</span>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>

			<!-- Network IP Configuration Card -->
			<Card.Root class="relative overflow-hidden">
				<Card.Header class="pb-2">
					<Card.Description
						class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider"
					>
						<span>Assigned IP Lease</span>
						<GlobeIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title
						class="text-lg font-bold font-mono tracking-tight text-foreground truncate"
					>
						{#if status?.local_ip}
							{status.local_ip}
						{:else}
							<span
								class="text-muted-foreground text-sm font-normal"
								>Waiting for IPCP...</span
							>
						{/if}
					</Card.Title>
				</Card.Header>
				<Card.Content class="flex flex-col gap-2.5 pt-1 text-xs">
					<div
						class="grid grid-cols-2 gap-x-4 gap-y-2 border-t pt-2.5"
					>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>Gateway (Peer IP)</span
							>
							<span
								class="font-mono font-medium text-foreground truncate"
								>{status?.peer_ip ?? "—"}</span
							>
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>Negotiated MRU</span
							>
							<span class="font-mono font-medium text-foreground"
								>{status?.mru
									? `${status.mru} bytes`
									: "—"}</span
							>
						</div>
					</div>
					<div class="flex flex-col gap-1 border-t pt-2">
						<span class="text-[11px] text-muted-foreground"
							>ISP DNS Fallback</span
						>
						{#if status?.dns_servers && status.dns_servers.length > 0}
							<div class="flex flex-wrap gap-1.5">
								{#each status.dns_servers as dns}
									<Badge
										variant="secondary"
										class="font-mono text-[10px] font-normal px-1.5 py-0"
									>
										{dns}
									</Badge>
								{/each}
							</div>
						{:else}
							<span
								class="font-mono text-[11px] text-muted-foreground/80"
								>None provided by ISP</span
							>
						{/if}
					</div>
				</Card.Content>
			</Card.Root>

			<!-- AC & Remote Details Card -->
			<Card.Root class="relative overflow-hidden">
				<Card.Header class="pb-2">
					<Card.Description
						class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider"
					>
						<span>Access Concentrator</span>
						<ServerIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title
						class="truncate text-lg font-bold text-foreground"
						title={status?.ac_name ?? "None"}
					>
						{status?.ac_name ||
							(status?.state === "connected"
								? "ISP Concentrator"
								: "Searching...")}
					</Card.Title>
				</Card.Header>
				<Card.Content class="flex flex-col gap-2.5 pt-1 text-xs">
					<div
						class="grid grid-cols-2 gap-x-4 gap-y-2 border-t pt-2.5"
					>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>AC MAC Address</span
							>
							<span
								class="font-mono font-medium text-foreground truncate"
								>{status?.ac_mac ?? "—"}</span
							>
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-[11px] text-muted-foreground"
								>Auth Method</span
							>
							<div>
								<Badge
									variant="outline"
									class="font-medium text-[10px] px-1.5 py-0"
								>
									{formatAuthMethod(
										status?.auth ??
											config?.auth ??
											formAuth,
									)}
								</Badge>
							</div>
						</div>
					</div>
					<div class="flex flex-col gap-0.5 border-t pt-2">
						<span class="text-[11px] text-muted-foreground"
							>Service Name</span
						>
						<span
							class="font-mono text-[11px] text-foreground truncate"
						>
							{config?.service_name ||
								formServiceName ||
								"Any / Automatic"}
						</span>
					</div>
				</Card.Content>
			</Card.Root>
		</div>
	{/if}

	<!-- Detailed Configuration Tabs -->
	<Tabs.Root bind:value={activeTab} class="flex flex-col gap-4">
		<Tabs.List class="grid w-full grid-cols-3 sm:w-[520px]">
			<Tabs.Trigger
				value="uplink"
				class="flex items-center gap-2 transition-all duration-150 transform-gpu"
			>
				<KeyIcon class="size-4" />
				<span>Connection & ISP</span>
				{#if isDirty}
					<span
						class="size-1.5 rounded-full bg-amber-500 animate-pulse"
					></span>
				{/if}
			</Tabs.Trigger>
			<Tabs.Trigger
				value="acceleration"
				class="flex items-center gap-2 transition-all duration-150 transform-gpu"
			>
				<ZapIcon class="size-4" />
				<span>Acceleration & Dataplane</span>
			</Tabs.Trigger>
			<Tabs.Trigger
				value="timers"
				class="flex items-center gap-2 transition-all duration-150 transform-gpu"
			>
				<SlidersIcon class="size-4" />
				<span>Link & Timers</span>
			</Tabs.Trigger>
		</Tabs.List>

		<!-- Tab 1: Connection & ISP -->
		<Tabs.Content
			value="uplink"
			class="flex flex-col gap-6 focus-visible:outline-none"
		>
			{#if activeTab === "uplink"}
				<div
					in:fly={{ y: 12, duration: 240, easing: cubicOut }}
					class="flex flex-col gap-6 transform-gpu will-change-[transform,opacity]"
				>
					<Card.Root>
						<Card.Header class="pb-3">
							<Card.Title class="text-base"
								>ISP Uplink & Authentication</Card.Title
							>
							<Card.Description>
								Configure your WAN physical port, subscriber
								login credentials, and authentication protocol.
							</Card.Description>
						</Card.Header>
						<Card.Content class="flex flex-col gap-5">
							<!-- Service Enable Switch -->
							<div
								class="flex items-center justify-between rounded-xl border p-4 bg-muted/20"
							>
								<div class="flex flex-col gap-0.5">
									<Label class="text-sm font-semibold"
										>Enable PPPoE Client Service</Label
									>
									<p class="text-xs text-muted-foreground">
										When enabled, Lanforge actively
										negotiates and maintains the PPPoE
										session on the physical WAN interface.
									</p>
								</div>
								<Switch bind:checked={formEnabled} />
							</div>

							<div class="grid gap-4 sm:grid-cols-2">
								<!-- WAN Physical Interface Select -->
								<div class="flex flex-col gap-1.5">
									<Label class="text-xs font-medium"
										>Physical WAN Interface</Label
									>
									{#if interfaceOptions.length > 0}
										<Select.Root
											type="single"
											value={formWanIface}
											onValueChange={(val) => {
												if (val) formWanIface = val;
											}}
										>
											<Select.Trigger
												class="h-9 text-xs font-mono"
											>
												{formWanIface ||
													"Select WAN interface..."}
											</Select.Trigger>
											<Select.Content>
												{#each interfaceOptions as iface (iface.name)}
													<Select.Item
														value={iface.name}
														class="text-xs"
													>
														<div
															class="flex items-center justify-between w-full gap-3"
														>
															<div
																class="flex items-center gap-2"
															>
																<span
																	class="font-mono font-medium"
																	>{iface.name}</span
																>
																{#if iface.carrier_up}
																	<span
																		class="size-1.5 rounded-full bg-emerald-500"
																		title="Carrier connected"
																	></span>
																{:else}
																	<span
																		class="size-1.5 rounded-full bg-muted-foreground/40"
																		title="Disconnected"
																	></span>
																{/if}
															</div>
															<div
																class="flex items-center gap-1.5 text-[10px] text-muted-foreground"
															>
																{#if iface.is_physical}
																	<Badge
																		variant="secondary"
																		class="text-[9px] px-1 py-0 font-normal"
																		>Physical</Badge
																	>
																{/if}
																{#if iface.ips && iface.ips.length > 0}
																	<span
																		class="truncate max-w-[120px] font-mono text-[10px]"
																		>{iface
																			.ips[0]}</span
																	>
																{/if}
															</div>
														</div>
													</Select.Item>
												{/each}
											</Select.Content>
										</Select.Root>
									{:else}
										<Input
											id="wan_iface"
											bind:value={formWanIface}
											placeholder="e.g. eth1, end1, eno1"
											class="h-9 font-mono text-xs"
										/>
									{/if}
									<p
										class="text-[11px] text-muted-foreground"
									>
										Port connected to your fiber ONT, modem,
										or upstream switch.
									</p>
								</div>

								<!-- Authentication Protocol Select -->
								<div class="flex flex-col gap-1.5">
									<Label class="text-xs font-medium"
										>Authentication Protocol</Label
									>
									<Select.Root
										type="single"
										value={formAuth}
										onValueChange={(val) => {
											if (val)
												formAuth =
													val as PppoeAuthMethod;
										}}
									>
										<Select.Trigger class="h-9 text-xs">
											{formatAuthMethod(formAuth)}
										</Select.Trigger>
										<Select.Content>
											<Select.Item
												value="chap_md5"
												class="text-xs"
												>CHAP-MD5 (Recommended)</Select.Item
											>
											<Select.Item
												value="pap"
												class="text-xs"
												>PAP (Plaintext Password)</Select.Item
											>
											<Select.Item
												value="none"
												class="text-xs"
												>None (Unauthenticated)</Select.Item
											>
										</Select.Content>
									</Select.Root>
									<p
										class="text-[11px] text-muted-foreground"
									>
										Most fiber and broadband ISPs require
										CHAP-MD5 authentication.
									</p>
								</div>

								<!-- PPPoE Username -->
								<div class="flex flex-col gap-1.5">
									<Label
										for="username"
										class="text-xs font-medium"
										>PPPoE Username</Label
									>
									<Input
										id="username"
										bind:value={formUsername}
										placeholder="cliente@provedor.com.br"
										class="h-9 text-xs font-mono"
									/>
								</div>

								<!-- PPPoE Password -->
								<div class="flex flex-col gap-1.5">
									<Label
										for="password"
										class="text-xs font-medium"
										>PPPoE Password</Label
									>
									<div class="relative">
										<Input
											id="password"
											type={showPassword
												? "text"
												: "password"}
											bind:value={formPassword}
											placeholder="••••••••"
											class="h-9 text-xs font-mono pr-10"
										/>
										<button
											type="button"
											class="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground transition-colors"
											onclick={() =>
												(showPassword = !showPassword)}
										>
											{#if showPassword}
												<EyeOffIcon class="size-4" />
											{:else}
												<EyeIcon class="size-4" />
											{/if}
										</button>
									</div>
								</div>

								<!-- Service Name -->
								<div class="flex flex-col gap-1.5">
									<Label
										for="service_name"
										class="text-xs font-medium"
										>Service Name (Optional)</Label
									>
									<Input
										id="service_name"
										bind:value={formServiceName}
										placeholder="Leave empty for any"
										class="h-9 text-xs"
									/>
									<p
										class="text-[11px] text-muted-foreground"
									>
										Specifies the requested ISP service tag.
										Leave empty to accept any.
									</p>
								</div>

								<!-- Access Concentrator Name -->
								<div class="flex flex-col gap-1.5">
									<Label
										for="ac_name"
										class="text-xs font-medium"
										>Access Concentrator Name (Optional)</Label
									>
									<Input
										id="ac_name"
										bind:value={formAcName}
										placeholder="Leave empty for any"
										class="h-9 text-xs"
									/>
									<p
										class="text-[11px] text-muted-foreground"
									>
										Filter discovery to a specific BRAS
										hostname. Leave empty for fastest
										response.
									</p>
								</div>
							</div>
						</Card.Content>
					</Card.Root>
				</div>
			{/if}
		</Tabs.Content>

		<!-- Tab 2: Acceleration & Dataplane -->
		<Tabs.Content
			value="acceleration"
			class="flex flex-col gap-6 focus-visible:outline-none"
		>
			{#if activeTab === "acceleration"}
				<div
					in:fly={{ y: 12, duration: 240, easing: cubicOut }}
					class="flex flex-col gap-6 transform-gpu will-change-[transform,opacity]"
				>
					<!-- Data Plane Architecture Card -->
					<Card.Root>
						<Card.Header class="pb-3">
							<Card.Title
								class="text-base flex items-center gap-2"
							>
								<ZapIcon class="size-5 text-primary" />
								Data Plane Architecture Selection
							</Card.Title>
							<Card.Description>
								Choose how PPPoE packets are encapsulated,
								processed, and routed through the network
								subsystem.
							</Card.Description>
						</Card.Header>
						<Card.Content>
							<div class="grid gap-4 md:grid-cols-2">
								<!-- Linux Kernel Mode Option -->
								<div
									class="relative cursor-pointer rounded-xl border p-4 transition-all duration-200 hover:scale-[1.01] active:scale-[0.99] transform-gpu will-change-transform flex flex-col gap-2 {formDataplane ===
									'kernel'
										? 'border-primary bg-primary/5 shadow-sm'
										: 'border-border/60 hover:bg-muted/10'}"
									onclick={() => (formDataplane = "kernel")}
									role="button"
									tabindex="0"
									onkeydown={(e) =>
										e.key === "Enter" &&
										(formDataplane = "kernel")}
								>
									<div
										class="flex items-center justify-between"
									>
										<div
											class="flex items-center gap-2 font-semibold text-sm"
										>
											<CpuIcon
												class="size-4 text-blue-500"
											/>
											<span>Standard Linux Kernel</span>
										</div>
										{#if formDataplane === "kernel"}
											<Badge
												variant="default"
												class="bg-primary text-primary-foreground text-xs"
												>Active Mode</Badge
											>
										{:else}
											<Badge
												variant="outline"
												class="text-xs"
												>Recommended</Badge
											>
										{/if}
									</div>
									<p
										class="text-xs text-muted-foreground leading-relaxed"
									>
										Uses upstream <code
											class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono"
											>/dev/ppp</code
										>
										and standard
										<code
											class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono"
											>ppp_generic</code
										> drivers. Highly stable, universal hardware
										compatibility, standard routing, and transparent
										traffic accounting.
									</p>
									<div
										class="flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium mt-1"
									>
										<CheckCircleIcon class="size-3.5" />
										Full support for Flowtable offload and PMTU
										Clamping
									</div>
								</div>

								<!-- eBPF Fast-Path Option -->
								<div
									class="relative cursor-pointer rounded-xl border p-4 transition-all duration-200 hover:scale-[1.01] active:scale-[0.99] transform-gpu will-change-transform flex flex-col gap-2 {formDataplane ===
									'ebpf'
										? 'border-amber-500 bg-amber-500/5 shadow-sm'
										: 'border-border/60 hover:bg-muted/10'}"
									onclick={() =>
										handleDataplaneSelect("ebpf")}
									role="button"
									tabindex="0"
									onkeydown={(e) =>
										e.key === "Enter" &&
										handleDataplaneSelect("ebpf")}
								>
									<div
										class="flex items-center justify-between"
									>
										<div
											class="flex items-center gap-2 font-semibold text-sm text-amber-600 dark:text-amber-400"
										>
											<ZapIcon
												class="size-4 text-amber-500"
											/>
											<span
												>eBPF Fast-Path (Generic XDP +
												TC)</span
											>
										</div>
										{#if formDataplane === "ebpf"}
											<Badge
												variant="outline"
												class="border-amber-500 text-amber-600 text-xs"
												>Active Experimental</Badge
											>
										{:else}
											<Badge
												variant="secondary"
												class="text-xs"
												>Experimental</Badge
											>
										{/if}
									</div>
									<p
										class="text-xs text-muted-foreground leading-relaxed"
									>
										Zero-copy packet decapsulation using
										eBPF TC filters attached directly to the
										physical WAN interface. Extreme
										throughput and sub-millisecond line-rate
										routing with minimal CPU overhead.
									</p>
									<div
										class="flex items-center gap-1.5 text-[11px] text-amber-600 dark:text-amber-400 font-medium mt-1"
									>
										<AlertTriangleIcon class="size-3.5" />
										Requires eBPF kernel support (Generic XDP
										SKB mode)
									</div>
								</div>
							</div>
						</Card.Content>
					</Card.Root>

					<!-- nftables Tuning Card -->
					<Card.Root>
						<Card.Header class="pb-3">
							<Card.Title
								class="text-base flex items-center gap-2"
							>
								<ShieldIcon class="size-5 text-primary" />
								Kernel Router Performance & nftables Tuning
							</Card.Title>
							<Card.Description>
								Automatic router optimizations, TCP MSS
								clamping, Flowtable fast-path, and VoWiFi
								bypass.
							</Card.Description>
						</Card.Header>
						<Card.Content class="flex flex-col gap-4">
							<div
								class="flex items-center justify-between rounded-xl border p-4 bg-muted/20"
							>
								<div class="flex flex-col gap-0.5">
									<Label class="text-sm font-semibold"
										>Apply nftables Router Tuning</Label
									>
									<p class="text-xs text-muted-foreground">
										Automatically injects optimized firewall
										rules, fast routing, and connection
										tracking filters.
									</p>
								</div>
								<Switch bind:checked={formNftEnabled} />
							</div>

							<div
								class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3"
							>
								<div
									class="flex items-center justify-between rounded-xl border p-3"
								>
									<div class="flex flex-col gap-0.5">
										<Label class="text-xs font-medium"
											>Flowtable Offloading</Label
										>
										<p
											class="text-[10px] text-muted-foreground"
										>
											Fast-path TCP/UDP flows in software
											flowtable.
										</p>
									</div>
									<Switch
										bind:checked={formNftFlowOffload}
										disabled={!formNftEnabled}
									/>
								</div>

								<div
									class="flex items-center justify-between rounded-xl border p-3"
								>
									<div class="flex flex-col gap-0.5">
										<Label class="text-xs font-medium"
											>TCP MSS Clamping (1452)</Label
										>
										<p
											class="text-[10px] text-muted-foreground"
										>
											Prevents PMTU discovery blackholes.
										</p>
									</div>
									<Switch
										bind:checked={formNftMssClamping}
										disabled={!formNftEnabled}
									/>
								</div>

								<div
									class="flex items-center justify-between rounded-xl border p-3"
								>
									<div class="flex flex-col gap-0.5">
										<Label class="text-xs font-medium"
											>DNS Port 53 / 853 Bypass</Label
										>
										<p
											class="text-[10px] text-muted-foreground"
										>
											Ensures local resolver analytics
											remain accurate.
										</p>
									</div>
									<Switch
										bind:checked={formNftBypassDns}
										disabled={!formNftEnabled}
									/>
								</div>

								<div
									class="flex items-center justify-between rounded-xl border p-3"
								>
									<div class="flex flex-col gap-0.5">
										<Label class="text-xs font-medium"
											>VoWiFi / IPsec Bypass</Label
										>
										<p
											class="text-[10px] text-muted-foreground"
										>
											Keeps Wi-Fi Calling tunnels alive
											without drops.
										</p>
									</div>
									<Switch
										bind:checked={formNftBypassVowifi}
										disabled={!formNftEnabled}
									/>
								</div>

								<div
									class="flex items-center justify-between rounded-xl border p-3"
								>
									<div class="flex flex-col gap-0.5">
										<Label class="text-xs font-medium"
											>Outbound NAT Masquerade</Label
										>
										<p
											class="text-[10px] text-muted-foreground"
										>
											Enables source NAT masquerading for
											LAN clients.
										</p>
									</div>
									<Switch
										bind:checked={formNftMasquerade}
										disabled={!formNftEnabled}
									/>
								</div>
							</div>
						</Card.Content>
					</Card.Root>
				</div>
			{/if}
		</Tabs.Content>

		<!-- Tab 3: Link & Timers -->
		<Tabs.Content
			value="timers"
			class="flex flex-col gap-6 focus-visible:outline-none"
		>
			{#if activeTab === "timers"}
				<div
					in:fly={{ y: 12, duration: 240, easing: cubicOut }}
					class="flex flex-col gap-6 transform-gpu will-change-[transform,opacity]"
				>
					<Card.Root>
						<Card.Header class="pb-3">
							<Card.Title
								class="text-base flex items-center gap-2"
							>
								<SlidersIcon class="size-5 text-primary" />
								Link Parameters, MTU & Keepalive Timers
							</Card.Title>
							<Card.Description>
								Fine-tune packet sizing, discovery retry
								timeouts, and LCP keepalive echo intervals.
							</Card.Description>
						</Card.Header>
						<Card.Content class="flex flex-col gap-6">
							<div
								class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3"
							>
								<div class="flex flex-col gap-1.5">
									<Label for="mru" class="text-xs font-medium"
										>Max Receive Unit (MRU / MTU)</Label
									>
									<Input
										id="mru"
										type="number"
										min="576"
										max="1500"
										bind:value={formMru}
										class="h-9 font-mono text-xs"
									/>
									<p
										class="text-[10px] text-muted-foreground"
									>
										Standard PPPoE MTU is 1492 (1500 - 8
										bytes overhead).
									</p>
								</div>

								<div class="flex flex-col gap-1.5">
									<Label
										for="reconnect_delay"
										class="text-xs font-medium"
										>Reconnect Delay (s)</Label
									>
									<Input
										id="reconnect_delay"
										type="number"
										min="1"
										max="300"
										bind:value={formReconnectDelay}
										class="h-9 font-mono text-xs"
									/>
									<p
										class="text-[10px] text-muted-foreground"
									>
										Pause before attempting discovery after
										a link drop.
									</p>
								</div>

								<div class="flex flex-col gap-1.5">
									<Label
										for="echo_interval"
										class="text-xs font-medium"
										>LCP Echo Interval (s)</Label
									>
									<Input
										id="echo_interval"
										type="number"
										min="1"
										max="120"
										bind:value={formEchoInterval}
										class="h-9 font-mono text-xs"
									/>
									<p
										class="text-[10px] text-muted-foreground"
									>
										Frequency of keepalive Echo-Requests.
									</p>
								</div>

								<div class="flex flex-col gap-1.5">
									<Label
										for="echo_failures"
										class="text-xs font-medium"
										>LCP Echo Max Failures</Label
									>
									<Input
										id="echo_failures"
										type="number"
										min="1"
										max="20"
										bind:value={formEchoMaxFailures}
										class="h-9 font-mono text-xs"
									/>
									<p
										class="text-[10px] text-muted-foreground"
									>
										Consecutive unanswered echoes before
										session teardown.
									</p>
								</div>

								<div class="flex flex-col gap-1.5">
									<Label
										for="padi_retries"
										class="text-xs font-medium"
										>Discovery PADI Retries</Label
									>
									<Input
										id="padi_retries"
										type="number"
										min="1"
										max="20"
										bind:value={formPadiRetries}
										class="h-9 font-mono text-xs"
									/>
									<p
										class="text-[10px] text-muted-foreground"
									>
										Max initiation attempts before backoff.
									</p>
								</div>

								<div class="flex flex-col gap-1.5">
									<Label
										for="padi_timeout"
										class="text-xs font-medium"
										>PADI Timeout (s)</Label
									>
									<Input
										id="padi_timeout"
										type="number"
										min="1"
										max="30"
										bind:value={formPadiTimeout}
										class="h-9 font-mono text-xs"
									/>
									<p
										class="text-[10px] text-muted-foreground"
									>
										Timeout per initiation retry attempt.
									</p>
								</div>
							</div>

							<Separator />

							<div class="flex items-center justify-between">
								<div class="flex flex-col gap-0.5">
									<Label class="text-sm font-semibold"
										>Send PADT Frame on Shutdown</Label
									>
									<p class="text-xs text-muted-foreground">
										Explicitly notifies the BRAS to
										terminate the session on service stop or
										daemon reboot.
									</p>
								</div>
								<Switch bind:checked={formSendPadt} />
							</div>
						</Card.Content>
					</Card.Root>
				</div>
			{/if}
		</Tabs.Content>
	</Tabs.Root>

	<!-- eBPF Experimental Warning Dialog -->
	<AlertDialog.Root bind:open={showEbpfWarningDialog}>
		<AlertDialog.Content>
			<AlertDialog.Header>
				<AlertDialog.Title
					class="flex items-center gap-2 text-amber-600 dark:text-amber-400"
				>
					<AlertTriangleIcon class="size-5 text-amber-500" />
					Experimental eBPF Architecture
				</AlertDialog.Title>
				<AlertDialog.Description
					class="flex flex-col gap-2 text-left pt-2 text-xs"
				>
					<p>
						eBPF Fast-Path bypasses the standard Linux networking
						stack using TC filters and Generic XDP.
					</p>
					<p>
						While offering ultra-low CPU utilization and higher line
						rates, it requires an up-to-date Linux Kernel (5.15+)
						and specialized network driver hooks. If your kernel
						lacks BPF features, the daemon will automatically
						fallback to standard kernel mode.
					</p>
				</AlertDialog.Description>
			</AlertDialog.Header>
			<AlertDialog.Footer>
				<AlertDialog.Cancel
					onclick={() => (showEbpfWarningDialog = false)}
				>
					Cancel
				</AlertDialog.Cancel>
				<AlertDialog.Action
					onclick={() => {
						formDataplane = "ebpf";
						showEbpfWarningDialog = false;
					}}
				>
					I understand, enable eBPF
				</AlertDialog.Action>
			</AlertDialog.Footer>
		</AlertDialog.Content>
	</AlertDialog.Root>

	<!-- Floating GPU-Accelerated Save/Discard Action Island -->
	{#if isDirty}
		<div
			transition:fly={{ y: 24, duration: 220, easing: cubicOut }}
			class="sticky bottom-4 z-30 flex items-center justify-between p-3.5 sm:p-4 rounded-xl border bg-card/90 backdrop-blur-md shadow-2xl border-primary/40 transform-gpu will-change-[transform,opacity] gap-4"
		>
			<div class="flex items-center gap-2.5">
				<span class="relative flex size-2.5">
					<span
						class="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"
					></span>
					<span
						class="relative inline-flex rounded-full size-2.5 bg-amber-500"
					></span>
				</span>
				<div class="flex flex-col sm:flex-row sm:items-center sm:gap-2">
					<span class="text-xs font-semibold text-foreground"
						>Unsaved PPPoE Changes</span
					>
					<span
						class="text-[11px] text-muted-foreground hidden sm:inline"
						>Configuration differs from active runtime parameters</span
					>
				</div>
			</div>

			<div class="flex items-center gap-2 shrink-0">
				<Button
					variant="outline"
					size="sm"
					onclick={handleDiscard}
					disabled={saving || loading}
					class="h-8 text-xs transition-transform duration-150 active:scale-95 transform-gpu"
				>
					<RotateCcwIcon data-icon="inline-start" class="size-3.5" />
					Discard
				</Button>

				<Button
					variant="default"
					size="sm"
					onclick={handleSave}
					disabled={!isDirty || saving || loading}
					class="h-8 text-xs shadow-sm transition-all duration-150 hover:shadow-primary/20 hover:shadow-md active:scale-95 transform-gpu"
				>
					<SaveIcon
						class={saving ? "animate-spin size-3.5" : "size-3.5"}
						data-icon="inline-start"
					/>
					{saving ? "Saving..." : "Save Configuration"}
				</Button>
			</div>
		</div>
	{/if}
</div>
