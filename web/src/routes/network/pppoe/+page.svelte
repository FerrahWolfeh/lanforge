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
	import { onMount } from "svelte";
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";

	import PlugZapIcon from "@lucide/svelte/icons/plug-zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import LockIcon from "@lucide/svelte/icons/lock";
	import KeyIcon from "@lucide/svelte/icons/key";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ServerIcon from "@lucide/svelte/icons/server";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import RadioIcon from "@lucide/svelte/icons/radio";
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
	let activeTab = $state("credentials");

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

	function formatAuthMethod(auth: PppoeAuthMethod | string | null | undefined): string {
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
		const normCfgAuth = (cfgAuth === "chapmd5" ? "chap_md5" : cfgAuth);
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

		if (formNftEnabled !== (config.nftables?.enabled ?? true)) return true;
		if (formNftFlowOffload !== (config.nftables?.flow_offload ?? true)) return true;
		if (formNftMssClamping !== (config.nftables?.mss_clamping ?? true)) return true;
		if (formNftBypassDns !== (config.nftables?.bypass_dns ?? true)) return true;
		if (formNftBypassVowifi !== (config.nftables?.bypass_vowifi ?? true)) return true;
		if (formNftMasquerade !== (config.nftables?.masquerade ?? true)) return true;

		return false;
	});

	function syncFormFromConfig(c: PppoeConfig) {
		formEnabled = c.enabled;
		formDataplane = c.dataplane ?? "kernel";
		formWanIface = c.wan_iface || (availableInterfaces[0]?.name || "eth1");
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

		formNftEnabled = c.nftables?.enabled ?? true;
		formNftFlowOffload = c.nftables?.flow_offload ?? true;
		formNftMssClamping = c.nftables?.mss_clamping ?? true;
		formNftBypassDns = c.nftables?.bypass_dns ?? true;
		formNftBypassVowifi = c.nftables?.bypass_vowifi ?? true;
		formNftMasquerade = c.nftables?.masquerade ?? true;
	}

	async function loadAll() {
		loading = true;
		try {
			const [s, c, setupRes] = await Promise.all([
				pppoeStatus().catch(() => null),
				pppoeConfig().catch(() => null),
				getSetupStatus().catch(() => null),
			]);
			status = s;
			config = c;

			if (setupRes?.interfaces) {
				availableInterfaces = setupRes.interfaces;
			}

			if (c) {
				syncFormFromConfig(c);
			}
		} catch {
			toast.error("Failed to load PPPoE configuration");
		} finally {
			loading = false;
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
				nftables: {
					enabled: formNftEnabled,
					table_name: config?.nftables?.table_name ?? "lanforge_pppoe",
					flow_offload: formNftFlowOffload,
					mss_clamping: formNftMssClamping,
					bypass_dns: formNftBypassDns,
					bypass_vowifi: formNftBypassVowifi,
					masquerade: formNftMasquerade,
					custom_rules_file: config?.nftables?.custom_rules_file ?? null,
				},
			};

			await pppoeUpdateConfig(payload);
			toast.success("PPPoE configuration saved and reloaded");
			await loadAll();
		} catch {
			toast.error("Failed to save PPPoE configuration");
		} finally {
			saving = false;
		}
	}

	async function handleReconnect() {
		reconnecting = true;
		try {
			await pppoeReconnect();
			toast.success("PPPoE reconnection triggered");
			await loadAll();
		} catch {
			toast.error("Failed to trigger PPPoE reconnection");
		} finally {
			reconnecting = false;
		}
	}

	async function handleDisconnect() {
		disconnecting = true;
		try {
			await pppoeDisconnect();
			toast.success("PPPoE disconnection triggered");
			await loadAll();
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
		if (!seconds) return "0s";
		const days = Math.floor(seconds / 86400);
		const hours = Math.floor((seconds % 86400) / 3600);
		const minutes = Math.floor((seconds % 3600) / 60);
		const sec = seconds % 60;

		if (days > 0) return `${days}d ${hours}h ${minutes}m`;
		if (hours > 0) return `${hours}h ${minutes}m`;
		if (minutes > 0) return `${minutes}m ${sec}s`;
		return `${sec}s`;
	}

	onMount(loadAll);
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- Page Header -->
	<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
		<div class="flex items-center gap-3">
			<div class="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
				<PlugZapIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-0.5">
				<h1 class="text-2xl font-bold tracking-tight">PPPoE WAN Concentrator</h1>
				<p class="text-sm text-muted-foreground">
					Carrier broadband link orchestration, credentials, MSS clamping, and eBPF Fast-Path.
				</p>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={loadAll}
				disabled={loading}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={loading ? "animate-spin" : ""} data-icon="inline-start" />
				Refresh
			</Button>
			<Button
				variant="outline"
				size="sm"
				onclick={handleReconnect}
				disabled={reconnecting || loading}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={reconnecting ? "animate-spin" : ""} data-icon="inline-start" />
				Reconnect
			</Button>
			<Button
				variant="destructive"
				size="sm"
				onclick={handleDisconnect}
				disabled={disconnecting || loading || status?.state === "disconnected"}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<XCircleIcon data-icon="inline-start" />
				Disconnect
			</Button>
		</div>
	</div>

	<!-- Status Overview Grid (Responsive 3-Column Layout) -->
	{#if loading && !status}
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
			<Skeleton class="h-28 rounded-xl" />
			<Skeleton class="h-28 rounded-xl" />
			<Skeleton class="h-28 rounded-xl" />
		</div>
	{:else}
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
			<!-- Session State Card -->
			<Card.Root class="relative overflow-hidden">
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
						<span>Session State</span>
						{#if status?.state === "connected"}
							<span class="relative flex size-2.5">
								<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
								<span class="relative inline-flex rounded-full size-2.5 bg-emerald-500"></span>
							</span>
						{:else if status?.state === "authenticating" || status?.state === "reconnecting"}
							<span class="relative flex size-2.5">
								<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
								<span class="relative inline-flex rounded-full size-2.5 bg-amber-500"></span>
							</span>
						{:else}
							<span class="flex size-2.5 rounded-full bg-destructive/60"></span>
						{/if}
					</Card.Description>
					<Card.Title class="flex items-center gap-2 text-lg font-bold">
						{#if status?.state === "connected"}
							<CheckCircleIcon class="size-5 text-emerald-500" />
							<span class="capitalize text-emerald-600 dark:text-emerald-400">Connected</span>
						{:else if status?.state === "reconnecting"}
							<RefreshCwIcon class="size-5 animate-spin text-amber-500" />
							<span class="capitalize text-amber-600 dark:text-amber-400">Reconnecting</span>
						{:else if status?.state === "authenticating"}
							<KeyIcon class="size-5 animate-pulse text-amber-500" />
							<span class="capitalize text-amber-600 dark:text-amber-400">Authenticating</span>
						{:else}
							<XCircleIcon class="size-5 text-muted-foreground" />
							<span class="capitalize text-muted-foreground">Disconnected</span>
						{/if}
					</Card.Title>
				</Card.Header>
				<Card.Content class="text-xs text-muted-foreground flex flex-col gap-1">
					<div class="flex justify-between">
						<span>Virtual / WAN Iface:</span>
						<span class="font-mono text-foreground font-semibold">
							{status?.interface ?? "none"} / {status?.wan_iface ?? formWanIface}
						</span>
					</div>
					<div class="flex justify-between">
						<span>Uptime:</span>
						<span class="font-medium text-foreground">{formatUptime(status?.uptime_secs)}</span>
					</div>
					{#if status?.reconnect_attempts && status.reconnect_attempts > 0}
						<div class="flex justify-between text-amber-600 dark:text-amber-400">
							<span>Reconnect Attempts:</span>
							<span class="font-semibold">{status.reconnect_attempts}</span>
						</div>
					{/if}
					{#if status?.last_error}
						<div class="rounded-md bg-destructive/10 p-1.5 text-[11px] text-destructive flex items-center gap-1 mt-1">
							<AlertCircleIcon class="size-3 shrink-0" />
							<span class="truncate">{status.last_error}</span>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>

			<!-- Network IP Configuration Card -->
			<Card.Root>
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
						<span>Assigned IP Lease</span>
						<GlobeIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title class="flex items-center gap-2 text-lg font-bold font-mono">
						{#if status?.local_ip}
							<span class="text-foreground">{status.local_ip}</span>
						{:else}
							<span class="text-muted-foreground text-sm font-normal">Waiting for IPCP...</span>
						{/if}
					</Card.Title>
				</Card.Header>
				<Card.Content class="text-xs text-muted-foreground flex flex-col gap-1">
					<div class="flex justify-between">
						<span>Gateway (Peer IP):</span>
						<span class="font-mono text-foreground font-semibold">{status?.peer_ip ?? "—"}</span>
					</div>
					<div class="flex justify-between">
						<span>Negotiated MRU:</span>
						<span class="font-mono text-foreground font-semibold">{status?.mru ? `${status.mru} bytes` : "—"}</span>
					</div>
					<div class="flex justify-between">
						<span>Session ID:</span>
						<span class="font-mono text-foreground">{status?.session_id ? `0x${status.session_id.toString(16).padStart(4, "0")}` : "—"}</span>
					</div>
				</Card.Content>
			</Card.Root>

			<!-- AC & Remote Details Card -->
			<Card.Root>
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
						<span>Access Concentrator</span>
						<ServerIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title class="truncate text-base font-bold text-foreground" title={status?.ac_name ?? "None"}>
						{status?.ac_name || (status?.state === "connected" ? "ISP Concentrator" : "Searching...")}
					</Card.Title>
				</Card.Header>
				<Card.Content class="text-xs text-muted-foreground flex flex-col gap-1">
					<div class="flex justify-between">
						<span>AC MAC Address:</span>
						<span class="font-mono text-foreground font-semibold">{status?.ac_mac ?? "—"}</span>
					</div>
					<div class="flex justify-between">
						<span>ISP DNS Fallback:</span>
						<span class="font-mono text-foreground truncate max-w-[140px]" title={status?.dns_servers?.join(", ")}>
							{status?.dns_servers?.length ? status.dns_servers.join(", ") : "None"}
						</span>
					</div>
					<div class="flex justify-between items-center">
						<span>Auth Method:</span>
						<Badge variant="outline" class="font-medium text-[10px]">
							{formatAuthMethod(status?.auth ?? config?.auth ?? formAuth)}
						</Badge>
					</div>
				</Card.Content>
			</Card.Root>
		</div>
	{/if}

	<!-- Data Plane Mode Selector -->
	<Card.Root class="border-primary/20 bg-muted/20">
		<Card.Header class="pb-3">
			<Card.Title class="text-base font-bold flex items-center gap-2">
				<ZapIcon class="size-5 text-primary" />
				Data Plane Architecture Selection
			</Card.Title>
			<Card.Description>
				Choose how PPPoE packets are processed and routed through the network subsystem.
			</Card.Description>
		</Card.Header>
		<Card.Content>
			<div class="grid gap-4 md:grid-cols-2">
				<!-- Linux Kernel Mode Option -->
				<div
					class="relative cursor-pointer rounded-xl border p-4 transition-all duration-200 hover:scale-[1.01] active:scale-[0.99] transform-gpu will-change-transform flex flex-col gap-2 {formDataplane === 'kernel' ? 'border-primary bg-primary/5 shadow-sm' : 'border-border/60'}"
					onclick={() => formDataplane = 'kernel'}
					role="button"
					tabindex="0"
					onkeydown={(e) => e.key === 'Enter' && (formDataplane = 'kernel')}
				>
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2 font-semibold text-sm">
							<CpuIcon class="size-4 text-blue-500" />
							<span>Standard Linux Kernel</span>
						</div>
						{#if formDataplane === 'kernel'}
							<Badge variant="default" class="bg-primary text-primary-foreground text-xs">Active Mode</Badge>
						{:else}
							<Badge variant="outline" class="text-xs">Recommended</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed">
						Uses upstream <code class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono">/dev/ppp</code> and standard <code class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono">ppp_generic</code> drivers. Highly stable, universal hardware compatibility, standard routing, and transparent traffic accounting.
					</p>
					<div class="flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
						<CheckCircleIcon class="size-3.5" />
						Full support for Flowtable offload and PMTU Clamping
					</div>
				</div>

				<!-- eBPF Fast-Path Option -->
				<div
					class="relative cursor-pointer rounded-xl border p-4 transition-all duration-200 hover:scale-[1.01] active:scale-[0.99] transform-gpu will-change-transform flex flex-col gap-2 {formDataplane === 'ebpf' ? 'border-amber-500 bg-amber-500/5 shadow-sm' : 'border-border/60'}"
					onclick={() => handleDataplaneSelect('ebpf')}
					role="button"
					tabindex="0"
					onkeydown={(e) => e.key === 'Enter' && handleDataplaneSelect('ebpf')}
				>
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2 font-semibold text-sm text-amber-600 dark:text-amber-400">
							<ZapIcon class="size-4 text-amber-500" />
							<span>eBPF Fast-Path (Generic XDP + TC)</span>
						</div>
						{#if formDataplane === 'ebpf'}
							<Badge variant="outline" class="border-amber-500 text-amber-600 text-xs">Active Experimental</Badge>
						{:else}
							<Badge variant="secondary" class="text-xs">Experimental</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed">
						Zero-copy packet decapsulation using eBPF TC filters attached directly to the physical WAN interface. Extreme throughput and sub-millisecond line-rate routing with minimal CPU overhead.
					</p>
					<div class="flex items-center gap-1.5 text-[11px] text-amber-600 dark:text-amber-400 font-medium">
						<AlertTriangleIcon class="size-3.5" />
						Requires eBPF kernel support (Generic XDP SKB mode)
					</div>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- eBPF Experimental Warning Dialog -->
	<AlertDialog.Root bind:open={showEbpfWarningDialog}>
		<AlertDialog.Content>
			<AlertDialog.Header>
				<AlertDialog.Title class="flex items-center gap-2 text-amber-600">
					<AlertTriangleIcon class="size-5" />
					Experimental eBPF Architecture
				</AlertDialog.Title>
				<AlertDialog.Description class="flex flex-col gap-2 text-left pt-2 text-xs">
					<p>
						eBPF Fast-Path bypasses standard Linux networking stack using TC filters and Generic XDP.
					</p>
					<p>
						While offering ultra-low CPU utilization, it requires an up-to-date Linux Kernel (5.15+) and specialized network driver hooks. If your kernel lacks BPF features, the daemon will automatically fallback to standard kernel mode.
					</p>
				</AlertDialog.Description>
			</AlertDialog.Header>
			<AlertDialog.Footer>
				<AlertDialog.Cancel onclick={() => (showEbpfWarningDialog = false)}>
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

	<!-- Detailed Configuration Tabs -->
	<Tabs.Root bind:value={activeTab} class="flex flex-col gap-4">
		<Tabs.List class="grid w-full grid-cols-3 sm:w-[480px]">
			<Tabs.Trigger value="credentials" class="flex items-center gap-2 transition-all duration-150 transform-gpu">
				<KeyIcon class="size-4" />
				<span>Credentials</span>
				{#if isDirty}
					<span class="size-1.5 rounded-full bg-amber-500 animate-pulse"></span>
				{/if}
			</Tabs.Trigger>
			<Tabs.Trigger value="link" class="flex items-center gap-2 transition-all duration-150 transform-gpu">
				<SlidersIcon class="size-4" />
				<span>Link & Timers</span>
			</Tabs.Trigger>
			<Tabs.Trigger value="nftables" class="flex items-center gap-2 transition-all duration-150 transform-gpu">
				<ShieldIcon class="size-4" />
				<span>nftables Tuning</span>
			</Tabs.Trigger>
		</Tabs.List>

		<!-- Tab 1: Credentials & Interface -->
		<Tabs.Content value="credentials" class="flex flex-col gap-6 focus-visible:outline-none">
			{#if activeTab === "credentials"}
				<div in:fly={{ y: 12, duration: 240, easing: cubicOut }} class="flex flex-col gap-6 transform-gpu will-change-[transform,opacity]">

				<Card.Root>
					<Card.Header class="pb-3">
						<Card.Title class="text-base">ISP Authentication & Uplink Interface</Card.Title>
						<Card.Description>
							Configure the physical Ethernet port, subscriber credentials, and authentication protocol.
						</Card.Description>
					</Card.Header>
					<Card.Content class="flex flex-col gap-5">
						<!-- Service Enable Switch -->
						<div class="flex items-center justify-between rounded-xl border p-4">
							<div class="flex flex-col gap-0.5">
								<Label class="text-sm font-semibold">Enable PPPoE Service</Label>
								<p class="text-xs text-muted-foreground">
									When enabled, Lanforge automatically discovers the Access Concentrator and maintains the session.
								</p>
							</div>
							<Switch bind:checked={formEnabled} />
						</div>

						<div class="grid gap-4 sm:grid-cols-2">
							<!-- WAN Physical Interface Select -->
							<div class="flex flex-col gap-1.5">
								<Label class="text-xs font-medium">Physical WAN Interface</Label>
								{#if interfaceOptions.length > 0}
									<Select.Root
										type="single"
										value={formWanIface}
										onValueChange={(val) => {
											if (val) formWanIface = val;
										}}
									>
										<Select.Trigger class="h-9 text-xs font-mono">
											{formWanIface || "Select WAN interface..."}
										</Select.Trigger>
										<Select.Content>
											{#each interfaceOptions as iface (iface.name)}
												<Select.Item value={iface.name} class="text-xs">
													<div class="flex items-center justify-between w-full gap-3">
														<div class="flex items-center gap-2">
															<span class="font-mono font-medium">{iface.name}</span>
															{#if iface.carrier_up}
																<span class="size-1.5 rounded-full bg-emerald-500" title="Carrier connected"></span>
															{:else}
																<span class="size-1.5 rounded-full bg-muted-foreground/40" title="Disconnected"></span>
															{/if}
														</div>
														<div class="flex items-center gap-1.5 text-[10px] text-muted-foreground">
															{#if iface.is_physical}
																<Badge variant="secondary" class="text-[9px] px-1 py-0 font-normal">Physical</Badge>
															{/if}
															{#if iface.ips && iface.ips.length > 0}
																<span class="truncate max-w-[120px] font-mono text-[10px]">{iface.ips[0]}</span>
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
								<p class="text-[11px] text-muted-foreground">
									Port connected to your fiber ONT, modem, or upstream switch.
								</p>
							</div>

							<!-- Authentication Protocol Select -->
							<div class="flex flex-col gap-1.5">
								<Label class="text-xs font-medium">Authentication Protocol</Label>
								<Select.Root
									type="single"
									value={formAuth}
									onValueChange={(val) => {
										if (val) formAuth = val as PppoeAuthMethod;
									}}
								>
									<Select.Trigger class="h-9 text-xs">
										{formatAuthMethod(formAuth)}
									</Select.Trigger>
									<Select.Content>
										<Select.Item value="chap_md5" class="text-xs">CHAP-MD5 (Recommended)</Select.Item>
										<Select.Item value="pap" class="text-xs">PAP (Plaintext Password)</Select.Item>
										<Select.Item value="none" class="text-xs">None (Unauthenticated)</Select.Item>
									</Select.Content>
								</Select.Root>
								<p class="text-[11px] text-muted-foreground">
									Most ISPs require CHAP-MD5 authentication.
								</p>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="username" class="text-xs font-medium">PPPoE Username</Label>
								<Input
									id="username"
									bind:value={formUsername}
									placeholder="user@isp.com"
									class="h-9 text-xs"
								/>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="password" class="text-xs font-medium">PPPoE Password</Label>
								<div class="relative">
									<Input
										id="password"
										type={showPassword ? "text" : "password"}
										bind:value={formPassword}
										placeholder="••••••••"
										class="h-9 text-xs pr-10"
									/>
									<button
										type="button"
										class="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground transition-colors"
										onclick={() => (showPassword = !showPassword)}
									>
										{#if showPassword}
											<EyeOffIcon class="size-4" />
										{:else}
											<EyeIcon class="size-4" />
										{/if}
									</button>
								</div>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="service_name" class="text-xs font-medium">Service Name (Optional)</Label>
								<Input
									id="service_name"
									bind:value={formServiceName}
									placeholder="Leave empty for any"
									class="h-9 text-xs"
								/>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="ac_name" class="text-xs font-medium">Access Concentrator Name (Optional)</Label>
								<Input
									id="ac_name"
									bind:value={formAcName}
									placeholder="Leave empty for any"
									class="h-9 text-xs"
								/>
							</div>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- Synced Daemon Footer Status -->
				{#if !isDirty}
					<div class="flex items-center justify-between p-3.5 rounded-xl border bg-card/40 gap-4 mt-2">
						<div class="flex items-center gap-2">
							<span class="size-2 rounded-full bg-emerald-500"></span>
							<span class="text-xs text-muted-foreground">Configuration is synchronized with active daemon</span>
						</div>
						<Button
							variant="secondary"
							size="sm"
							disabled={true}
							class="h-8 text-xs opacity-50"
						>
							<SaveIcon class="size-3.5" data-icon="inline-start" />
							Synchronized
						</Button>
					</div>
				{/if}
			</div>
			{/if}
		</Tabs.Content>

		<!-- Tab 2: Link & Timers -->
		<Tabs.Content value="link" class="flex flex-col gap-6 focus-visible:outline-none">
			{#if activeTab === "link"}
				<div in:fly={{ y: 12, duration: 240, easing: cubicOut }} class="flex flex-col gap-6 transform-gpu will-change-[transform,opacity]">
					<Card.Root>

					<Card.Header class="pb-3">
						<Card.Title class="text-base">Link Parameters, MTU & Keepalive Timers</Card.Title>
						<Card.Description>
							Fine-tune packet sizing, discovery retry timeouts, and LCP keepalive echo intervals.
						</Card.Description>
					</Card.Header>
					<Card.Content class="flex flex-col gap-6">
						<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
							<div class="flex flex-col gap-1.5">
								<Label for="mru" class="text-xs font-medium">Max Receive Unit (MRU / MTU)</Label>
								<Input
									id="mru"
									type="number"
									min="576"
									max="1500"
									bind:value={formMru}
									class="h-9 font-mono text-xs"
								/>
								<p class="text-[10px] text-muted-foreground">
									Standard PPPoE MTU is 1492 (1500 - 8 bytes).
								</p>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="reconnect_delay" class="text-xs font-medium">Reconnect Delay (s)</Label>
								<Input
									id="reconnect_delay"
									type="number"
									min="1"
									max="300"
									bind:value={formReconnectDelay}
									class="h-9 font-mono text-xs"
								/>
								<p class="text-[10px] text-muted-foreground">
									Pause before attempting discovery after a drop.
								</p>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="echo_interval" class="text-xs font-medium">LCP Echo Interval (s)</Label>
								<Input
									id="echo_interval"
									type="number"
									min="1"
									max="120"
									bind:value={formEchoInterval}
									class="h-9 font-mono text-xs"
								/>
								<p class="text-[10px] text-muted-foreground">
									Frequency of keepalive Echo-Requests.
								</p>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="echo_failures" class="text-xs font-medium">LCP Echo Max Failures</Label>
								<Input
									id="echo_failures"
									type="number"
									min="1"
									max="20"
									bind:value={formEchoMaxFailures}
									class="h-9 font-mono text-xs"
								/>
								<p class="text-[10px] text-muted-foreground">
									Consecutive unanswered echoes before drop.
								</p>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="padi_retries" class="text-xs font-medium">Discovery PADI Retries</Label>
								<Input
									id="padi_retries"
									type="number"
									min="1"
									max="20"
									bind:value={formPadiRetries}
									class="h-9 font-mono text-xs"
								/>
								<p class="text-[10px] text-muted-foreground">Max initiation attempts.</p>
							</div>

							<div class="flex flex-col gap-1.5">
								<Label for="padi_timeout" class="text-xs font-medium">PADI Timeout (s)</Label>
								<Input
									id="padi_timeout"
									type="number"
									min="1"
									max="30"
									bind:value={formPadiTimeout}
									class="h-9 font-mono text-xs"
								/>
								<p class="text-[10px] text-muted-foreground">Timeout per initiation retry.</p>
							</div>
						</div>

						<Separator />

						<div class="flex items-center justify-between">
							<div class="flex flex-col gap-0.5">
								<Label class="text-sm font-semibold">Send PADT Frame on Shutdown</Label>
								<p class="text-xs text-muted-foreground">
									Explicitly notifies the BRAS to terminate the session on service stop.
								</p>
							</div>
							<Switch bind:checked={formSendPadt} />
						</div>
					</Card.Content>
				</Card.Root>

				<!-- Synced Daemon Footer Status -->
				{#if !isDirty}
					<div class="flex items-center justify-between p-3.5 rounded-xl border bg-card/40 gap-4 mt-2">
						<div class="flex items-center gap-2">
							<span class="size-2 rounded-full bg-emerald-500"></span>
							<span class="text-xs text-muted-foreground">Configuration is synchronized with active daemon</span>
						</div>
						<Button
							variant="secondary"
							size="sm"
							disabled={true}
							class="h-8 text-xs opacity-50"
						>
							<SaveIcon class="size-3.5" data-icon="inline-start" />
							Synchronized
						</Button>
					</div>
				{/if}
			</div>
			{/if}
		</Tabs.Content>

		<!-- Tab 3: nftables Tuning -->
		<Tabs.Content value="nftables" class="flex flex-col gap-6 focus-visible:outline-none">
			{#if activeTab === "nftables"}
				<div in:fly={{ y: 12, duration: 240, easing: cubicOut }} class="flex flex-col gap-6 transform-gpu will-change-[transform,opacity]">
					<Card.Root>

					<Card.Header class="pb-3">
						<Card.Title class="text-base">Kernel Router Performance & nftables Tuning</Card.Title>
						<Card.Description>
							Automatic router optimizations, TCP MSS clamping, Flowtable fast-path, and VoWiFi bypass.
						</Card.Description>
					</Card.Header>
					<Card.Content class="flex flex-col gap-4">
						<div class="flex items-center justify-between rounded-xl border p-4">
							<div class="flex flex-col gap-0.5">
								<Label class="text-base font-semibold">Apply nftables Router Tuning</Label>
								<p class="text-xs text-muted-foreground">
									Automatically applies optimized firewall rules, fast routing, and connection tracking filters.
								</p>
							</div>
							<Switch bind:checked={formNftEnabled} />
						</div>

						<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
							<div class="flex items-center justify-between rounded-xl border p-3">
								<div class="flex flex-col gap-0.5">
									<Label class="text-xs font-medium">Flowtable Offloading</Label>
									<p class="text-[10px] text-muted-foreground">
										Fast-path TCP/UDP flows in software flowtable.
									</p>
								</div>
								<Switch bind:checked={formNftFlowOffload} disabled={!formNftEnabled} />
							</div>

							<div class="flex items-center justify-between rounded-xl border p-3">
								<div class="flex flex-col gap-0.5">
									<Label class="text-xs font-medium">TCP MSS Clamping (1452)</Label>
									<p class="text-[10px] text-muted-foreground">
										Prevents PMTU discovery blackholes.
									</p>
								</div>
								<Switch bind:checked={formNftMssClamping} disabled={!formNftEnabled} />
							</div>

							<div class="flex items-center justify-between rounded-xl border p-3">
								<div class="flex flex-col gap-0.5">
									<Label class="text-xs font-medium">DNS Port 53 / 853 Bypass</Label>
									<p class="text-[10px] text-muted-foreground">
										Ensures local resolver analytics remain accurate.
									</p>
								</div>
								<Switch bind:checked={formNftBypassDns} disabled={!formNftEnabled} />
							</div>

							<div class="flex items-center justify-between rounded-xl border p-3">
								<div class="flex flex-col gap-0.5">
									<Label class="text-xs font-medium">VoWiFi / IPsec Bypass</Label>
									<p class="text-[10px] text-muted-foreground">
										Keeps Wi-Fi Calling tunnels alive without drops.
									</p>
								</div>
								<Switch bind:checked={formNftBypassVowifi} disabled={!formNftEnabled} />
							</div>

							<div class="flex items-center justify-between rounded-xl border p-3">
								<div class="flex flex-col gap-0.5">
									<Label class="text-xs font-medium">Outbound NAT Masquerade</Label>
									<p class="text-[10px] text-muted-foreground">
										Enables source NAT masquerading for LAN clients.
									</p>
								</div>
								<Switch bind:checked={formNftMasquerade} disabled={!formNftEnabled} />
							</div>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- Synced Daemon Footer Status -->
				{#if !isDirty}
					<div class="flex items-center justify-between p-3.5 rounded-xl border bg-card/40 gap-4 mt-2">
						<div class="flex items-center gap-2">
							<span class="size-2 rounded-full bg-emerald-500"></span>
							<span class="text-xs text-muted-foreground">Configuration is synchronized with active daemon</span>
						</div>
						<Button
							variant="secondary"
							size="sm"
							disabled={true}
							class="h-8 text-xs opacity-50"
						>
							<SaveIcon class="size-3.5" data-icon="inline-start" />
							Synchronized
						</Button>
					</div>
				{/if}
			</div>
			{/if}
		</Tabs.Content>

	</Tabs.Root>

	<!-- Floating GPU-Accelerated Save/Discard Action Island -->
	{#if isDirty}
		<div
			transition:fly={{ y: 24, duration: 220, easing: cubicOut }}
			class="sticky bottom-4 z-30 flex items-center justify-between p-3.5 sm:p-4 rounded-xl border bg-card/90 backdrop-blur-md shadow-2xl border-primary/40 transform-gpu will-change-[transform,opacity] gap-4"
		>
			<div class="flex items-center gap-2.5">
				<span class="relative flex size-2.5">
					<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
					<span class="relative inline-flex rounded-full size-2.5 bg-amber-500"></span>
				</span>
				<div class="flex flex-col sm:flex-row sm:items-center sm:gap-2">
					<span class="text-xs font-semibold text-foreground">Unsaved PPPoE Changes</span>
					<span class="text-[11px] text-muted-foreground hidden sm:inline">Configuration differs from active runtime parameters</span>
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
					<SaveIcon class={saving ? "animate-spin size-3.5" : "size-3.5"} data-icon="inline-start" />
					{saving ? "Saving..." : "Save Configuration"}
				</Button>
			</div>
		</div>
	{/if}
</div>
