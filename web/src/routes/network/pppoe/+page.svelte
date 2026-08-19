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
	} from "$lib/api/client";
	import type {
		PppoeConfig,
		PppoeStatusResponse,
		PppoeDataplane,
		PppoeAuthMethod,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";

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

	// Page state
	let status = $state<PppoeStatusResponse | null>(null);
	let config = $state<PppoeConfig | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let reconnecting = $state(false);
	let disconnecting = $state(false);
	let showPassword = $state(false);
	let showEbpfWarningDialog = $state(false);

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

	async function loadAll() {
		loading = true;
		try {
			const [s, c] = await Promise.all([
				pppoeStatus().catch(() => null),
				pppoeConfig().catch(() => null),
			]);
			status = s;
			config = c;

			if (c) {
				formEnabled = c.enabled;
				formDataplane = c.dataplane ?? "kernel";
				formWanIface = c.wan_iface;
				formUsername = c.username;
				formPassword = c.password;
				formAuth = c.auth;
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
		} catch {
			toast.error("Failed to load PPPoE configuration");
		} finally {
			loading = false;
		}
	}

	async function handleSave() {
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
					table_name: config?.nftables?.table_name ?? "lanforge",
					flow_offload: formNftFlowOffload,
					mss_clamping: formNftMssClamping,
					bypass_dns: formNftBypassDns,
					bypass_vowifi: formNftBypassVowifi,
					masquerade: formNftMasquerade,
					custom_rules_file: config?.nftables?.custom_rules_file ?? null,
				},
			};

			await pppoeUpdateConfig(payload);
			toast.success("PPPoE configuration saved successfully");
			await loadAll();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save PPPoE configuration");
		} finally {
			saving = false;
		}
	}

	async function handleReconnect() {
		reconnecting = true;
		try {
			await pppoeReconnect();
			toast.success("Reconnection triggered");
			setTimeout(loadAll, 2000);
		} catch {
			toast.error("Failed to trigger reconnection");
		} finally {
			reconnecting = false;
		}
	}

	async function handleDisconnect() {
		disconnecting = true;
		try {
			await pppoeDisconnect();
			toast.success("Disconnection triggered");
			setTimeout(loadAll, 2000);
		} catch {
			toast.error("Failed to trigger disconnection");
		} finally {
			disconnecting = false;
		}
	}

	function formatUptime(secs?: number | null): string {
		if (secs === undefined || secs === null) return "—";
		const d = Math.floor(secs / 86400);
		const h = Math.floor((secs % 86400) / 3600);
		const m = Math.floor((secs % 3600) / 60);
		if (d > 0) return `${d}d ${h}h ${m}m`;
		if (h > 0) return `${h}h ${m}m`;
		return `${m}m ${secs % 60}s`;
	}

	onMount(loadAll);
</script>

<div class="container mx-auto space-y-6 p-4 md:p-8">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
		<div>
			<div class="flex items-center gap-3">
				<div class="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/10 text-primary">
					<PlugZapIcon class="h-6 w-6" />
				</div>
				<div>
					<h1 class="text-2xl font-bold tracking-tight">PPPoE WAN Concentrator</h1>
					<p class="text-sm text-muted-foreground">
						Carrier broadband link orchestration, credentials, MSS clamping, and eBPF Fast-Path.
					</p>
				</div>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<Button variant="outline" size="sm" onclick={loadAll} disabled={loading}>
				<RefreshCwIcon class="mr-2 h-4 w-4 {loading ? 'animate-spin' : ''}" />
				Refresh
			</Button>
			<Button
				variant="outline"
				size="sm"
				onclick={handleReconnect}
				disabled={reconnecting || loading}
			>
				<RefreshCwIcon class="mr-2 h-4 w-4 {reconnecting ? 'animate-spin' : ''}" />
				Reconnect
			</Button>
			<Button
				variant="destructive"
				size="sm"
				onclick={handleDisconnect}
				disabled={disconnecting || loading || status?.state === 'disconnected'}
			>
				<XCircleIcon class="mr-2 h-4 w-4" />
				Disconnect
			</Button>
		</div>
	</div>

	<!-- Status Overview Grid -->
	{#if loading && !status}
		<div class="grid gap-4 md:grid-cols-3">
			<Skeleton class="h-32 rounded-xl" />
			<Skeleton class="h-32 rounded-xl" />
			<Skeleton class="h-32 rounded-xl" />
		</div>
	{:else}
		<div class="grid gap-4 md:grid-cols-3">
			<!-- Session State Card -->
			<Card.Root class="relative overflow-hidden">
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
						<span>Session State</span>
						{#if status?.state === "connected"}
							<span class="flex h-2 w-2 rounded-full bg-emerald-500 ring-4 ring-emerald-500/20 animate-pulse"></span>
						{:else if status?.state === "authenticating" || status?.state === "reconnecting"}
							<span class="flex h-2 w-2 rounded-full bg-amber-500 ring-4 ring-amber-500/20 animate-pulse"></span>
						{:else}
							<span class="flex h-2 w-2 rounded-full bg-destructive/60"></span>
						{/if}
					</Card.Description>
					<Card.Title class="flex items-center gap-2 text-xl font-bold">
						{#if status?.state === "connected"}
							<CheckCircleIcon class="h-5 w-5 text-emerald-500" />
							<span class="capitalize text-emerald-600 dark:text-emerald-400">Connected</span>
						{:else if status?.state === "reconnecting"}
							<RefreshCwIcon class="h-5 w-5 animate-spin text-amber-500" />
							<span class="capitalize text-amber-600 dark:text-amber-400">Reconnecting</span>
						{:else if status?.state === "authenticating"}
							<KeyIcon class="h-5 w-5 animate-pulse text-amber-500" />
							<span class="capitalize text-amber-600 dark:text-amber-400">Authenticating</span>
						{:else}
							<XCircleIcon class="h-5 w-5 text-muted-foreground" />
							<span class="capitalize text-muted-foreground">Disconnected</span>
						{/if}
					</Card.Title>
				</Card.Header>
				<Card.Content class="text-xs text-muted-foreground space-y-1">
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
				</Card.Content>
			</Card.Root>

			<!-- Data Plane & Acceleration Card -->
			<Card.Root>
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
						<span>Data Plane Engine</span>
						{#if status?.dataplane === "ebpf"}
							<Badge variant="destructive" class="bg-amber-500/20 text-amber-600 dark:text-amber-400 border-amber-500/30">
								eBPF (Experimental)
							</Badge>
						{:else}
							<Badge variant="secondary">
								Kernel Standard
							</Badge>
						{/if}
					</Card.Description>
					<Card.Title class="text-xl font-bold flex items-center gap-2">
						{#if status?.dataplane === "ebpf"}
							<ZapIcon class="h-5 w-5 text-amber-500" />
							<span>Generic XDP + TC</span>
						{:else}
							<CpuIcon class="h-5 w-5 text-muted-foreground" />
							<span>ppp_generic (Linux)</span>
						{/if}
					</Card.Title>
				</Card.Header>
				<Card.Content class="text-xs text-muted-foreground space-y-1">
					<div class="flex justify-between">
						<span>Assigned WAN IP:</span>
						<span class="font-mono text-foreground font-semibold">{status?.local_ip ?? "—"}</span>
					</div>
					<div class="flex justify-between">
						<span>Peer Gateway IP:</span>
						<span class="font-mono text-foreground font-semibold">{status?.peer_ip ?? "—"}</span>
					</div>
					<div class="flex justify-between">
						<span>Session ID / MRU:</span>
						<span class="font-medium text-foreground">
							{status?.session_id ? `0x${status.session_id.toString(16).toUpperCase()}` : "—"} / {status?.mru ?? formMru}
						</span>
					</div>
				</Card.Content>
			</Card.Root>

			<!-- Uplink / Access Concentrator Card -->
			<Card.Root>
				<Card.Header class="pb-2">
					<Card.Description class="text-xs font-semibold uppercase tracking-wider">
						Broadband Uplink Details
					</Card.Description>
					<Card.Title class="text-xl font-bold flex items-center gap-2 truncate">
						<RadioIcon class="h-5 w-5 text-muted-foreground shrink-0" />
						<span class="truncate">{status?.ac_name ?? "Auto-Discovered AC"}</span>
					</Card.Title>
				</Card.Header>
				<Card.Content class="text-xs text-muted-foreground space-y-1">
					<div class="flex justify-between">
						<span>AC MAC Address:</span>
						<span class="font-mono text-foreground font-semibold">{status?.ac_mac ?? "—"}</span>
					</div>
					<div class="flex justify-between">
						<span>ISP DNS Fallback:</span>
						<span class="font-mono text-foreground truncate max-w-[160px]" title={status?.dns_servers?.join(", ")}>
							{status?.dns_servers?.length ? status.dns_servers.join(", ") : "None"}
						</span>
					</div>
					<div class="flex justify-between">
						<span>Auth Method:</span>
						<span class="font-medium uppercase text-foreground">{formAuth}</span>
					</div>
				</Card.Content>
			</Card.Root>
		</div>
	{/if}

	<!-- Data Plane Mode Selector -->
	<Card.Root class="border-primary/20 bg-muted/20">
		<Card.Header>
			<div class="flex items-center justify-between">
				<div>
					<Card.Title class="text-lg font-bold flex items-center gap-2">
						<ZapIcon class="h-5 w-5 text-primary" />
						Data Plane Architecture Selection
					</Card.Title>
					<Card.Description>
						Choose how PPPoE packets are processed and routed through the network subsystem.
					</Card.Description>
				</div>
			</div>
		</Card.Header>
		<Card.Content class="space-y-4">
			<div class="grid gap-4 md:grid-cols-2">
				<!-- Linux Kernel Standard -->
				<button
					type="button"
					class="flex flex-col text-left rounded-xl border p-4 transition-all {formDataplane === 'kernel' ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-muted-foreground/40'}"
					onclick={() => (formDataplane = "kernel")}
				>
					<div class="flex items-center justify-between w-full mb-2">
						<div class="flex items-center gap-2">
							<CpuIcon class="h-5 w-5 text-muted-foreground" />
							<span class="font-bold text-foreground">Linux Kernel Standard (ppp_generic)</span>
						</div>
						{#if formDataplane === "kernel"}
							<Badge variant="default">Selected</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground">
						Traditional Linux kernel driver handoff via <code class="text-foreground">/dev/ppp</code> ioctl calls. Creates a point-to-point virtual interface (<code class="text-foreground">ppp0</code>). High stability and full Linux networking compatibility.
					</p>
					<div class="mt-3 flex items-center gap-3 text-[11px] text-muted-foreground font-medium">
						<span class="text-emerald-600 dark:text-emerald-400">✓ Production Recommended</span>
						<span>• Standard Routing Table</span>
					</div>
				</button>

				<!-- eBPF Fast-Path -->
				<button
					type="button"
					class="flex flex-col text-left rounded-xl border p-4 transition-all {formDataplane === 'ebpf' ? 'border-amber-500 bg-amber-500/5 ring-1 ring-amber-500' : 'border-border hover:border-muted-foreground/40'}"
					onclick={() => {
						if (formDataplane !== "ebpf") {
							showEbpfWarningDialog = true;
						}
					}}
				>
					<div class="flex items-center justify-between w-full mb-2">
						<div class="flex items-center gap-2">
							<ZapIcon class="h-5 w-5 text-amber-500" />
							<span class="font-bold text-foreground">eBPF Fast-Path (Generic XDP + TC)</span>
						</div>
						<div class="flex items-center gap-1.5">
							<Badge variant="destructive" class="bg-amber-500/20 text-amber-600 dark:text-amber-400 border-amber-500/30 text-[10px] uppercase tracking-wider">
								Experimental
							</Badge>
							{#if formDataplane === "ebpf"}
								<Badge variant="default" class="bg-amber-600 hover:bg-amber-700">Selected</Badge>
							{/if}
						</div>
					</div>
					<p class="text-xs text-muted-foreground">
						Experimental in-kernel bytecode fast-path bypassing <code class="text-foreground">ppp_mutex</code>. Executes decapsulation at Generic XDP and encapsulation at TC Egress. Note: highly experimental and prone to stability bugs.
					</p>
					<div class="mt-3 flex items-center gap-3 text-[11px] text-amber-600 dark:text-amber-400 font-medium">
						<span>⚠️ Unstable / Active Research</span>
						<span>• In-Place MSS Clamping</span>
						<span>• Generic XDP Hook</span>
					</div>
				</button>
			</div>

			<!-- Warning Banner when eBPF is active in form -->
			{#if formDataplane === "ebpf"}
				<div class="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-amber-900 dark:text-amber-200">
					<div class="flex items-start gap-3">
						<AlertTriangleIcon class="h-5 w-5 text-amber-600 dark:text-amber-400 mt-0.5 shrink-0" />
						<div class="space-y-1 text-sm">
							<p class="font-bold text-amber-800 dark:text-amber-300">
								Warning: eBPF PPPoE Fast-Path is highly experimental
							</p>
							<p class="text-xs text-amber-700 dark:text-amber-300/80 leading-relaxed">
								The eBPF data plane implementation is prone to stability issues, packet drops, and compatibility quirks with certain NIC drivers and ISP configurations. It is not recommended for production environments. Use <strong>Linux Kernel Standard (ppp_generic)</strong> for a reliable broadband connection.
							</p>
						</div>
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- eBPF Confirmation Dialog -->
	<AlertDialog.Root bind:open={showEbpfWarningDialog}>
		<AlertDialog.Content>
			<AlertDialog.Header>
				<AlertDialog.Title class="flex items-center gap-2 text-amber-600 dark:text-amber-400">
					<AlertTriangleIcon class="h-5 w-5" />
					Enable Experimental eBPF Data Plane?
				</AlertDialog.Title>
				<AlertDialog.Description class="space-y-2 text-left pt-2">
					<p>
						The <strong>eBPF PPPoE data plane</strong> is currently experimental and prone to <strong>severe bugs, connection dropouts, and stability issues</strong>.
					</p>
					<p>
						XDP bypasses standard Linux networking structures, which may cause unexpected behavior with routing, firewall rules, or keepalive management.
					</p>
					<p class="font-semibold text-foreground">
						Are you sure you want to switch to the experimental eBPF mode?
					</p>
				</AlertDialog.Description>
			</AlertDialog.Header>
			<AlertDialog.Footer>
				<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
				<AlertDialog.Action
					class="bg-amber-600 hover:bg-amber-700 text-white"
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
	<Tabs.Root value="credentials" class="space-y-4">
		<Tabs.List class="grid w-full grid-cols-3 md:w-[480px]">
			<Tabs.Trigger value="credentials" class="gap-2">
				<KeyIcon class="h-4 w-4" />
				<span>Credentials</span>
			</Tabs.Trigger>
			<Tabs.Trigger value="link" class="gap-2">
				<SlidersIcon class="h-4 w-4" />
				<span>Link & Timers</span>
			</Tabs.Trigger>
			<Tabs.Trigger value="nftables" class="gap-2">
				<ShieldIcon class="h-4 w-4" />
				<span>nftables Tuning</span>
			</Tabs.Trigger>
		</Tabs.List>

		<!-- Tab 1: Credentials & Interface -->
		<Tabs.Content value="credentials">
			<Card.Root>
				<Card.Header>
					<Card.Title>ISP Authentication & Uplink Interface</Card.Title>
					<Card.Description>
						Configure the physical Ethernet port, subscriber credentials, and authentication protocol.
					</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-6">
					<!-- Service Enable Switch -->
					<div class="flex items-center justify-between rounded-xl border p-4">
						<div class="space-y-0.5">
							<Label class="text-base font-semibold">Enable PPPoE Service</Label>
							<p class="text-xs text-muted-foreground">
								When enabled, Lanforge automatically discovers the Access Concentrator and maintains the session.
							</p>
						</div>
						<Switch bind:checked={formEnabled} />
					</div>

					<div class="grid gap-4 md:grid-cols-2">
						<div class="space-y-2">
							<Label for="wan_iface">Physical WAN Interface</Label>
							<Input
								id="wan_iface"
								bind:value={formWanIface}
								placeholder="e.g. eth1, end1, eno1"
							/>
							<p class="text-[11px] text-muted-foreground">
								The physical port connected to your fiber ONT, modem, or upstream switch.
							</p>
						</div>

						<div class="space-y-2">
							<Label for="auth_method">Authentication Protocol</Label>
							<select
								id="auth_method"
								bind:value={formAuth}
								class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
							>
								<option value="chap_md5">CHAP-MD5 (Recommended)</option>
								<option value="pap">PAP (Plaintext Password)</option>
								<option value="none">None (Unauthenticated)</option>
							</select>
							<p class="text-[11px] text-muted-foreground">
								Most ISPs require CHAP-MD5 authentication.
							</p>
						</div>

						<div class="space-y-2">
							<Label for="username">PPPoE Username</Label>
							<Input
								id="username"
								bind:value={formUsername}
								placeholder="user@isp.com"
							/>
						</div>

						<div class="space-y-2">
							<Label for="password">PPPoE Password</Label>
							<div class="relative">
								<Input
									id="password"
									type={showPassword ? "text" : "password"}
									bind:value={formPassword}
									placeholder="••••••••"
								/>
								<button
									type="button"
									class="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground"
									onclick={() => (showPassword = !showPassword)}
								>
									{#if showPassword}
										<EyeOffIcon class="h-4 w-4" />
									{:else}
										<EyeIcon class="h-4 w-4" />
									{/if}
								</button>
							</div>
						</div>

						<div class="space-y-2">
							<Label for="service_name">Service Name (Optional)</Label>
							<Input
								id="service_name"
								bind:value={formServiceName}
								placeholder="Leave empty for any"
							/>
						</div>

						<div class="space-y-2">
							<Label for="ac_name">Access Concentrator Name (Optional)</Label>
							<Input
								id="ac_name"
								bind:value={formAcName}
								placeholder="Leave empty for any"
							/>
						</div>
					</div>
				</Card.Content>
			</Card.Root>
		</Tabs.Content>

		<!-- Tab 2: Link & Timers -->
		<Tabs.Content value="link">
			<Card.Root>
				<Card.Header>
					<Card.Title>Link Parameters, MTU & Keepalive Timers</Card.Title>
					<Card.Description>
						Fine-tune packet sizing, discovery retry timeouts, and LCP keepalive echo intervals.
					</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-6">
					<div class="grid gap-4 md:grid-cols-2">
						<div class="space-y-2">
							<Label for="mru">Maximum Receive Unit (MRU / MTU)</Label>
							<Input
								id="mru"
								type="number"
								min="576"
								max="1500"
								bind:value={formMru}
							/>
							<p class="text-[11px] text-muted-foreground">
								Standard PPPoE MTU is 1492 (1500 Ethernet - 8 PPPoE bytes).
							</p>
						</div>

						<div class="space-y-2">
							<Label for="reconnect_delay">Reconnect Delay (Seconds)</Label>
							<Input
								id="reconnect_delay"
								type="number"
								min="1"
								max="300"
								bind:value={formReconnectDelay}
							/>
							<p class="text-[11px] text-muted-foreground">
								Pause before attempting discovery after a session drop.
							</p>
						</div>

						<div class="space-y-2">
							<Label for="echo_interval">LCP Echo Keepalive Interval (s)</Label>
							<Input
								id="echo_interval"
								type="number"
								min="1"
								max="120"
								bind:value={formEchoInterval}
							/>
							<p class="text-[11px] text-muted-foreground">
								Frequency of LCP Echo-Requests sent to the Access Concentrator.
							</p>
						</div>

						<div class="space-y-2">
							<Label for="echo_failures">LCP Echo Max Failures</Label>
							<Input
								id="echo_failures"
								type="number"
								min="1"
								max="20"
								bind:value={formEchoMaxFailures}
							/>
							<p class="text-[11px] text-muted-foreground">
								Consecutive unanswered echoes before declaring session dead.
							</p>
						</div>

						<div class="space-y-2">
							<Label for="padi_retries">Discovery PADI Retries</Label>
							<Input
								id="padi_retries"
								type="number"
								min="1"
								max="20"
								bind:value={formPadiRetries}
							/>
						</div>

						<div class="space-y-2">
							<Label for="padi_timeout">PADI Timeout per Retry (s)</Label>
							<Input
								id="padi_timeout"
								type="number"
								min="1"
								max="30"
								bind:value={formPadiTimeout}
							/>
						</div>
					</div>

					<Separator />

					<div class="flex items-center justify-between">
						<div class="space-y-0.5">
							<Label class="text-sm font-semibold">Send PADT Frame on Shutdown</Label>
							<p class="text-xs text-muted-foreground">
								Explicitly notifies the BRAS to terminate the session on service stop. (Disable for fast-reconnect debugging).
							</p>
						</div>
						<Switch bind:checked={formSendPadt} />
					</div>
				</Card.Content>
			</Card.Root>
		</Tabs.Content>

		<!-- Tab 3: nftables Tuning -->
		<Tabs.Content value="nftables">
			<Card.Root>
				<Card.Header>
					<Card.Title>Kernel Router Performance & nftables Tuning</Card.Title>
					<Card.Description>
						Automatic router optimizations, TCP MSS clamping, Flowtable fast-path, and VoWiFi bypass.
					</Card.Description>
				</Card.Header>
				<Card.Content class="space-y-4">
					<div class="flex items-center justify-between rounded-xl border p-4">
						<div class="space-y-0.5">
							<Label class="text-base font-semibold">Apply nftables Router Tuning</Label>
							<p class="text-xs text-muted-foreground">
								Automatically applies optimized firewall rules, fast routing, and connection tracking filters.
							</p>
						</div>
						<Switch bind:checked={formNftEnabled} />
					</div>

					<div class="grid gap-4 md:grid-cols-2">
						<div class="flex items-center justify-between rounded-xl border p-3">
							<div class="space-y-0.5">
								<Label class="text-sm font-medium">Flowtable Offloading</Label>
								<p class="text-[11px] text-muted-foreground">
									Fast-path established TCP/UDP flows directly in software flowtable.
								</p>
							</div>
							<Switch bind:checked={formNftFlowOffload} disabled={!formNftEnabled} />
						</div>

						<div class="flex items-center justify-between rounded-xl border p-3">
							<div class="space-y-0.5">
								<Label class="text-sm font-medium">TCP MSS Clamping (1452)</Label>
								<p class="text-[11px] text-muted-foreground">
									Prevents PMTU discovery blackholes on 1492 MTU links.
								</p>
							</div>
							<Switch bind:checked={formNftMssClamping} disabled={!formNftEnabled} />
						</div>

						<div class="flex items-center justify-between rounded-xl border p-3">
							<div class="space-y-0.5">
								<Label class="text-sm font-medium">DNS Port 53 / 853 Bypass</Label>
								<p class="text-[11px] text-muted-foreground">
									Bypasses flowtable for DNS to ensure local resolver analytics and adblock function accurately.
								</p>
							</div>
							<Switch bind:checked={formNftBypassDns} disabled={!formNftEnabled} />
						</div>

						<div class="flex items-center justify-between rounded-xl border p-3">
							<div class="space-y-0.5">
								<Label class="text-sm font-medium">VoWiFi / IPsec (Ports 500 / 4500) Bypass</Label>
								<p class="text-[11px] text-muted-foreground">
									Keeps Wi-Fi Calling tunnels alive without flowtable aging disconnects.
								</p>
							</div>
							<Switch bind:checked={formNftBypassVowifi} disabled={!formNftEnabled} />
						</div>

						<div class="flex items-center justify-between rounded-xl border p-3">
							<div class="space-y-0.5">
								<Label class="text-sm font-medium">Outbound NAT Masquerade</Label>
								<p class="text-[11px] text-muted-foreground">
									Enables source NAT masquerading for all LAN clients routing through WAN.
								</p>
							</div>
							<Switch bind:checked={formNftMasquerade} disabled={!formNftEnabled} />
						</div>
					</div>
				</Card.Content>
			</Card.Root>
		</Tabs.Content>
	</Tabs.Root>

	<!-- Save Action Footer Bar -->
	<div class="flex items-center justify-end gap-3 pt-4 border-t">
		<Button variant="outline" onclick={loadAll} disabled={saving || loading}>
			Discard Changes
		</Button>
		<Button onclick={handleSave} disabled={saving || loading}>
			{#if saving}
				<RefreshCwIcon class="mr-2 h-4 w-4 animate-spin" />
				Saving...
			{:else}
				<CheckCircleIcon class="mr-2 h-4 w-4" />
				Save Configuration
			{/if}
		</Button>
	</div>
</div>
