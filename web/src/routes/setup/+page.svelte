<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { auth } from "$lib/stores/auth.svelte";
	import { getSetupStatus, submitSetup, ApiError } from "$lib/api/client";
	import type { SetupStatusResponse, SetupPayload, SetupWanConfig, SetupRaConfig, FirewallMode } from "$lib/api/types";
	import { goto } from "$app/navigation";
	import { onMount } from "svelte";
	import { toast } from "svelte-sonner";
	import { markSetupCompleted } from "$lib/stores/setup.svelte";

	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import CheckIcon from "@lucide/svelte/icons/check";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";

	import AdminStep from "./components/AdminStep.svelte";
	import UplinkStep from "./components/UplinkStep.svelte";
	import LanStep from "./components/LanStep.svelte";
	import FirewallStep from "./components/FirewallStep.svelte";
	import ReviewStep from "./components/ReviewStep.svelte";

	let step = $state<1 | 2 | 3 | 4 | 5>(1);
	let loading = $state(true);
	let submitting = $state(false);
	let errorMsg = $state("");

	let setupStatus = $state<SetupStatusResponse | null>(null);

	// Step 1: Admin Credentials
	let admin_username = $state("admin");
	let admin_password = $state("");
	let confirm_password = $state("");

	// Step 2: Uplink Connection Mode
	let wan_mode = $state<"system_gateway" | "pppoe">("system_gateway");
	let wan_iface = $state("");
	let pppoe_username = $state("");
	let pppoe_password = $state("");
	let pppoe_vlan = $state("");
	let pppoe_mtu = $state(1492);
	let system_gateway = $state("192.168.1.1");

	// Step 3: LAN Network & Presence
	let lan_iface = $state("");
	let lan_ip = $state("192.168.1.1");
	let subnet_mask = $state("255.255.255.0");
	let dhcp_enabled = $state(true);
	let dhcp_pool_start = $state("192.168.1.100");
	let dhcp_pool_end = $state("192.168.1.240");
	let dhcp_router = $state("192.168.1.1");
	let domain_name = $state("lan");
	let adblock_enabled = $state(true);

	// IPv6 Router Advertisement (RA)
	let ra_enabled = $state(true);
	let ra_auto_gua = $state(true);
	let ra_ula_enabled = $state(true);
	let ra_ula_prefix = $state("");

	// DNS Upstream
	let dns_preset = $state<"quad9" | "cloudflare" | "google" | "custom">("quad9");
	let custom_dns_servers = $state("9.9.9.9, 149.112.112.112");

	// Step 4: Firewall & Security
	let firewall_mode = $state<FirewallMode>("full");
	let firewall_flow_offload = $state(true);

	function cidrToSubnetMask(prefixLen: number): string {
		if (prefixLen <= 0) return "0.0.0.0";
		if (prefixLen >= 32) return "255.255.255.255";
		const mask = (~0 << (32 - prefixLen)) >>> 0;
		return [
			(mask >>> 24) & 255,
			(mask >>> 16) & 255,
			(mask >>> 8) & 255,
			mask & 255,
		].join(".");
	}

	function onLanIfaceChange(name: string) {
		lan_iface = name;
		if (setupStatus) {
			const found = setupStatus.interfaces.find((i) => i.name === name);
			if (found && found.ips.length > 0) {
				const v4 = found.ips.find((ip) => !ip.includes(":"));
				if (v4) {
					const [cleanIp, prefixStr] = v4.split("/");
					lan_ip = cleanIp;
					dhcp_router = cleanIp;

					if (prefixStr) {
						const prefixLen = parseInt(prefixStr, 10);
						if (!isNaN(prefixLen) && prefixLen >= 0 && prefixLen <= 32) {
							subnet_mask = cidrToSubnetMask(prefixLen);
						}
					}

					const parts = cleanIp.split(".");
					if (parts.length === 4) {
						dhcp_pool_start = `${parts[0]}.${parts[1]}.${parts[2]}.100`;
						dhcp_pool_end = `${parts[0]}.${parts[1]}.${parts[2]}.240`;
					}
				}
			}
			if (name === setupStatus.detected_lan_iface && setupStatus.detected_subnet_mask) {
				subnet_mask = setupStatus.detected_subnet_mask;
			}
		}
	}

	onMount(async () => {
		try {
			const res = await getSetupStatus();
			setupStatus = res;

			if (res.detected_ula_prefix) {
				ra_ula_prefix = res.detected_ula_prefix;
			}

			if (res.detected_lan_iface) {
				onLanIfaceChange(res.detected_lan_iface);
			} else if (res.interfaces.length > 0) {
				onLanIfaceChange(res.interfaces[0].name);
			}

			// Preselect WAN interface if multiple interfaces exist
			const otherIface = res.interfaces.find((i) => i.name !== lan_iface);
			if (otherIface) {
				wan_iface = otherIface.name;
			} else if (res.interfaces.length > 0) {
				wan_iface = res.interfaces[0].name;
			}

			if (res.detected_gateway) {
				system_gateway = res.detected_gateway;
			}
		} catch {
			errorMsg = "Failed to load system environment status.";
		} finally {
			loading = false;
		}
	});

	function handleNextStep1() {
		errorMsg = "";
		if (admin_password.length < 8) {
			errorMsg = "Password must be at least 8 characters long.";
			return;
		}
		if (admin_password !== confirm_password) {
			errorMsg = "Passwords do not match.";
			return;
		}
		step = 2;
	}

	function handleNextStep2() {
		errorMsg = "";
		if (wan_mode === "pppoe") {
			if (!wan_iface) {
				errorMsg = "Please select a WAN interface.";
				return;
			}
			if (!pppoe_username.trim()) {
				errorMsg = "PPPoE username cannot be empty.";
				return;
			}
		} else {
			if (!system_gateway.trim()) {
				errorMsg = "Please specify the upstream gateway IP.";
				return;
			}
		}
		step = 3;
	}

	function handleNextStep3() {
		errorMsg = "";
		if (!lan_iface) {
			errorMsg = "Please select a LAN interface.";
			return;
		}
		if (!lan_ip.trim()) {
			errorMsg = "LAN IP cannot be empty.";
			return;
		}
		step = 4;
	}

	function handleNextStep4() {
		errorMsg = "";
		step = 5;
	}

	function getUpstreamDnsList(): string[] {
		switch (dns_preset) {
			case "quad9":
				return ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"];
			case "cloudflare":
				return ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"];
			case "google":
				return ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"];
			case "custom":
				return custom_dns_servers
					.split(",")
					.map((s) => s.trim())
					.filter((s) => s.length > 0);
		}
	}

	async function handleLaunch() {
		errorMsg = "";
		submitting = true;

		let wanConfig: SetupWanConfig | null = null;
		if (wan_mode === "pppoe") {
			wanConfig = {
				mode: "pppoe",
				interface: wan_iface,
				username: pppoe_username,
				password: pppoe_password,
				vlan_id: pppoe_vlan ? Number.parseInt(pppoe_vlan, 10) : null,
				mtu: pppoe_mtu || 1492,
				nftables: {
					flow_offload: firewall_flow_offload,
					mss_clamping: true,
					masquerade: true,
					bypass_dns: true,
					bypass_vowifi: true
				}
			};
		} else {
			wanConfig = {
				mode: "system_gateway",
				gateway_ip: system_gateway
			};
		}

		const raConfig: SetupRaConfig = {
			enabled: ra_enabled,
			auto_gua: ra_auto_gua,
			ula_enabled: ra_ula_enabled,
			ula_prefix: ra_ula_prefix.trim() || null,
			managed: true,
			other_config: true
		};

		const payload: SetupPayload = {
			admin_username,
			admin_password,
			lan_iface,
			lan_ip,
			subnet_mask,
			domain_name,
			dhcp_enabled,
			dhcp_pool_start,
			dhcp_pool_end,
			dhcp_router: dhcp_router.trim() || lan_ip,
			adblock_enabled,
			upstream_dns: getUpstreamDnsList(),
			ra: raConfig,
			wan: wanConfig,
			firewall_mode
		};

		try {
			const res = await submitSetup(payload);
			if (res.token) {
				auth.setToken(res.token);
			}
			await auth.fetchUser();
			markSetupCompleted();
			toast.success("Router configuration successfully deployed! Welcome to Lanforge.");
			goto("/");
		} catch (e) {
			if (e instanceof ApiError) {
				errorMsg = e.message;
			} else {
				errorMsg = "An unexpected error occurred while applying initial setup.";
			}
		} finally {
			submitting = false;
		}
	}
</script>

<div class="relative flex min-h-screen w-full items-center justify-center bg-background p-4 sm:p-8">
	<!-- Background glow / pattern -->
	<div class="pointer-events-none absolute inset-0 overflow-hidden opacity-25">
		<div class="absolute -top-[25%] -left-[10%] h-[500px] w-[500px] rounded-full bg-cyan-500/20 blur-[120px]"></div>
		<div class="absolute -bottom-[20%] -right-[10%] h-[500px] w-[500px] rounded-full bg-blue-600/20 blur-[120px]"></div>
	</div>

	<div class="relative w-full max-w-2xl">
		<!-- Header / Logo -->
		<div class="mb-8 text-center">
			<div class="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs font-medium text-cyan-400">
				<SparklesIcon class="h-3.5 w-3.5" />
				First-Run Onboarding Wizard
			</div>
			<h1 class="mt-3 text-3xl font-bold tracking-tight text-foreground">Welcome to Lanforge</h1>
			<p class="mt-1 text-sm text-muted-foreground">Complete this quick setup to configure your router, IPv6 SLAAC, and network services.</p>
		</div>

		{#if setupStatus && (!setupStatus.first_run || setupStatus.is_provisioned)}
			<!-- Already Provisioned Locked Card -->
			<Card.Root class="border-border/60 bg-card/80 backdrop-blur-sm shadow-xl text-center p-8">
				<div class="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-400 mb-4">
					<ShieldCheckIcon class="h-8 w-8" />
				</div>
				<h2 class="text-2xl font-bold text-foreground">Lanforge is Operational</h2>
				<p class="mt-2 text-sm text-muted-foreground max-w-md mx-auto">
					This instance has already been provisioned and configured. The onboarding setup wizard is permanently locked to prevent unauthorized changes.
				</p>
				<div class="mt-6 flex justify-center gap-4">
					<Button onclick={() => goto("/")} class="gap-2">
						Open Web Console
						<ArrowRightIcon class="h-4 w-4" />
					</Button>
				</div>
			</Card.Root>
		{:else}
			<!-- Step Progress Indicator -->
			<div class="mb-8 flex items-center justify-between px-2 sm:px-4">
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 1 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						{#if step > 1}<CheckIcon class="h-4 w-4" />{:else}1{/if}
					</div>
					<span class="text-[11px] sm:text-xs font-medium {step >= 1 ? 'text-foreground' : 'text-muted-foreground'}">Admin</span>
				</div>
				<div class="h-0.5 flex-1 mx-1.5 sm:mx-2 transition-all {step >= 2 ? 'bg-primary' : 'bg-muted'}"></div>
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 2 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						{#if step > 2}<CheckIcon class="h-4 w-4" />{:else}2{/if}
					</div>
					<span class="text-[11px] sm:text-xs font-medium {step >= 2 ? 'text-foreground' : 'text-muted-foreground'}">Uplink</span>
				</div>
				<div class="h-0.5 flex-1 mx-1.5 sm:mx-2 transition-all {step >= 3 ? 'bg-primary' : 'bg-muted'}"></div>
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 3 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						{#if step > 3}<CheckIcon class="h-4 w-4" />{:else}3{/if}
					</div>
					<span class="text-[11px] sm:text-xs font-medium {step >= 3 ? 'text-foreground' : 'text-muted-foreground'}">LAN</span>
				</div>
				<div class="h-0.5 flex-1 mx-1.5 sm:mx-2 transition-all {step >= 4 ? 'bg-primary' : 'bg-muted'}"></div>
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 4 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						{#if step > 4}<CheckIcon class="h-4 w-4" />{:else}4{/if}
					</div>
					<span class="text-[11px] sm:text-xs font-medium {step >= 4 ? 'text-foreground' : 'text-muted-foreground'}">Firewall</span>
				</div>
				<div class="h-0.5 flex-1 mx-1.5 sm:mx-2 transition-all {step >= 5 ? 'bg-primary' : 'bg-muted'}"></div>
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 5 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						5
					</div>
					<span class="text-[11px] sm:text-xs font-medium {step >= 5 ? 'text-foreground' : 'text-muted-foreground'}">Launch</span>
				</div>
			</div>

			<!-- Card Content -->
			<Card.Root class="border-border/60 bg-card/80 backdrop-blur-sm shadow-xl">
				{#if errorMsg}
					<div class="m-6 mb-0 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
						{errorMsg}
					</div>
				{/if}

				{#if step === 1}
					<AdminStep
						bind:username={admin_username}
						bind:password={admin_password}
						bind:confirmPassword={confirm_password}
						onnext={handleNextStep1}
					/>
				{:else if step === 2}
					<UplinkStep
						bind:wanMode={wan_mode}
						bind:systemGateway={system_gateway}
						bind:wanIface={wan_iface}
						bind:pppoeUsername={pppoe_username}
						bind:pppoePassword={pppoe_password}
						bind:pppoeVlan={pppoe_vlan}
						bind:pppoeMtu={pppoe_mtu}
						interfaces={setupStatus?.interfaces ?? []}
						onback={() => (step = 1)}
						onnext={handleNextStep2}
					/>
				{:else if step === 3}
					<LanStep
						bind:lanIface={lan_iface}
						bind:lanIp={lan_ip}
						bind:subnetMask={subnet_mask}
						bind:dhcpPoolStart={dhcp_pool_start}
						bind:dhcpPoolEnd={dhcp_pool_end}
						bind:dhcpRouter={dhcp_router}
						bind:domainName={domain_name}
						bind:raEnabled={ra_enabled}
						bind:raAutoGua={ra_auto_gua}
						bind:raUlaEnabled={ra_ula_enabled}
						bind:raUlaPrefix={ra_ula_prefix}
						bind:dnsPreset={dns_preset}
						bind:customDnsServers={custom_dns_servers}
						bind:adblockEnabled={adblock_enabled}
						interfaces={setupStatus?.interfaces ?? []}
						{onLanIfaceChange}
						onback={() => (step = 2)}
						onnext={handleNextStep3}
					/>
				{:else if step === 4}
					<FirewallStep
						bind:firewallMode={firewall_mode}
						bind:firewallFlowOffload={firewall_flow_offload}
						onback={() => (step = 3)}
						onnext={handleNextStep4}
					/>
				{:else if step === 5}
					<ReviewStep
						adminUsername={admin_username}
						wanMode={wan_mode}
						wanIface={wan_iface}
						pppoeVlan={pppoe_vlan}
						systemGateway={system_gateway}
						lanIface={lan_iface}
						lanIp={lan_ip}
						subnetMask={subnet_mask}
						dhcpPoolStart={dhcp_pool_start}
						dhcpPoolEnd={dhcp_pool_end}
						dhcpRouter={dhcp_router}
						raEnabled={ra_enabled}
						raAutoGua={ra_auto_gua}
						raUlaEnabled={ra_ula_enabled}
						domainName={domain_name}
						upstreamDnsList={getUpstreamDnsList()}
						adblockEnabled={adblock_enabled}
						firewallMode={firewall_mode}
						firewallFlowOffload={firewall_flow_offload}
						{submitting}
						onback={() => (step = 4)}
						onlaunch={handleLaunch}
					/>
				{/if}
			</Card.Root>
		{/if}
	</div>
</div>
