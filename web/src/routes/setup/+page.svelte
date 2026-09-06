<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Label } from "$lib/components/ui/label";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import { auth } from "$lib/stores/auth.svelte";
	import { getSetupStatus, submitSetup, ApiError } from "$lib/api/client";
	import type { SetupStatusResponse, SetupPayload, SetupWanConfig, SetupRaConfig } from "$lib/api/types";
	import { goto } from "$app/navigation";
	import { onMount } from "svelte";
	import { toast } from "svelte-sonner";

	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import ArrowLeftIcon from "@lucide/svelte/icons/arrow-left";
	import CheckIcon from "@lucide/svelte/icons/check";
	import LockIcon from "@lucide/svelte/icons/lock";
	import UserIcon from "@lucide/svelte/icons/user";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ChevronUpIcon from "@lucide/svelte/icons/chevron-up";
	import RadioIcon from "@lucide/svelte/icons/radio";

	let step = $state<1 | 2 | 3 | 4>(1);
	let loading = $state(true);
	let submitting = $state(false);
	let errorMsg = $state("");

	let setupStatus = $state<SetupStatusResponse | null>(null);

	// Step 1: Admin Credentials
	let admin_username = $state("admin");
	let admin_password = $state("");
	let confirm_password = $state("");
	let showPassword = $state(false);

	// Step 2: Uplink Connection Mode
	let wan_mode = $state<"system_gateway" | "pppoe">("system_gateway");
	let wan_iface = $state("");
	let pppoe_username = $state("");
	let pppoe_password = $state("");
	let pppoe_vlan = $state("");
	let pppoe_mtu = $state(1492);
	let show_advanced_pppoe = $state(false);
	let pppoe_flow_offload = $state(false);
	let pppoe_mss_clamping = $state(true);
	let pppoe_masquerade = $state(true);
	let pppoe_bypass_dns = $state(true);
	let pppoe_bypass_vowifi = $state(true);
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
	let ra_ula_prefix = $state("fd97:f00d:cafe:3731::/64");

	// DNS Upstream
	let dns_preset = $state<"quad9" | "cloudflare" | "google" | "custom">("quad9");
	let custom_dns_servers = $state("9.9.9.9, 149.112.112.112");

	function onLanIfaceChange(name: string) {
		lan_iface = name;
		if (setupStatus) {
			const found = setupStatus.interfaces.find((i) => i.name === name);
			if (found && found.ips.length > 0) {
				const v4 = found.ips.find((ip) => !ip.includes(":"));
				if (v4) {
					const cleanIp = v4.split("/")[0];
					lan_ip = cleanIp;
					dhcp_router = cleanIp;

					const parts = cleanIp.split(".");
					if (parts.length === 4) {
						dhcp_pool_start = `${parts[0]}.${parts[1]}.${parts[2]}.100`;
						dhcp_pool_end = `${parts[0]}.${parts[1]}.${parts[2]}.240`;
					}
				}
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

	function getUpstreamDnsList(): string[] {
		switch (dns_preset) {
			case "quad9":
				return ["9.9.9.9", "149.112.112.112"];
			case "cloudflare":
				return ["1.1.1.1", "1.0.0.1"];
			case "google":
				return ["8.8.8.8", "8.8.4.4"];
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
					flow_offload: pppoe_flow_offload,
					mss_clamping: pppoe_mss_clamping,
					masquerade: pppoe_masquerade,
					bypass_dns: pppoe_bypass_dns,
					bypass_vowifi: pppoe_bypass_vowifi
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
			wan: wanConfig
		};

		try {
			const res = await submitSetup(payload);
			if (res.token) {
				auth.setToken(res.token);
			}
			await auth.fetchUser();
			toast.success("Lanforge initialized and operational!");
			goto("/");
		} catch (err) {
			if (err instanceof ApiError) {
				errorMsg = err.message;
			} else {
				errorMsg = "Failed to submit configuration. Check daemon connection.";
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
			<div class="mb-8 flex items-center justify-between px-4">
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 1 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						{#if step > 1}<CheckIcon class="h-4 w-4" />{:else}1{/if}
					</div>
					<span class="text-xs font-medium {step >= 1 ? 'text-foreground' : 'text-muted-foreground'}">Security</span>
				</div>
				<div class="h-0.5 flex-1 mx-2 transition-all {step >= 2 ? 'bg-primary' : 'bg-muted'}"></div>
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 2 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						{#if step > 2}<CheckIcon class="h-4 w-4" />{:else}2{/if}
					</div>
					<span class="text-xs font-medium {step >= 2 ? 'text-foreground' : 'text-muted-foreground'}">Uplink</span>
				</div>
				<div class="h-0.5 flex-1 mx-2 transition-all {step >= 3 ? 'bg-primary' : 'bg-muted'}"></div>
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 3 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						{#if step > 3}<CheckIcon class="h-4 w-4" />{:else}3{/if}
					</div>
					<span class="text-xs font-medium {step >= 3 ? 'text-foreground' : 'text-muted-foreground'}">LAN & Services</span>
				</div>
				<div class="h-0.5 flex-1 mx-2 transition-all {step >= 4 ? 'bg-primary' : 'bg-muted'}"></div>
				<div class="flex flex-col items-center gap-1">
					<div class="flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold transition-all {step >= 4 ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'}">
						4
					</div>
					<span class="text-xs font-medium {step >= 4 ? 'text-foreground' : 'text-muted-foreground'}">Launch</span>
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
					<Card.Header>
						<div class="flex items-center gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
								<ShieldCheckIcon class="h-5 w-5" />
							</div>
							<div>
								<Card.Title>Administrator Security</Card.Title>
								<Card.Description>Create your primary administrator account to secure the network console.</Card.Description>
							</div>
						</div>
					</Card.Header>
					<Card.Content class="space-y-4">
						<div class="space-y-1.5">
							<Label for="username">Admin Username</Label>
							<div class="relative">
								<UserIcon class="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
								<Input id="username" class="pl-9" bind:value={admin_username} placeholder="admin" />
							</div>
						</div>

						<div class="space-y-1.5">
							<Label for="password">Password (Minimum 8 characters)</Label>
							<div class="relative">
								<LockIcon class="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
								<Input
									id="password"
									type={showPassword ? "text" : "password"}
									class="pl-9 pr-9"
									bind:value={admin_password}
									placeholder="••••••••••••"
								/>
								<button
									type="button"
									class="absolute right-3 top-3 text-muted-foreground hover:text-foreground"
									onclick={() => (showPassword = !showPassword)}
								>
									{#if showPassword}<EyeOffIcon class="h-4 w-4" />{:else}<EyeIcon class="h-4 w-4" />{/if}
								</button>
							</div>
						</div>

						<div class="space-y-1.5">
							<Label for="confirm_password">Confirm Password</Label>
							<div class="relative">
								<LockIcon class="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
								<Input
									id="confirm_password"
									type={showPassword ? "text" : "password"}
									class="pl-9"
									bind:value={confirm_password}
									placeholder="••••••••••••"
								/>
							</div>
						</div>
					</Card.Content>
					<Card.Footer class="flex justify-end">
						<Button onclick={handleNextStep1} class="gap-2">
							Next: Internet Uplink
							<ArrowRightIcon class="h-4 w-4" />
						</Button>
					</Card.Footer>

				{:else if step === 2}
					<Card.Header>
						<div class="flex items-center gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
								<GlobeIcon class="h-5 w-5" />
							</div>
							<div>
								<Card.Title>Internet / Uplink Connection</Card.Title>
								<Card.Description>Select how this device connects to your ISP or upstream router.</Card.Description>
							</div>
						</div>
					</Card.Header>
					<Card.Content class="space-y-4">
						<div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
							<!-- System-Managed Mode -->
							<button
								type="button"
								class="flex flex-col items-start rounded-xl border p-4 text-left transition-all {wan_mode === 'system_gateway' ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-muted-foreground/40'}"
								onclick={() => (wan_mode = "system_gateway")}
							>
								<div class="flex w-full items-center justify-between mb-2">
									<ServerIcon class="h-5 w-5 text-primary" />
									{#if wan_mode === "system_gateway"}<Badge variant="default">Selected</Badge>{/if}
								</div>
								<h4 class="font-semibold text-foreground">System-Managed Uplink</h4>
								<p class="mt-1 text-xs text-muted-foreground">
									Single-NIC or OS-managed network (systemd-networkd / existing modem).
								</p>
							</button>

							<!-- Integrated PPPoE Mode -->
							<button
								type="button"
								class="flex flex-col items-start rounded-xl border p-4 text-left transition-all {wan_mode === 'pppoe' ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-muted-foreground/40'}"
								onclick={() => (wan_mode = "pppoe")}
							>
								<div class="flex w-full items-center justify-between mb-2">
									<GlobeIcon class="h-5 w-5 text-primary" />
									{#if wan_mode === "pppoe"}<Badge variant="default">Selected</Badge>{/if}
								</div>
								<h4 class="font-semibold text-foreground">Integrated PPPoE</h4>
								<p class="mt-1 text-xs text-muted-foreground">
									Direct Fiber / DSL dial-in managed on a dedicated WAN port by Lanforge.
								</p>
							</button>
						</div>

						<Separator class="my-4" />

						{#if wan_mode === "system_gateway"}
							<div class="space-y-1.5">
								<Label for="gateway_ip">Upstream Default Gateway IP</Label>
								<Input id="gateway_ip" bind:value={system_gateway} placeholder="192.168.1.1" />
								<p class="text-xs text-muted-foreground mt-1">
									LAN clients will route internet traffic through this IP while Lanforge orchestrates DHCP and local DNS.
								</p>
							</div>
						{:else}
							<div class="space-y-3">
								<div class="space-y-1.5">
									<Label for="wan_iface">WAN Interface</Label>
									<select id="wan_iface" class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background" bind:value={wan_iface}>
										{#if setupStatus}
											{#each setupStatus.interfaces as iface}
												<option value={iface.name}>
													{iface.name} ({iface.bus_type} - {iface.carrier_up ? '🟢 Cable Connected' : '⚪ Disconnected'})
												</option>
											{/each}
										{/if}
									</select>
								</div>

								<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
									<div class="space-y-1.5">
										<Label for="pppoe_user">PPPoE Username</Label>
										<Input id="pppoe_user" bind:value={pppoe_username} placeholder="client@isp.com" />
									</div>
									<div class="space-y-1.5">
										<Label for="pppoe_pass">PPPoE Password</Label>
										<Input id="pppoe_pass" type="password" bind:value={pppoe_password} placeholder="••••••••" />
									</div>
								</div>

								<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
									<div class="space-y-1.5">
										<Label for="pppoe_vlan">VLAN Tag (Optional)</Label>
										<Input id="pppoe_vlan" bind:value={pppoe_vlan} placeholder="e.g. 35 (leave empty if none)" />
									</div>
									<div class="space-y-1.5">
										<Label for="pppoe_mtu">WAN MTU / MRU</Label>
										<Input id="pppoe_mtu" type="number" bind:value={pppoe_mtu} placeholder="1492" />
									</div>
								</div>

								<!-- Advanced PPPoE & Firewall Tuning Accordion -->
								<div class="rounded-lg border bg-muted/20 p-3 mt-2">
									<button
										type="button"
										class="flex w-full items-center justify-between text-xs font-semibold text-foreground hover:text-primary transition-colors"
										onclick={() => (show_advanced_pppoe = !show_advanced_pppoe)}
									>
										<span class="inline-flex items-center gap-1.5">
											<SlidersIcon class="h-3.5 w-3.5" />
											Advanced PPPoE & nftables Firewall Options
										</span>
										{#if show_advanced_pppoe}<ChevronUpIcon class="h-3.5 w-3.5" />{:else}<ChevronDownIcon class="h-3.5 w-3.5" />{/if}
									</button>

									{#if show_advanced_pppoe}
										<div class="mt-3 space-y-2.5 pt-2 border-t text-xs">
											<div class="flex items-center justify-between">
												<div>
													<p class="font-medium text-foreground">MSS Clamping</p>
													<p class="text-muted-foreground">Clamps TCP MSS to MTU - 40 to avoid packet fragmentation.</p>
												</div>
												<Switch bind:checked={pppoe_mss_clamping} />
											</div>
											<div class="flex items-center justify-between">
												<div>
													<p class="font-medium text-foreground">Flow Offloading</p>
													<p class="text-muted-foreground">Hardware/kernel bypass (disable if using SQM CAKE QoS).</p>
												</div>
												<Switch bind:checked={pppoe_flow_offload} />
											</div>
											<div class="flex items-center justify-between">
												<div>
													<p class="font-medium text-foreground">NAT Masquerade</p>
													<p class="text-muted-foreground">Enable kernel NAT masquerading on the PPPoE WAN interface.</p>
												</div>
												<Switch bind:checked={pppoe_masquerade} />
											</div>
											<div class="flex items-center justify-between">
												<div>
													<p class="font-medium text-foreground">Bypass Local DNS</p>
													<p class="text-muted-foreground">Ensure router-local DNS queries bypass flow offloading.</p>
												</div>
												<Switch bind:checked={pppoe_bypass_dns} />
											</div>
											<div class="flex items-center justify-between">
												<div>
													<p class="font-medium text-foreground">Bypass VoWiFi (IPsec ESP)</p>
													<p class="text-muted-foreground">Ensure Wi-Fi calling tunnels bypass offload table.</p>
												</div>
												<Switch bind:checked={pppoe_bypass_vowifi} />
											</div>
										</div>
									{/if}
								</div>
							</div>
						{/if}
					</Card.Content>
					<Card.Footer class="flex justify-between">
						<Button variant="outline" onclick={() => (step = 1)} class="gap-2">
							<ArrowLeftIcon class="h-4 w-4" />
							Back
						</Button>
						<Button onclick={handleNextStep2} class="gap-2">
							Next: LAN & Services
							<ArrowRightIcon class="h-4 w-4" />
						</Button>
					</Card.Footer>

				{:else if step === 3}
					<Card.Header>
						<div class="flex items-center gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
								<NetworkIcon class="h-5 w-5" />
							</div>
							<div>
								<Card.Title>LAN Subnet, DHCP, RA & DNS</Card.Title>
								<Card.Description>Configure local address pools, IPv6 SLAAC, and DNS resolver.</Card.Description>
							</div>
						</div>
					</Card.Header>
					<Card.Content class="space-y-4">
						<div class="space-y-1.5">
							<Label for="lan_iface">LAN Interface (Local Network)</Label>
							<select
								id="lan_iface"
								class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background"
								value={lan_iface}
								onchange={(e) => onLanIfaceChange((e.target as HTMLSelectElement).value)}
							>
								{#if setupStatus}
									{#each setupStatus.interfaces as iface}
										<option value={iface.name}>
											{iface.name} ({iface.bus_type} - {iface.carrier_up ? '🟢 Cable Connected' : '⚪ Disconnected'} {iface.ips[0] ? `[${iface.ips[0]}]` : ''})
										</option>
									{/each}
								{/if}
							</select>
						</div>

						<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
							<div class="space-y-1.5">
								<Label for="lan_ip">Lanforge Router IP</Label>
								<Input id="lan_ip" bind:value={lan_ip} placeholder="192.168.1.1" onchange={() => (dhcp_router = lan_ip)} />
							</div>
							<div class="space-y-1.5">
								<Label for="subnet_mask">Subnet Mask</Label>
								<Input id="subnet_mask" bind:value={subnet_mask} placeholder="255.255.255.0" />
							</div>
						</div>

						<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
							<div class="space-y-1.5">
								<Label for="pool_start">DHCPv4 Pool Start</Label>
								<Input id="pool_start" bind:value={dhcp_pool_start} placeholder="192.168.1.100" />
							</div>
							<div class="space-y-1.5">
								<Label for="pool_end">DHCPv4 Pool End</Label>
								<Input id="pool_end" bind:value={dhcp_pool_end} placeholder="192.168.1.240" />
							</div>
						</div>

						<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
							<div class="space-y-1.5">
								<Label for="dhcp_router">DHCP Default Gateway (Router)</Label>
								<Input id="dhcp_router" bind:value={dhcp_router} placeholder="192.168.1.1" />
							</div>
							<div class="space-y-1.5">
								<Label for="domain_name">Local Domain</Label>
								<Input id="domain_name" bind:value={domain_name} placeholder="lan" />
							</div>
						</div>

						<Separator class="my-2" />

						<!-- IPv6 Router Advertisement (RA) Card -->
						<div class="rounded-lg border bg-muted/20 p-3.5 space-y-3">
							<div class="flex items-center justify-between">
								<div class="flex items-center gap-2">
									<RadioIcon class="h-4 w-4 text-cyan-400" />
									<div>
										<h5 class="text-sm font-semibold text-foreground">IPv6 Router Advertisement (SLAAC)</h5>
										<p class="text-xs text-muted-foreground">Dual-prefix auto-configuration (ULA local + Auto-GUA public ISP).</p>
									</div>
								</div>
								<Switch bind:checked={ra_enabled} />
							</div>

							{#if ra_enabled}
								<div class="grid grid-cols-1 gap-2 sm:grid-cols-2 pt-2 border-t text-xs">
									<div class="flex items-center justify-between rounded border bg-background/50 p-2">
										<div>
											<p class="font-medium text-foreground">Auto-GUA Delegated Prefix</p>
											<p class="text-muted-foreground">SLAAC for ISP public IPv6 addresses.</p>
										</div>
										<Switch bind:checked={ra_auto_gua} />
									</div>

									<div class="flex items-center justify-between rounded border bg-background/50 p-2">
										<div>
											<p class="font-medium text-foreground">Custom ULA Local Prefix</p>
											<p class="text-muted-foreground">Stable fd00:: link for local LAN.</p>
										</div>
										<Switch bind:checked={ra_ula_enabled} />
									</div>
								</div>

								{#if ra_ula_enabled}
									<div class="space-y-1 pt-1">
										<Label for="ra_prefix" class="text-xs">ULA Prefix (RFC 4193)</Label>
										<Input id="ra_prefix" class="h-8 text-xs font-mono" bind:value={ra_ula_prefix} placeholder="fd97:f00d:cafe:3731::/64" />
									</div>
								{/if}
							{/if}
						</div>

						<!-- Upstream DNS Resolvers -->
						<div class="rounded-lg border bg-muted/20 p-3.5 space-y-2.5">
							<div class="flex items-center justify-between">
								<div>
									<h5 class="text-sm font-semibold text-foreground">Upstream DNS Resolvers</h5>
									<p class="text-xs text-muted-foreground">Secure upstream DNS forwarding servers for external domain queries.</p>
								</div>
								<Badge variant="outline">{dns_preset.toUpperCase()}</Badge>
							</div>

							<div class="grid grid-cols-2 gap-2 sm:grid-cols-4 pt-1">
								<button
									type="button"
									class="rounded-md border py-1.5 text-xs font-medium transition-colors {dns_preset === 'quad9' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
									onclick={() => (dns_preset = "quad9")}
								>
									Quad9 (Default)
								</button>
								<button
									type="button"
									class="rounded-md border py-1.5 text-xs font-medium transition-colors {dns_preset === 'cloudflare' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
									onclick={() => (dns_preset = "cloudflare")}
								>
									Cloudflare
								</button>
								<button
									type="button"
									class="rounded-md border py-1.5 text-xs font-medium transition-colors {dns_preset === 'google' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
									onclick={() => (dns_preset = "google")}
								>
									Google
								</button>
								<button
									type="button"
									class="rounded-md border py-1.5 text-xs font-medium transition-colors {dns_preset === 'custom' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
									onclick={() => (dns_preset = "custom")}
								>
									Custom
								</button>
							</div>

							{#if dns_preset === "custom"}
								<div class="space-y-1 pt-1">
									<Label for="custom_dns" class="text-xs">Custom DNS Server IPs (Comma separated)</Label>
									<Input id="custom_dns" class="h-8 text-xs font-mono" bind:value={custom_dns_servers} placeholder="1.1.1.1, 8.8.8.8" />
								</div>
							{/if}
						</div>

						<div class="flex items-center justify-between rounded-lg border p-3">
							<div>
								<h5 class="text-sm font-medium text-foreground">Built-in DNS Adblocker</h5>
								<p class="text-xs text-muted-foreground">Block ads, trackers, and telemetry network-wide via Lanforge DNS.</p>
							</div>
							<Switch bind:checked={adblock_enabled} />
						</div>
					</Card.Content>
					<Card.Footer class="flex justify-between">
						<Button variant="outline" onclick={() => (step = 2)} class="gap-2">
							<ArrowLeftIcon class="h-4 w-4" />
							Back
						</Button>
						<Button onclick={handleNextStep3} class="gap-2">
							Review & Launch
							<ArrowRightIcon class="h-4 w-4" />
						</Button>
					</Card.Footer>

				{:else if step === 4}
					<Card.Header>
						<div class="flex items-center gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-400">
								<SparklesIcon class="h-5 w-5" />
							</div>
							<div>
								<Card.Title>Review & Launch</Card.Title>
								<Card.Description>Review your configuration summary before activating services.</Card.Description>
							</div>
						</div>
					</Card.Header>
					<Card.Content class="space-y-4">
						<div class="rounded-xl border bg-muted/30 p-4 space-y-2.5">
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">Administrator:</span>
								<span class="font-medium text-foreground">{admin_username}</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">Uplink Mode:</span>
								<span class="font-medium text-foreground">
									{wan_mode === 'pppoe' ? `Integrated PPPoE (${wan_iface}${pppoe_vlan ? ` VLAN ${pppoe_vlan}` : ''})` : `System-Managed Gateway (${system_gateway})`}
								</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">LAN Interface:</span>
								<span class="font-medium text-foreground">{lan_iface} ({lan_ip})</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">Subnet Mask:</span>
								<span class="font-medium text-foreground">{subnet_mask}</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">DHCPv4 Scope:</span>
								<span class="font-medium text-foreground">{dhcp_pool_start} – {dhcp_pool_end}</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">DHCP Default Gateway:</span>
								<span class="font-medium text-foreground">{dhcp_router}</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">IPv6 RA SLAAC:</span>
								<span class="font-medium text-foreground">
									{#if ra_enabled}
										Enabled ({ra_auto_gua ? 'Auto-GUA' : ''}{ra_auto_gua && ra_ula_enabled ? ' + ' : ''}{ra_ula_enabled ? 'ULA' : ''})
									{:else}
										Disabled
									{/if}
								</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">Local Domain:</span>
								<span class="font-medium text-foreground">.{domain_name}</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">Upstream DNS:</span>
								<span class="font-medium text-foreground">{getUpstreamDnsList().join(", ")}</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">DNS Adblocker:</span>
								<span class="font-medium text-foreground">{adblock_enabled ? 'Enabled' : 'Disabled'}</span>
							</div>
							<div class="flex justify-between text-sm">
								<span class="text-muted-foreground">Storage Engine:</span>
								<span class="font-medium text-emerald-400">redb (embedded pure-Rust)</span>
							</div>
						</div>
					</Card.Content>
					<Card.Footer class="flex justify-between">
						<Button variant="outline" onclick={() => (step = 3)} class="gap-2" disabled={submitting}>
							<ArrowLeftIcon class="h-4 w-4" />
							Back
						</Button>
						<Button onclick={handleLaunch} class="gap-2 bg-emerald-600 hover:bg-emerald-500 text-white" disabled={submitting}>
							{#if submitting}
								Activating Lanforge...
							{:else}
								Launch Lanforge 🚀
							{/if}
						</Button>
					</Card.Footer>
				{/if}
			</Card.Root>
		{/if}
	</div>
</div>
