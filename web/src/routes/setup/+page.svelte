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
	import type { SetupStatusResponse, SetupPayload, SetupWanConfig } from "$lib/api/types";
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
	let system_gateway = $state("192.168.1.1");

	// Step 3: LAN Network & Presence
	let lan_iface = $state("");
	let lan_ip = $state("192.168.1.1");
	let dhcp_enabled = $state(true);
	let dhcp_pool_start = $state("192.168.1.100");
	let dhcp_pool_end = $state("192.168.1.240");
	let domain_name = $state("lan");
	let adblock_enabled = $state(true);

	onMount(async () => {
		try {
			const res = await getSetupStatus();
			setupStatus = res;

			if (res.detected_lan_iface) {
				lan_iface = res.detected_lan_iface;
			} else if (res.interfaces.length > 0) {
				lan_iface = res.interfaces[0].name;
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
		} catch (e) {
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
				mtu: 1492
			};
		} else {
			wanConfig = {
				mode: "system_gateway",
				gateway_ip: system_gateway
			};
		}

		const payload: SetupPayload = {
			admin_username,
			admin_password,
			lan_iface,
			lan_ip,
			domain_name,
			dhcp_enabled,
			dhcp_pool_start,
			dhcp_pool_end,
			adblock_enabled,
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
			<p class="mt-1 text-sm text-muted-foreground">Complete this quick setup to configure your router and local presence engine.</p>
		</div>

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
				<span class="text-xs font-medium {step >= 3 ? 'text-foreground' : 'text-muted-foreground'}">LAN</span>
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

							<div class="space-y-1.5">
								<Label for="pppoe_vlan">VLAN Tag (Optional)</Label>
								<Input id="pppoe_vlan" bind:value={pppoe_vlan} placeholder="e.g. 35 (leave empty if none)" />
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
						Next: LAN & Presence
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
							<Card.Title>LAN Network & Presence Settings</Card.Title>
							<Card.Description>Configure local subnet addressing and device presence discovery.</Card.Description>
						</div>
					</div>
				</Card.Header>
				<Card.Content class="space-y-4">
					<div class="space-y-1.5">
						<Label for="lan_iface">LAN Interface (Local Network)</Label>
						<select id="lan_iface" class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background" bind:value={lan_iface}>
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
							<Label for="lan_ip">Router / LAN IP</Label>
							<Input id="lan_ip" bind:value={lan_ip} placeholder="192.168.1.1" />
						</div>
						<div class="space-y-1.5">
							<Label for="domain_name">Local Domain</Label>
							<Input id="domain_name" bind:value={domain_name} placeholder="lan" />
						</div>
					</div>

					<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
						<div class="space-y-1.5">
							<Label for="pool_start">DHCP Pool Start</Label>
							<Input id="pool_start" bind:value={dhcp_pool_start} placeholder="192.168.1.100" />
						</div>
						<div class="space-y-1.5">
							<Label for="pool_end">DHCP Pool End</Label>
							<Input id="pool_end" bind:value={dhcp_pool_end} placeholder="192.168.1.240" />
						</div>
					</div>

					<Separator class="my-2" />

					<div class="flex items-center justify-between rounded-lg border p-3">
						<div>
							<h5 class="text-sm font-medium text-foreground">Built-in DNS Adblocker</h5>
							<p class="text-xs text-muted-foreground">Block ads, trackers, and telemetry on the local network.</p>
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
					<div class="rounded-xl border bg-muted/30 p-4 space-y-3">
						<div class="flex justify-between text-sm">
							<span class="text-muted-foreground">Administrator:</span>
							<span class="font-medium text-foreground">{admin_username}</span>
						</div>
						<div class="flex justify-between text-sm">
							<span class="text-muted-foreground">Uplink Mode:</span>
							<span class="font-medium text-foreground">
								{wan_mode === 'pppoe' ? `Integrated PPPoE (${wan_iface})` : `System-Managed (Gateway ${system_gateway})`}
							</span>
						</div>
						<div class="flex justify-between text-sm">
							<span class="text-muted-foreground">LAN Interface:</span>
							<span class="font-medium text-foreground">{lan_iface} ({lan_ip}/24)</span>
						</div>
						<div class="flex justify-between text-sm">
							<span class="text-muted-foreground">DHCP Scope:</span>
							<span class="font-medium text-foreground">{dhcp_pool_start} – {dhcp_pool_end}</span>
						</div>
						<div class="flex justify-between text-sm">
							<span class="text-muted-foreground">Local Domain:</span>
							<span class="font-medium text-foreground">.{domain_name}</span>
						</div>
						<div class="flex justify-between text-sm">
							<span class="text-muted-foreground">DNS Adblocker:</span>
							<span class="font-medium text-foreground">{adblock_enabled ? 'Enabled' : 'Disabled'}</span>
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
	</div>
</div>
