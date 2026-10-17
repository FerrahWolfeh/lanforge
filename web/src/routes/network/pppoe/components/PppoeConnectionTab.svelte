<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Select from "$lib/components/ui/select";
	import { Badge } from "$lib/components/ui/badge";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import EyeOffIcon from "@lucide/svelte/icons/eye-off";
	import RouterIcon from "@lucide/svelte/icons/router";

	import type {
		PppoeAuthMethod,
		NetworkInterfaceInfo,
	} from "$lib/api/types";

	let {
		formEnabled = $bindable(false),
		formWanIface = $bindable("eth1"),
		formAuth = $bindable("chap_md5" as PppoeAuthMethod),
		formUsername = $bindable(""),
		formPassword = $bindable(""),
		formServiceName = $bindable(""),
		formAcName = $bindable(""),
		interfaceOptions = [],
		formProbeEnabled = $bindable(false),
		formProbeTargetIp = $bindable("192.168.1.1"),
		formProbeSenderIp = $bindable(""),
		formProbeIface = $bindable(""),
		formProbeTimeoutMs = $bindable(1000),
		formProbePollIntervalSecs = $bindable(2),
		formProbeMaxWaitSecs = $bindable(10),
	}: {
		formEnabled?: boolean;
		formWanIface?: string;
		formAuth?: PppoeAuthMethod;
		formUsername?: string;
		formPassword?: string;
		formServiceName?: string;
		formAcName?: string;
		interfaceOptions?: NetworkInterfaceInfo[];
		formProbeEnabled?: boolean;
		formProbeTargetIp?: string;
		formProbeSenderIp?: string;
		formProbeIface?: string;
		formProbeTimeoutMs?: number;
		formProbePollIntervalSecs?: number;
		formProbeMaxWaitSecs?: number;
	} = $props();

	let showPassword = $state(false);

	function formatAuthMethod(auth?: string): string {
		switch (auth) {
			case "chap_md5": return "CHAP-MD5 (Recommended)";
			case "pap": return "PAP (Plaintext)";
			case "none": return "None (Unauthenticated)";
			default: return auth || "CHAP-MD5";
		}
	}
</script>

<div class="flex flex-col gap-6">
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<Card.Title class="text-base font-semibold">ISP Uplink & Authentication</Card.Title>
			<Card.Description class="text-xs">
				Configure your WAN physical port, subscriber login credentials, and authentication protocol.
			</Card.Description>
		</Card.Header>
		<Card.Content class="p-4 flex flex-col gap-5">
			<!-- Service Enable Switch -->
			<div class="flex items-center justify-between rounded-xl border p-3.5 bg-muted/20">
				<div class="flex flex-col gap-0.5">
					<Label class="text-xs font-semibold">Enable PPPoE Client Service</Label>
					<p class="text-[11px] text-muted-foreground">
						When enabled, Lanforge actively negotiates and maintains the PPPoE session on the physical WAN interface.
					</p>
				</div>
				<Switch bind:checked={formEnabled} />
			</div>

			<div class="grid gap-4 sm:grid-cols-2">
				<!-- WAN Interface Select -->
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs font-semibold">Physical WAN Interface</Label>
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
													<span class="size-1.5 rounded-full bg-emerald-500" title="Connected"></span>
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
							placeholder="e.g. eth1, end1"
							class="h-9 font-mono text-xs"
						/>
					{/if}
					<p class="text-[11px] text-muted-foreground">
						Port connected to your fiber ONT, modem, or upstream switch.
					</p>
				</div>

				<!-- Authentication Protocol Select -->
				<div class="flex flex-col gap-1.5">
					<Label class="text-xs font-semibold">Authentication Protocol</Label>
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
						Most fiber and broadband ISPs require CHAP-MD5 authentication.
					</p>
				</div>

				<!-- PPPoE Username -->
				<div class="flex flex-col gap-1.5">
					<Label for="username" class="text-xs font-semibold">PPPoE Username</Label>
					<Input
						id="username"
						bind:value={formUsername}
						placeholder="cliente@provedor.com.br"
						class="h-9 text-xs font-mono"
					/>
				</div>

				<!-- PPPoE Password -->
				<div class="flex flex-col gap-1.5">
					<Label for="password" class="text-xs font-semibold">PPPoE Password</Label>
					<div class="relative">
						<Input
							id="password"
							type={showPassword ? "text" : "password"}
							bind:value={formPassword}
							placeholder="••••••••"
							class="h-9 text-xs font-mono pr-10"
						/>
						<button
							type="button"
							class="absolute right-3 top-2.5 text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
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

				<!-- Service Name -->
				<div class="flex flex-col gap-1.5">
					<Label for="service_name" class="text-xs font-semibold">Service Name (Optional)</Label>
					<Input
						id="service_name"
						bind:value={formServiceName}
						placeholder="Leave empty for any"
						class="h-9 text-xs"
					/>
					<p class="text-[11px] text-muted-foreground">
						Specifies the requested ISP service tag. Leave empty to accept any.
					</p>
				</div>

				<!-- Access Concentrator Name -->
				<div class="flex flex-col gap-1.5">
					<Label for="ac_name" class="text-xs font-semibold">Access Concentrator Name (Optional)</Label>
					<Input
						id="ac_name"
						bind:value={formAcName}
						placeholder="Leave empty for any"
						class="h-9 text-xs"
					/>
					<p class="text-[11px] text-muted-foreground">
						Filter discovery to a specific BRAS hostname. Leave empty for fastest response.
					</p>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Underlay ONT & Modem Probe (Layer 2 ARP) -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<Card.Title class="text-base font-semibold flex items-center gap-2">
				<RouterIcon class="size-4 text-primary" />
				Underlay ONT & Modem Probe (Layer 2 ARP)
			</Card.Title>
			<Card.Description class="text-xs">
				Optional pre-flight check. Probes your GPON ONT, SFP stick, or bridged modem via ARP before PPPoE discovery starts.
			</Card.Description>
		</Card.Header>
		<Card.Content class="p-4 flex flex-col gap-5">
			<!-- Probe Enable Switch -->
			<div class="flex items-center justify-between rounded-xl border p-3.5 bg-muted/20">
				<div class="flex flex-col gap-0.5">
					<Label class="text-xs font-semibold">Enable Underlay Terminal Probe</Label>
					<p class="text-[11px] text-muted-foreground">
						Verifies that the underlay hardware (optical ONT or bridge modem) has finished booting before transmitting PPPoE discovery packets.
					</p>
				</div>
				<Switch bind:checked={formProbeEnabled} />
			</div>

			{#if formProbeEnabled}
				<div class="grid gap-4 sm:grid-cols-2 pt-2 border-t border-border/40">
					<!-- Target Management IP -->
					<div class="flex flex-col gap-1.5">
						<Label for="probe_target_ip" class="text-xs font-semibold">ONT / Modem Management IPv4</Label>
						<Input
							id="probe_target_ip"
							bind:value={formProbeTargetIp}
							placeholder="192.168.1.1"
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Target IPv4 address of your ONT or modem (typically 192.168.1.1 or 192.168.100.1).
						</p>
					</div>

					<!-- Probe Interface -->
					<div class="flex flex-col gap-1.5">
						<Label class="text-xs font-semibold">Probe Interface</Label>
						{#if interfaceOptions.length > 0}
							<Select.Root
								type="single"
								value={formProbeIface || "auto"}
								onValueChange={(val) => {
									formProbeIface = val === "auto" ? "" : (val ?? "");
								}}
							>
								<Select.Trigger class="h-9 text-xs font-mono">
									{formProbeIface ? formProbeIface : "Auto (Untagged parent of WAN)"}
								</Select.Trigger>
								<Select.Content>
									<Select.Item value="auto" class="text-xs">
										<span class="font-sans text-muted-foreground">Auto (Untagged parent of WAN)</span>
									</Select.Item>
									{#each interfaceOptions as iface (iface.name)}
										<Select.Item value={iface.name} class="text-xs">
											<div class="flex items-center justify-between w-full gap-3">
												<span class="font-mono font-medium">{iface.name}</span>
												{#if iface.is_physical}
													<Badge variant="secondary" class="text-[9px] px-1 py-0 font-normal">Physical</Badge>
												{/if}
											</div>
										</Select.Item>
									{/each}
								</Select.Content>
							</Select.Root>
						{:else}
							<Input
								id="probe_iface"
								bind:value={formProbeIface}
								placeholder="Auto (parent of WAN)"
								class="h-9 font-mono text-xs"
							/>
						{/if}
						<p class="text-[11px] text-muted-foreground">
							Network interface for sending ARP probes. Defaults to untagged parent if WAN uses a VLAN.
						</p>
					</div>

					<!-- Soft-Gate Max Wait Deadline -->
					<div class="flex flex-col gap-1.5">
						<Label for="probe_max_wait" class="text-xs font-semibold">Max Wait Deadline (seconds)</Label>
						<Input
							id="probe_max_wait"
							type="number"
							min="1"
							max="60"
							bind:value={formProbeMaxWaitSecs}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Soft-gate deadline (default 10s). If the ONT does not reply within this limit, PPPoE dials anyway.
						</p>
					</div>

					<!-- Poll Interval -->
					<div class="flex flex-col gap-1.5">
						<Label for="probe_poll_interval" class="text-xs font-semibold">Poll Interval (seconds)</Label>
						<Input
							id="probe_poll_interval"
							type="number"
							min="1"
							max="30"
							bind:value={formProbePollIntervalSecs}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Frequency of ARP requests while waiting for the ONT to answer (default 2s).
						</p>
					</div>

					<!-- Per-probe Reply Timeout -->
					<div class="flex flex-col gap-1.5">
						<Label for="probe_timeout" class="text-xs font-semibold">Probe Reply Timeout (ms)</Label>
						<Input
							id="probe_timeout"
							type="number"
							min="100"
							max="10000"
							step="100"
							bind:value={formProbeTimeoutMs}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Per-probe ARP response timeout (default 1000 ms).
						</p>
					</div>

					<!-- Custom Sender IP -->
					<div class="flex flex-col gap-1.5">
						<Label for="probe_sender_ip" class="text-xs font-semibold">Sender IPv4 (Optional)</Label>
						<Input
							id="probe_sender_ip"
							bind:value={formProbeSenderIp}
							placeholder="0.0.0.0 (RFC 5227 Probe)"
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Source IP inside the ARP frame. Leave empty for standard 0.0.0.0 probe request.
						</p>
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
