<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Select from "$lib/components/ui/select";
	import * as Collapsible from "$lib/components/ui/collapsible";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ZapOffIcon from "@lucide/svelte/icons/zap-off";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ChevronUpIcon from "@lucide/svelte/icons/chevron-up";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import XIcon from "@lucide/svelte/icons/x";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";

	import type { NetworkInterfaceInfo } from "$lib/api/types";

	let {
		enabled = $bindable(false),
		interfaces = $bindable<string[]>([]),
		cpuMask = $bindable("auto"),
		rxRing = $bindable("auto"),
		txRing = $bindable("auto"),
		disableEee = $bindable(true),
		udpGroForwarding = $bindable(true),
		rpsFlowEntries = $bindable(32768),
		rpsFlowCnt = $bindable(4096),
		availableInterfaces = [],
		effectiveCpuMask = "",
		detectedLan = null,
		detectedWan = null,
	}: {
		enabled?: boolean;
		interfaces?: string[];
		cpuMask?: string;
		rxRing?: string;
		txRing?: string;
		disableEee?: boolean;
		udpGroForwarding?: boolean;
		rpsFlowEntries?: number;
		rpsFlowCnt?: number;
		availableInterfaces?: NetworkInterfaceInfo[];
		effectiveCpuMask?: string;
		detectedLan?: string | null;
		detectedWan?: string | null;
	} = $props();

	let advancedOpen = $state(false);
	let customIfaceInput = $state("");
	let selectedToAdd = $state("");

	function addInterface(name: string) {
		const trimmed = name.trim();
		if (!trimmed || interfaces.includes(trimmed)) return;
		interfaces = [...interfaces, trimmed];
		customIfaceInput = "";
		selectedToAdd = "";
	}

	function removeInterface(name: string) {
		interfaces = interfaces.filter((i) => i !== name);
	}

	function autoDetectInterfaces() {
		const detected: string[] = [];
		if (detectedLan && !detected.includes(detectedLan)) detected.push(detectedLan);
		if (detectedWan && !detected.includes(detectedWan)) detected.push(detectedWan);
		if (detected.length === 0) {
			eligibleInterfaces.slice(0, 2).forEach((i) => detected.push(i.name));
		}
		interfaces = detected;
	}

	// Filter interfaces: exclude virtual ifb, teql, and point-to-point ppp devices from hardware tuning
	const eligibleInterfaces = $derived(
		availableInterfaces.filter(
			(i) => !i.name.startsWith("ifb") && !i.name.startsWith("teql") && !i.name.startsWith("ppp")
		)
	);

	// Interfaces available to add that are not already in the list
	const unselectedInterfaces = $derived(
		eligibleInterfaces.filter((i) => !interfaces.includes(i.name))
	);
</script>

<div class="flex flex-col gap-6">
	<!-- Master Enable Switch Card -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<Card.Title class="text-base font-semibold">Hardware & NIC Optimization</Card.Title>
					<HelpPopover
						title="Kernel-level Network Optimization"
						description="Configures CPU packet distribution and interface hardware buffers directly through sysfs and ethtool."
					>
						<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
							<p>
								<strong class="text-foreground">RPS & RFS:</strong> Directs incoming packet processing across multiple CPU cores rather than bottling on core 0.
							</p>
							<p>
								<strong class="text-foreground">Ring Buffers:</strong> Sets reception and transmission DMA buffers to the hardware maximum to absorb sudden packet bursts.
							</p>
							<p>
								<strong class="text-foreground">Disable EEE:</strong> Turns off IEEE 802.3az Energy Efficient Ethernet to eliminate micro-sleep latency and link drops.
							</p>
						</div>
					</HelpPopover>
				</div>
				<Badge variant={enabled ? "default" : "secondary"} class="text-xs">
					{enabled ? "Enabled" : "Disabled"}
				</Badge>
			</div>
			<Card.Description class="text-xs">
				Low-level kernel tuning to maximize router packet forwarding throughput and minimize packet jitter.
			</Card.Description>
		</Card.Header>
		<Card.Content class="p-4 flex flex-col gap-5">
			<div class="flex items-center justify-between rounded-xl border p-3.5 bg-muted/20">
				<div class="flex flex-col gap-0.5">
					<Label class="text-xs font-semibold">Enable NIC Hardware Tuning</Label>
					<p class="text-[11px] text-muted-foreground">
						When enabled, Lanforge configures RPS, RFS, max ring buffers, and disables EEE on target interfaces.
					</p>
				</div>
				<Switch
					bind:checked={enabled}
					aria-label="Enable NIC Hardware Tuning"
				/>
			</div>
		</Card.Content>
	</Card.Root>

	{#if enabled}
		<!-- Target Interfaces Configuration -->
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<Card.Title class="text-base font-semibold">Target Network Interfaces</Card.Title>
						<HelpPopover
							title="Target Interfaces Selection"
							description="Physical Ethernet ports that receive hardware tuning."
						>
							<p class="text-xs text-muted-foreground leading-relaxed">
								If the list is left empty, Lanforge automatically optimizes your active LAN and WAN ports. You can also explicitly specify which interfaces to tune.
							</p>
						</HelpPopover>
					</div>
					<Button
						variant="outline"
						size="sm"
						onclick={autoDetectInterfaces}
						class="h-7 text-xs gap-1.5"
					>
						<SparklesIcon class="size-3 text-primary" />
						<span>Auto-detect LAN & WAN</span>
					</Button>
				</div>
				<Card.Description class="text-xs">
					Select which physical network interfaces will receive RPS CPU affinity and maximum ring buffer sizes.
				</Card.Description>
			</Card.Header>
			<Card.Content class="p-4 flex flex-col gap-4">
				<!-- Active interfaces tags -->
				<div class="flex flex-wrap items-center gap-2">
					{#if interfaces.length === 0}
						<Badge variant="outline" class="text-xs border-dashed text-muted-foreground py-1 px-2.5">
							Default: Auto-detecting LAN ({detectedLan ?? "auto"}) and WAN ({detectedWan ?? "auto"})
						</Badge>
					{/if}
					{#each interfaces as iface (iface)}
						<Badge variant="secondary" class="gap-1.5 py-1 px-2.5 text-xs font-mono">
							<span>{iface}</span>
							<button
								type="button"
								onclick={() => removeInterface(iface)}
								class="hover:text-destructive transition-colors ml-0.5 cursor-pointer"
								aria-label={`Remove ${iface}`}
							>
								<XIcon class="size-3" />
							</button>
						</Badge>
					{/each}
				</div>

				<!-- Interface selector using shadcn Select -->
				<div class="flex flex-col sm:flex-row items-start sm:items-center gap-2 pt-1">
					<div class="w-full sm:w-64">
						<Select.Root
							type="single"
							value={selectedToAdd}
							onValueChange={(val) => {
								if (val) addInterface(val);
							}}
						>
							<Select.Trigger class="h-9 text-xs font-mono w-full">
								{selectedToAdd || "Add detected interface..."}
							</Select.Trigger>
							<Select.Content>
								{#if unselectedInterfaces.length === 0}
									<div class="p-2 text-xs text-muted-foreground text-center">
										All detected interfaces added
									</div>
								{:else}
									{#each unselectedInterfaces as iface (iface.name)}
										<Select.Item value={iface.name} class="text-xs font-mono">
											<div class="flex items-center justify-between w-full gap-3">
												<span class="font-medium">{iface.name}</span>
												<span class="text-[10px] text-muted-foreground">{iface.bus_type}</span>
											</div>
										</Select.Item>
									{/each}
								{/if}
							</Select.Content>
						</Select.Root>
					</div>

					<div class="flex items-center gap-1.5 w-full sm:w-auto">
						<Input
							type="text"
							placeholder="Or manual interface name..."
							bind:value={customIfaceInput}
							onkeydown={(e) => {
								if (e.key === "Enter") {
									e.preventDefault();
									addInterface(customIfaceInput);
								}
							}}
							class="h-9 text-xs font-mono flex-1 sm:w-48"
						/>
						<Button
							variant="outline"
							size="sm"
							onclick={() => addInterface(customIfaceInput)}
							disabled={!customIfaceInput.trim()}
							class="h-9 px-3 shrink-0"
						>
							<PlusIcon class="size-3.5 mr-1" />
							Add
						</Button>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Core Parameters Grid -->
		<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
			<!-- CPU Mask / RPS Affinity -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-1.5">
							<Card.Title class="text-base font-semibold">RPS CPU Affinity Mask</Card.Title>
							<InfoPopover
								title="RPS CPU Mask"
								description="Hexadecimal bitmask defining which CPU cores handle network interrupts."
							>
								<div class="flex flex-col gap-1 text-xs text-muted-foreground">
									<p><strong>auto:</strong> Reads online CPUs and activates all available CPU threads.</p>
									<p><strong>Example:</strong> An 8-thread CPU uses mask <code>ff</code> (binary 11111111).</p>
								</div>
							</InfoPopover>
						</div>
						{#if effectiveCpuMask}
							<Badge variant="outline" class="font-mono text-[10px]">
								Effective: 0x{effectiveCpuMask}
							</Badge>
						{/if}
					</div>
					<Card.Description class="text-xs">
						Sets the CPU core mask written to <code>/sys/class/net/&lt;iface&gt;/queues/rx-*/rps_cpus</code>.
					</Card.Description>
				</Card.Header>
				<Card.Content class="p-4 flex flex-col gap-2">
					<Input
						type="text"
						bind:value={cpuMask}
						placeholder="auto"
						class="font-mono text-xs h-9"
					/>
					<span class="text-[11px] text-muted-foreground">
						Use <code>auto</code> for automatic core detection, or provide a hex mask (e.g. <code>ff</code>).
					</span>
				</Card.Content>
			</Card.Root>

			<!-- Ring Buffers (Rx / Tx) -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex items-center gap-1.5">
						<Card.Title class="text-base font-semibold">NIC Ring Buffers (Rx / Tx)</Card.Title>
						<InfoPopover
							title="Ethtool Ring Buffers"
							description="Hardware DMA ring descriptor count for the network controller."
						>
							<p class="text-xs text-muted-foreground leading-relaxed">
								<strong>auto:</strong> Queries driver maximums via ethtool and expands queues to the highest safe capacity (e.g. 1024 or 4096 buffers).
							</p>
						</InfoPopover>
					</div>
					<Card.Description class="text-xs">
						Buffer size for packet transmission and reception to eliminate interface overruns.
					</Card.Description>
				</Card.Header>
				<Card.Content class="p-4 flex flex-col gap-3">
					<div class="grid grid-cols-2 gap-3">
						<div class="flex flex-col gap-1">
							<Label for="rx-ring" class="text-xs text-muted-foreground">RX Ring</Label>
							<Input
								id="rx-ring"
								type="text"
								bind:value={rxRing}
								placeholder="auto"
								class="font-mono text-xs h-9"
							/>
						</div>
						<div class="flex flex-col gap-1">
							<Label for="tx-ring" class="text-xs text-muted-foreground">TX Ring</Label>
							<Input
								id="tx-ring"
								type="text"
								bind:value={txRing}
								placeholder="auto"
								class="font-mono text-xs h-9"
							/>
						</div>
					</div>
					<span class="text-[11px] text-muted-foreground">
						Set to <code>auto</code> to apply maximum driver limits, or enter specific buffer sizes.
					</span>
				</Card.Content>
			</Card.Root>
		</div>

		<!-- Energy Efficiency & UDP GRO Card -->
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<Card.Title class="text-base font-semibold">Latency & Forwarding Offloads</Card.Title>
				<Card.Description class="text-xs">
					Toggle hardware power-saving and UDP packet aggregation behavior.
				</Card.Description>
			</Card.Header>
			<Card.Content class="p-4 flex flex-col gap-4">
				<!-- Disable EEE -->
				<div class="flex items-center justify-between rounded-xl border p-3.5 bg-muted/20">
					<div class="flex items-start gap-3">
						<div class="flex size-9 items-center justify-center rounded-lg bg-amber-500/10 text-amber-500 shrink-0 mt-0.5">
							<ZapOffIcon class="size-4" />
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-xs font-semibold text-foreground">Disable Energy Efficient Ethernet (EEE)</span>
							<p class="text-[11px] text-muted-foreground leading-relaxed max-w-xl">
								Disables IEEE 802.3az low-power idle states on Ethernet PHYs, preventing link micro-sleeps and latency spikes during bursts.
							</p>
						</div>
					</div>
					<Switch
						bind:checked={disableEee}
						aria-label="Disable Energy Efficient Ethernet"
					/>
				</div>

				<!-- UDP GRO Forwarding -->
				<div class="flex items-center justify-between rounded-xl border p-3.5 bg-muted/20">
					<div class="flex items-start gap-3">
						<div class="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-500 shrink-0 mt-0.5">
							<ActivityIcon class="size-4" />
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-xs font-semibold text-foreground">UDP GRO Forwarding Offload</span>
							<p class="text-[11px] text-muted-foreground leading-relaxed max-w-xl">
								Enables <code>net.ipv4.udp_gro_forwarding=1</code>, aggregating consecutive UDP packets before routing to significantly increase WireGuard, Tailscale, and QUIC throughput.
							</p>
						</div>
					</div>
					<Switch
						bind:checked={udpGroForwarding}
						aria-label="UDP GRO Forwarding"
					/>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Advanced Collapsible Parameters -->
		<Collapsible.Root bind:open={advancedOpen} class="flex flex-col gap-2">
			<Card.Root>
				<Card.Header class="p-4 flex flex-row items-center justify-between">
					<div class="flex items-center gap-2">
						<SlidersIcon class="size-4 text-muted-foreground" />
						<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
							Advanced Kernel Flow Tables (RFS)
						</span>
					</div>
					<Button
						variant="ghost"
						size="sm"
						onclick={() => (advancedOpen = !advancedOpen)}
						class="h-8 gap-1 text-xs text-muted-foreground hover:text-foreground"
					>
						<span>{advancedOpen ? "Collapse" : "Expand"}</span>
						{#if advancedOpen}
							<ChevronUpIcon class="size-3.5" />
						{:else}
							<ChevronDownIcon class="size-3.5" />
						{/if}
					</Button>
				</Card.Header>

				<Collapsible.Content class="px-4 pb-4 border-t pt-4">
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
						<div class="flex flex-col gap-1.5">
							<Label for="rps-entries" class="text-xs font-semibold text-foreground">
								Global Table Entries (rps_sock_flow_entries)
							</Label>
							<Input
								id="rps-entries"
								type="number"
								step="1024"
								bind:value={rpsFlowEntries}
								class="h-9 text-xs"
							/>
							<span class="text-[11px] text-muted-foreground">
								Default: 32768 entries. Global kernel flow table size.
							</span>
						</div>

						<div class="flex flex-col gap-1.5">
							<Label for="rps-cnt" class="text-xs font-semibold text-foreground">
								Per-Queue Table Entries (rps_flow_cnt)
							</Label>
							<Input
								id="rps-cnt"
								type="number"
								step="512"
								bind:value={rpsFlowCnt}
								class="h-9 text-xs"
							/>
							<span class="text-[11px] text-muted-foreground">
								Default: 4096 entries per receive queue.
							</span>
						</div>
					</div>
				</Collapsible.Content>
			</Card.Root>
		</Collapsible.Root>
	{/if}
</div>
