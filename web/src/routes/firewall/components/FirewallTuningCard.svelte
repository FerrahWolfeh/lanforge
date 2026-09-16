<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import CheckIcon from "@lucide/svelte/icons/check";

	interface Props {
		flowOffload: boolean;
		onToggleFlowOffload: (val: boolean) => void;
	}

	let { flowOffload, onToggleFlowOffload }: Props = $props();
</script>

<div class="flex flex-col gap-4">
	<!-- Flowtable Acceleration Card -->
	<Card.Root class="p-5">
		<div class="flex items-start justify-between gap-4">
			<div class="flex items-start gap-3">
				<div class="flex size-10 items-center justify-center rounded-xl bg-amber-500/10 text-amber-500 shrink-0 mt-0.5">
					<ZapIcon class="size-5" />
				</div>
				<div class="flex flex-col gap-1">
					<div class="flex items-center gap-2">
						<h3 class="text-base font-semibold text-foreground">Kernel Flowtable Offload</h3>
						<HelpPopover
							title="Flowtable Dataplane Acceleration"
							description="Kernel fast-path for established network connection flows."
						>
							<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
								<p>
									<strong class="text-foreground">How it works:</strong> Once a TCP/UDP connection handshake is completed, subsequent packets are processed directly at the driver/NIC layer, skipping redundant iptables/nftables rules.
								</p>
								<p>
									<strong class="text-foreground">SBC Performance:</strong> Significantly lowers CPU utilization on Raspberry Pi and homelab SBCs during heavy gigabit traffic.
								</p>
								<p>
									<strong class="text-amber-600 dark:text-amber-400 font-semibold">When to disable:</strong> If you use CAKE SQM or bufferbloat traffic shapers, disable flow offload so all packets can be metered by your queues.
								</p>
							</div>
						</HelpPopover>
						<Badge variant={flowOffload ? "default" : "secondary"} class="text-[10px]">
							{flowOffload ? "Fast-Path Active" : "Disabled"}
						</Badge>
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed max-w-2xl">
						Bypasses standard routing lookups for established flows, processing packets at wire speed directly in the kernel dataplane.
					</p>
				</div>
			</div>

			<div class="flex items-center pt-1">
				<Switch
					checked={flowOffload}
					onCheckedChange={onToggleFlowOffload}
					aria-label="Kernel Flowtable Offload"
				/>
			</div>
		</div>
	</Card.Root>

	<!-- Kernel Dataplane Acceleration Features Grid -->
	<div class="grid grid-cols-1 md:grid-cols-3 gap-3">
		<!-- Feature 1: TCP MSS Clamping -->
		<Card.Root class="p-4">
			<div class="flex items-center justify-between mb-2">
				<div class="flex items-center gap-2 text-foreground font-semibold text-xs">
					<GaugeIcon class="size-4 text-primary" />
					<span>TCP MSS Clamping</span>
				</div>
				<Badge variant="outline" class="text-[10px] font-mono">1452 / 1432</Badge>
			</div>
			<p class="text-xs text-muted-foreground leading-relaxed">
				Automatically clamps TCP Maximum Segment Size on WAN and PPPoE interfaces to avoid packet fragmentation and MTU black holes.
			</p>
			<div class="mt-3 flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
				<CheckIcon class="size-3.5" />
				<span>Enforced in nftables mangle hook</span>
			</div>
		</Card.Root>

		<!-- Feature 2: Outbound Masquerade -->
		<Card.Root class="p-4">
			<div class="flex items-center justify-between mb-2">
				<div class="flex items-center gap-2 text-foreground font-semibold text-xs">
					<NetworkIcon class="size-4 text-primary" />
					<span>NAT Masquerade</span>
				</div>
				<Badge variant="outline" class="text-[10px] font-mono">Full Cone SNAT</Badge>
			</div>
			<p class="text-xs text-muted-foreground leading-relaxed">
				Rewrites source IPs for outbound Internet egress traffic across WAN, PPPoE interfaces, and dynamic public uplink addresses.
			</p>
			<div class="mt-3 flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
				<CheckIcon class="size-3.5" />
				<span>Postrouting NAT active</span>
			</div>
		</Card.Root>

		<!-- Feature 3: Protocol Bypasses -->
		<Card.Root class="p-4">
			<div class="flex items-center justify-between mb-2">
				<div class="flex items-center gap-2 text-foreground font-semibold text-xs">
					<ShieldCheckIcon class="size-4 text-primary" />
					<span>Fast-Path Bypasses</span>
				</div>
				<Badge variant="outline" class="text-[10px] font-mono">DNS & IPsec</Badge>
			</div>
			<p class="text-xs text-muted-foreground leading-relaxed">
				Guarantees router-local DNS (port 53) and Wi-Fi calling tunnels (VoWiFi / IPsec ESP) bypass offload tables to preserve state tracking.
			</p>
			<div class="mt-3 flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium">
				<CheckIcon class="size-3.5" />
				<span>Strict conntrack preservation</span>
			</div>
		</Card.Root>
	</div>
</div>
