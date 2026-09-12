<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import InfoPopover from "$lib/components/InfoPopover.svelte";

	import type { PppoeDataplane } from "$lib/api/types";

	let {
		formDataplane = $bindable("kernel" as PppoeDataplane),
		formNftEnabled = $bindable(true),
		formNftFlowOffload = $bindable(true),
		formNftMssClamping = $bindable(true),
		formNftBypassDns = $bindable(true),
		formNftBypassVowifi = $bindable(true),
		formNftMasquerade = $bindable(true),
		onSelectEbpf = () => {},
	}: {
		formDataplane?: PppoeDataplane;
		formNftEnabled?: boolean;
		formNftFlowOffload?: boolean;
		formNftMssClamping?: boolean;
		formNftBypassDns?: boolean;
		formNftBypassVowifi?: boolean;
		formNftMasquerade?: boolean;
		onSelectEbpf?: () => void;
	} = $props();
</script>

<div class="flex flex-col gap-6">
	<!-- Data Plane Architecture Card -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<Card.Title class="text-base font-semibold flex items-center gap-2">
				<ZapIcon class="size-4 text-primary" />
				Data Plane Architecture Selection
			</Card.Title>
			<Card.Description class="text-xs">
				Choose how PPPoE packets are encapsulated, processed, and routed through the network subsystem.
			</Card.Description>
		</Card.Header>
		<Card.Content class="p-4">
			<div class="grid gap-4 md:grid-cols-2">
				<!-- Linux Kernel Mode Option -->
				<button
					type="button"
					class={[
						"relative text-left rounded-xl border p-4 transition-all duration-200 cursor-pointer flex flex-col gap-2",
						formDataplane === "kernel"
							? "border-primary bg-primary/5 shadow-sm"
							: "border-border/60 hover:bg-muted/10",
					].join(" ")}
					onclick={() => (formDataplane = "kernel")}
				>
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2 font-semibold text-sm">
							<CpuIcon class="size-4 text-blue-400" />
							<span>Standard Linux Kernel</span>
						</div>
						{#if formDataplane === "kernel"}
							<Badge variant="default" class="text-xs">Active Mode</Badge>
						{:else}
							<Badge variant="outline" class="text-xs">Recommended</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed">
						Uses kernel <code class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono">/dev/ppp</code> and <code class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono">ppp_generic</code> driver. Compatible with standard netfilter routing.
					</p>
					<div class="flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium mt-1">
						<CheckCircleIcon class="size-3.5" />
						Full support for Flowtable offload and PMTU Clamping
					</div>
				</button>

				<!-- eBPF Fast-Path Option -->
				<button
					type="button"
					class={[
						"relative text-left rounded-xl border p-4 transition-all duration-200 cursor-pointer flex flex-col gap-2",
						formDataplane === "ebpf"
							? "border-amber-500 bg-amber-500/5 shadow-sm"
							: "border-border/60 hover:bg-muted/10",
					].join(" ")}
					onclick={onSelectEbpf}
				>
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2 font-semibold text-sm text-amber-500">
							<ZapIcon class="size-4 text-amber-500" />
							<span>eBPF Fast-Path (Generic XDP + TC)</span>
						</div>
						{#if formDataplane === "ebpf"}
							<Badge variant="outline" class="border-amber-500 text-amber-500 text-xs">Active Experimental</Badge>
						{:else}
							<Badge variant="secondary" class="text-xs">Experimental</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed">
						Processes PPPoE framing using eBPF TC filters on the WAN interface, bypassing generic ppp driver layers.
					</p>
					<div class="flex items-center gap-1.5 text-[11px] text-amber-500 font-medium mt-1">
						<AlertTriangleIcon class="size-3.5" />
						Requires eBPF kernel support (Generic XDP SKB mode)
					</div>
				</button>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- nftables Tuning Card -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div>
					<Card.Title class="text-base font-semibold flex items-center gap-2">
						<ShieldIcon class="size-4 text-primary" />
						Kernel Router Performance & nftables Tuning
					</Card.Title>
					<Card.Description class="text-xs">
						Automatic router optimizations, TCP MSS clamping, Flowtable fast-path, and traffic bypass rules.
					</Card.Description>
				</div>
				<div class="flex items-center gap-2">
					<span class="text-xs font-medium text-muted-foreground hidden sm:inline">Manage nftables Rules</span>
					<Switch bind:checked={formNftEnabled} />
				</div>
			</div>
		</Card.Header>
		<Card.Content class={["p-4 flex flex-col gap-4", !formNftEnabled && "opacity-50 pointer-events-none"].filter(Boolean).join(" ")}>
			<div class="grid gap-3 sm:grid-cols-2">
				<!-- TCP MSS Clamping -->
				<div class="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/20">
					<div class="flex items-center gap-1.5 min-w-0">
						<Label class="text-xs font-semibold">TCP MSS Clamping</Label>
						<InfoPopover
							title="Automatic TCP MSS Clamping"
							text="Rewrites SYN packet MSS to match PMTU (typically 1452 bytes), preventing packet fragmentation and broken HTTPS connections."
						/>
					</div>
					<Switch bind:checked={formNftMssClamping} />
				</div>

				<!-- Flowtable Fast-Path -->
				<div class="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/20">
					<div class="flex items-center gap-1.5 min-w-0">
						<Label class="text-xs font-semibold">Flowtable Offload</Label>
						<InfoPopover
							title="Flowtable Offload"
							text="Bypasses Netfilter conntrack for established flows, reducing CPU usage on high-throughput links."
						/>
					</div>
					<Switch bind:checked={formNftFlowOffload} />
				</div>

				<!-- NAT Masquerading -->
				<div class="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/20">
					<div class="flex items-center gap-1.5 min-w-0">
						<Label class="text-xs font-semibold">NAT Masquerade</Label>
						<InfoPopover
							title="NAT Masquerade"
							text="Adds an outbound masquerade rule on the PPPoE interface for NAT routing."
						/>
					</div>
					<Switch bind:checked={formNftMasquerade} />
				</div>

				<!-- DNS Traffic Bypass -->
				<div class="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/20">
					<div class="flex items-center gap-1.5 min-w-0">
						<Label class="text-xs font-semibold">DNS Traffic Bypass</Label>
						<InfoPopover
							title="DNS Traffic Bypass"
							text="Exempts local DNS traffic from flowtable routing to allow local resolution and adblock inspection."
						/>
					</div>
					<Switch bind:checked={formNftBypassDns} />
				</div>

				<!-- VoWiFi / IPsec Bypass -->
				<div class="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/20 sm:col-span-2">
					<div class="flex items-center gap-1.5 min-w-0">
						<Label class="text-xs font-semibold">VoWiFi / IPsec Bypass (UDP 500/4500)</Label>
						<InfoPopover
							title="VoWiFi / IPsec Bypass"
							text="Exempts IKEv2 and NAT-T packets from MSS clamping and flowtable offload to prevent IPsec tunnel resets."
						/>
					</div>
					<Switch bind:checked={formNftBypassVowifi} />
				</div>
			</div>
		</Card.Content>
	</Card.Root>
</div>
