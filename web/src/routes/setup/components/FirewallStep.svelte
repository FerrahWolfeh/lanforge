<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ArrowLeftIcon from "@lucide/svelte/icons/arrow-left";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import type { FirewallMode } from "$lib/api/types";

	let {
		firewallMode = $bindable("full"),
		firewallFlowOffload = $bindable(true),
		onback,
		onnext,
	}: {
		firewallMode: FirewallMode;
		firewallFlowOffload: boolean;
		onback: () => void;
		onnext: () => void;
	} = $props();
</script>

<Card.Header>
	<div class="flex items-center gap-3">
		<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<ShieldIcon class="h-5 w-5" />
		</div>
		<div>
			<Card.Title>Firewall & Network Security</Card.Title>
			<Card.Description>Choose how Lanforge manages packet filtering, NAT, and network offload.</Card.Description>
		</div>
	</div>
</Card.Header>
<Card.Content class="space-y-4">
	<div class="grid grid-cols-1 gap-3">
		<!-- Full Mode Card -->
		<button
			type="button"
			class="flex flex-col text-left rounded-xl border p-4 transition-all {firewallMode === 'full' ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border bg-card hover:bg-muted/40'}"
			onclick={() => (firewallMode = 'full')}
		>
			<div class="flex items-center justify-between w-full mb-1.5">
				<div class="flex items-center gap-2">
					<ShieldCheckIcon class="h-4 w-4 text-primary" />
					<span class="font-semibold text-sm text-foreground">Full Router (Standalone)</span>
				</div>
				<Badge variant={firewallMode === 'full' ? 'default' : 'secondary'} class="text-xs">Recommended</Badge>
			</div>
			<p class="text-xs text-muted-foreground leading-relaxed">
				Lanforge acts as the primary firewall router. Replaces system firewalls (firewalld/ufw) with dedicated nftables zones (WAN, LAN, DMZ), host access rules, NAT masquerading, and port forwarding.
			</p>
		</button>

		<!-- Minimal Mode Card -->
		<button
			type="button"
			class="flex flex-col text-left rounded-xl border p-4 transition-all {firewallMode === 'minimal' ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border bg-card hover:bg-muted/40'}"
			onclick={() => (firewallMode = 'minimal')}
		>
			<div class="flex items-center justify-between w-full mb-1.5">
				<div class="flex items-center gap-2">
					<LayersIcon class="h-4 w-4 text-primary" />
					<span class="font-semibold text-sm text-foreground">Minimal Helper (Coexistence)</span>
				</div>
				<Badge variant={firewallMode === 'minimal' ? 'default' : 'outline'} class="text-xs">firewalld / ufw</Badge>
			</div>
			<p class="text-xs text-muted-foreground leading-relaxed">
				Creates a non-interfering helper table with default accept. Manages PPPoE Flowtable hardware acceleration, TCP MSS clamping, and masquerade, while delegating general filtering to your existing system firewall.
			</p>
		</button>

		<!-- Disabled Mode Card -->
		<button
			type="button"
			class="flex flex-col text-left rounded-xl border p-4 transition-all {firewallMode === 'disabled' ? 'border-destructive bg-destructive/5 ring-1 ring-destructive' : 'border-border bg-card hover:bg-muted/40'}"
			onclick={() => (firewallMode = 'disabled')}
		>
			<div class="flex items-center justify-between w-full mb-1.5">
				<div class="flex items-center gap-2">
					<ShieldOffIcon class="h-4 w-4 text-muted-foreground" />
					<span class="font-semibold text-sm text-foreground">Disabled</span>
				</div>
				<Badge variant="outline" class="text-xs">Unmanaged</Badge>
			</div>
			<p class="text-xs text-muted-foreground leading-relaxed">
				Lanforge will not create or manage any nftables rules. Packet filtering and routing offload must be configured manually on the host operating system.
			</p>
		</button>
	</div>

	{#if firewallMode !== 'disabled'}
		<Separator class="my-2" />

		<div class="flex items-center justify-between rounded-lg border p-3">
			<div class="space-y-0.5 pr-4">
				<div class="flex items-center gap-2">
					<ZapIcon class="h-4 w-4 text-primary" />
					<h5 class="text-sm font-medium text-foreground">Flowtable Fast-Path Offload</h5>
				</div>
				<p class="text-xs text-muted-foreground">
					Accelerate established TCP and UDP forward flows directly in the kernel dataplane to reduce CPU overhead and achieve line-rate throughput.
				</p>
			</div>
			<Switch bind:checked={firewallFlowOffload} />
		</div>
	{/if}
</Card.Content>
<Card.Footer class="flex justify-between">
	<Button variant="outline" onclick={onback} class="gap-2">
		<ArrowLeftIcon class="h-4 w-4" />
		Back
	</Button>
	<Button onclick={onnext} class="gap-2">
		Next: Review & Launch
		<ArrowRightIcon class="h-4 w-4" />
	</Button>
</Card.Footer>
