<script lang="ts">
	import * as Empty from "$lib/components/ui/empty";
	import { Button } from "$lib/components/ui/button";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import ZoneCard from "./ZoneCard.svelte";
	import ZoneNewDialog from "./ZoneNewDialog.svelte";
	import type { FirewallZone, NetworkInterfaceInfo } from "$lib/api/types";

	interface Props {
		zones: FirewallZone[];
		highlightedZone: string | null;
		availableInterfaces?: NetworkInterfaceInfo[];
		activeWan?: string | null;
		onUpdate: (zones: FirewallZone[]) => void;
	}

	let {
		zones,
		highlightedZone,
		availableInterfaces = [],
		activeWan = null,
		onUpdate,
	}: Props = $props();

	let newDialogOpen = $state(false);

	function handleZoneUpdate(index: number, updated: FirewallZone) {
		const next = [...zones];
		next[index] = updated;
		onUpdate(next);
	}

	function handleZoneDelete(index: number) {
		onUpdate(zones.filter((_, i) => i !== index));
	}

	function handleZoneAdd(zone: FirewallZone) {
		onUpdate([...zones, zone]);
		newDialogOpen = false;
	}
</script>

<div class="flex flex-col gap-4">
	<!-- Actions row -->
	<div class="flex items-center justify-between">
		<div>
			<div class="flex items-center gap-2">
				<h3 class="text-sm font-semibold tracking-tight text-foreground">Network Zones</h3>
				<HelpPopover
					title="Network Zones Guide"
					description="How zones organize physical and virtual network interfaces into security domains."
				>
					<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
						<p>
							<strong class="text-foreground">What is a Zone?</strong> A logical grouping of network interfaces that share the same firewall policy (Accept, Drop, or Reject).
						</p>
						<p>
							<strong class="text-foreground">External (WAN):</strong> Your uplink to the Internet. Usually set to Input Policy <em>Drop</em> with <em>Masquerade (NAT)</em> and <em>MSS Clamping</em> turned ON.
						</p>
						<p>
							<strong class="text-foreground">Internal (LAN):</strong> Your trusted local network (e.g. eth0, lan0, br0).
						</p>
						<p>
							<strong class="text-foreground">Trusted / Containers:</strong> For VPNs (tailscale0, wg0) and containers (podman*).
						</p>
					</div>
				</HelpPopover>
			</div>
			<p class="text-xs text-muted-foreground">Configure interfaces, traffic policies, and rules per zone.</p>
		</div>
		<Button size="sm" onclick={() => (newDialogOpen = true)}>
			<PlusIcon data-icon="inline-start" />
			New Zone
		</Button>
	</div>

	<!-- Zone cards grid -->
	{#if zones.length === 0}
		<Empty.Root class="rounded-xl border border-dashed py-12">
			<Empty.Media>
				<ShieldIcon class="size-10 text-muted-foreground" />
			</Empty.Media>
			<Empty.Header>
				<Empty.Title>No zones configured</Empty.Title>
				<Empty.Description>
					Add network zones to segment traffic and define filtering policies.
				</Empty.Description>
			</Empty.Header>
			<Empty.Content>
				<Button size="sm" onclick={() => (newDialogOpen = true)}>
					<PlusIcon data-icon="inline-start" />
					New Zone
				</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		<div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
			{#each zones as zone, index (zone.name)}
				<ZoneCard
					{zone}
					highlighted={zone.name === highlightedZone}
					{availableInterfaces}
					{activeWan}
					onUpdate={(updated) => handleZoneUpdate(index, updated)}
					onDelete={() => handleZoneDelete(index)}
				/>
			{/each}
		</div>
	{/if}

	<!-- New Zone Dialog with templates -->
	<ZoneNewDialog
		bind:open={newDialogOpen}
		onAdd={handleZoneAdd}
		onClose={() => (newDialogOpen = false)}
	/>
</div>
