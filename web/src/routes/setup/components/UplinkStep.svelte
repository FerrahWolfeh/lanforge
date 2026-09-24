<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Label } from "$lib/components/ui/label";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Separator } from "$lib/components/ui/separator";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ServerIcon from "@lucide/svelte/icons/server";
	import ArrowLeftIcon from "@lucide/svelte/icons/arrow-left";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import type { NetworkInterfaceInfo } from "$lib/api/types";

	let {
		wanMode = $bindable("system_gateway"),
		systemGateway = $bindable("192.168.1.1"),
		wanIface = $bindable(""),
		pppoeUsername = $bindable(""),
		pppoePassword = $bindable(""),
		pppoeVlan = $bindable(""),
		pppoeMtu = $bindable(1492),
		interfaces = [],
		onback,
		onnext,
	}: {
		wanMode: "system_gateway" | "pppoe";
		systemGateway: string;
		wanIface: string;
		pppoeUsername: string;
		pppoePassword: string;
		pppoeVlan: string;
		pppoeMtu: number;
		interfaces: NetworkInterfaceInfo[];
		onback: () => void;
		onnext: () => void;
	} = $props();
</script>

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
			class="flex flex-col items-start rounded-xl border p-4 text-left transition-all {wanMode === 'system_gateway' ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-muted-foreground/40'}"
			onclick={() => (wanMode = "system_gateway")}
		>
			<div class="flex w-full items-center justify-between mb-2">
				<ServerIcon class="h-5 w-5 text-primary" />
				{#if wanMode === "system_gateway"}<Badge variant="default">Selected</Badge>{/if}
			</div>
			<h4 class="font-semibold text-foreground">System-Managed Uplink</h4>
			<p class="mt-1 text-xs text-muted-foreground">
				Single-NIC or OS-managed network (systemd-networkd / existing modem).
			</p>
		</button>

		<!-- Integrated PPPoE Mode -->
		<button
			type="button"
			class="flex flex-col items-start rounded-xl border p-4 text-left transition-all {wanMode === 'pppoe' ? 'border-primary bg-primary/5 ring-1 ring-primary' : 'border-border hover:border-muted-foreground/40'}"
			onclick={() => (wanMode = "pppoe")}
		>
			<div class="flex w-full items-center justify-between mb-2">
				<GlobeIcon class="h-5 w-5 text-primary" />
				{#if wanMode === "pppoe"}<Badge variant="default">Selected</Badge>{/if}
			</div>
			<h4 class="font-semibold text-foreground">Integrated PPPoE</h4>
			<p class="mt-1 text-xs text-muted-foreground">
				Direct Fiber / DSL dial-in managed on a dedicated WAN port by Lanforge.
			</p>
		</button>
	</div>

	<Separator class="my-4" />

	{#if wanMode === "system_gateway"}
		<div class="space-y-1.5">
			<Label for="gateway_ip">Upstream Default Gateway IP</Label>
			<Input id="gateway_ip" bind:value={systemGateway} placeholder="192.168.1.1" />
			<p class="text-xs text-muted-foreground mt-1">
				LAN clients will route internet traffic through this IP while Lanforge orchestrates DHCP and local DNS.
			</p>
		</div>
	{:else}
		<div class="space-y-3">
			<div class="space-y-1.5">
				<Label for="wan_iface">WAN Interface</Label>
				<select
					id="wan_iface"
					class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background"
					bind:value={wanIface}
				>
					{#each interfaces as iface}
						<option value={iface.name}>
							{iface.name} ({iface.bus_type} - {iface.carrier_up ? '🟢 Cable Connected' : '⚪ Disconnected'})
						</option>
					{/each}
				</select>
			</div>

			<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
				<div class="space-y-1.5">
					<Label for="pppoe_user">PPPoE Username</Label>
					<Input id="pppoe_user" bind:value={pppoeUsername} placeholder="client@isp.com" />
				</div>
				<div class="space-y-1.5">
					<Label for="pppoe_pass">PPPoE Password</Label>
					<Input id="pppoe_pass" type="password" bind:value={pppoePassword} placeholder="••••••••" />
				</div>
			</div>

			<div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
				<div class="space-y-1.5">
					<Label for="pppoe_vlan">VLAN Tag (Optional)</Label>
					<Input id="pppoe_vlan" bind:value={pppoeVlan} placeholder="e.g. 35 (leave empty if none)" />
				</div>
				<div class="space-y-1.5">
					<Label for="pppoe_mtu">WAN MTU / MRU</Label>
					<Input id="pppoe_mtu" type="number" bind:value={pppoeMtu} placeholder="1492" />
				</div>
			</div>
		</div>
	{/if}
</Card.Content>
<Card.Footer class="flex justify-between">
	<Button variant="outline" onclick={onback} class="gap-2">
		<ArrowLeftIcon class="h-4 w-4" />
		Back
	</Button>
	<Button onclick={onnext} class="gap-2">
		Next: LAN & Services
		<ArrowRightIcon class="h-4 w-4" />
	</Button>
</Card.Footer>
