<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";
	import ArrowLeftIcon from "@lucide/svelte/icons/arrow-left";
	import type { FirewallMode } from "$lib/api/types";

	let {
		adminUsername,
		wanMode,
		wanIface,
		pppoeVlan,
		systemGateway,
		lanIface,
		lanIp,
		subnetMask,
		dhcpV4Enabled,
		dhcpPoolStart,
		dhcpPoolEnd,
		dhcpRouter,
		dhcpV6Enabled,
		dhcpV6PoolRange,
		raEnabled,
		raAutoGua,
		raAutoUla,
		raCustomUla,
		raUlaPrefix,
		domainName,
		upstreamDnsList,
		adblockEnabled,
		adblockPresetsCount,
		firewallMode,
		firewallFlowOffload,
		submitting,
		onback,
		onlaunch,
	}: {
		adminUsername: string;
		wanMode: "system_gateway" | "pppoe";
		wanIface: string;
		pppoeVlan: string;
		systemGateway: string;
		lanIface: string;
		lanIp: string;
		subnetMask: string;
		dhcpV4Enabled: boolean;
		dhcpPoolStart: string;
		dhcpPoolEnd: string;
		dhcpRouter: string;
		dhcpV6Enabled: boolean;
		dhcpV6PoolRange: string;
		raEnabled: boolean;
		raAutoGua: boolean;
		raAutoUla: boolean;
		raCustomUla: boolean;
		raUlaPrefix: string;
		domainName: string;
		upstreamDnsList: string[];
		adblockEnabled: boolean;
		adblockPresetsCount: number;
		firewallMode: FirewallMode;
		firewallFlowOffload: boolean;
		submitting: boolean;
		onback: () => void;
		onlaunch: () => void;
	} = $props();
</script>

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
			<span class="font-medium text-foreground">{adminUsername}</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">Uplink Mode:</span>
			<span class="font-medium text-foreground">
				{wanMode === 'pppoe' ? `Integrated PPPoE (${wanIface}${pppoeVlan ? ` VLAN ${pppoeVlan}` : ''})` : `System-Managed Gateway (${systemGateway})`}
			</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">LAN Interface:</span>
			<span class="font-medium text-foreground">{lanIface} ({lanIp})</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">Subnet Mask:</span>
			<span class="font-medium text-foreground">{subnetMask}</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">DHCPv4 Server:</span>
			<span class="font-medium text-foreground">
				{#if dhcpV4Enabled}
					Enabled ({dhcpPoolStart} – {dhcpPoolEnd})
				{:else}
					Disabled
				{/if}
			</span>
		</div>
		{#if dhcpV4Enabled}
			<div class="flex justify-between text-sm">
				<span class="text-muted-foreground">DHCPv4 Gateway:</span>
				<span class="font-medium text-foreground">{dhcpRouter}</span>
			</div>
		{/if}
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">DHCPv6 Server:</span>
			<span class="font-medium text-foreground">
				{#if dhcpV6Enabled}
					Enabled ({dhcpV6PoolRange || '::100-::1fff'})
				{:else}
					Disabled
				{/if}
			</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">IPv6 RA SLAAC:</span>
			<span class="font-medium text-foreground">
				{#if raEnabled}
					Enabled ({[raAutoGua ? 'Auto-GUA' : null, raAutoUla ? 'Auto-ULA' : null, raCustomUla && raUlaPrefix ? `Custom ULA (${raUlaPrefix})` : null].filter(Boolean).join(' + ') || 'Manual'})
				{:else}
					Disabled
				{/if}
			</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">Local Domain:</span>
			<span class="font-medium text-foreground">.{domainName}</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">Upstream DNS:</span>
			<span class="font-medium text-foreground">{upstreamDnsList.join(", ")}</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">DNS Adblocker:</span>
			<span class="font-medium text-foreground">
				{#if adblockEnabled}
					Enabled ({adblockPresetsCount} filter list{adblockPresetsCount === 1 ? '' : 's'})
				{:else}
					Disabled
				{/if}
			</span>
		</div>
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">Firewall Mode:</span>
			<span class="font-medium text-foreground">
				{firewallMode === 'full' ? 'Full Router (Standalone)' : firewallMode === 'minimal' ? 'Minimal Helper (Coexistence)' : 'Disabled'}
			</span>
		</div>
		{#if firewallMode !== 'disabled'}
			<div class="flex justify-between text-sm">
				<span class="text-muted-foreground">Flowtable Offload:</span>
				<span class="font-medium text-foreground">{firewallFlowOffload ? 'Enabled' : 'Disabled'}</span>
			</div>
		{/if}
		<div class="flex justify-between text-sm">
			<span class="text-muted-foreground">Storage Engine:</span>
			<span class="font-medium text-emerald-400">redb (embedded pure-Rust)</span>
		</div>
	</div>
</Card.Content>
<Card.Footer class="flex justify-between">
	<Button variant="outline" onclick={onback} class="gap-2" disabled={submitting}>
		<ArrowLeftIcon class="h-4 w-4" />
		Back
	</Button>
	<Button onclick={onlaunch} class="gap-2 bg-emerald-600 hover:bg-emerald-500 text-white" disabled={submitting}>
		{#if submitting}
			Activating Lanforge...
		{:else}
			Launch Lanforge 🚀
		{/if}
	</Button>
</Card.Footer>
