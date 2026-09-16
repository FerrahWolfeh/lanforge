<script lang="ts">
	import { Badge } from "$lib/components/ui/badge";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import type { FirewallMode } from "$lib/api/types";

	interface Props {
		mode: FirewallMode;
		disabled?: boolean;
		onSelect: (mode: FirewallMode) => void;
	}

	let { mode, disabled = false, onSelect }: Props = $props();
</script>

<div class="grid grid-cols-1 gap-3 md:grid-cols-3">
	<!-- Full Mode -->
	<button
		type="button"
		class="flex flex-col text-left rounded-xl border p-4 transition-all duration-150 {mode === 'full' ? 'border-primary bg-primary/5 ring-1 ring-primary shadow-xs' : 'border-border bg-card hover:bg-muted/40'} {disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}"
		onclick={() => !disabled && onSelect("full")}
		{disabled}
	>
		<div class="flex items-center justify-between w-full mb-1.5">
			<div class="flex items-center gap-2">
				<ShieldCheckIcon class="size-4 text-primary" />
				<span class="font-semibold text-sm text-foreground">Full Router</span>
			</div>
			<Badge variant={mode === 'full' ? 'default' : 'secondary'} class="text-[10px]">
				Recommended
			</Badge>
		</div>
		<p class="text-xs text-muted-foreground leading-relaxed">
			Lanforge manages all network filtering, zones, traffic matrix, host rules, and NAT port forwarding. Designed for standalone router gateways.
		</p>
	</button>

	<!-- Minimal Mode -->
	<button
		type="button"
		class="flex flex-col text-left rounded-xl border p-4 transition-all duration-150 {mode === 'minimal' ? 'border-primary bg-primary/5 ring-1 ring-primary shadow-xs' : 'border-border bg-card hover:bg-muted/40'} {disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}"
		onclick={() => !disabled && onSelect("minimal")}
		{disabled}
	>
		<div class="flex items-center justify-between w-full mb-1.5">
			<div class="flex items-center gap-2">
				<LayersIcon class="size-4 text-primary" />
				<span class="font-semibold text-sm text-foreground">Minimal Helper</span>
			</div>
			<Badge variant={mode === 'minimal' ? 'default' : 'outline'} class="text-[10px]">
				firewalld / ufw
			</Badge>
		</div>
		<p class="text-xs text-muted-foreground leading-relaxed">
			Non-interfering helper table with default accept. Manages PPPoE Flowtable hardware acceleration, TCP MSS clamping, and masquerade alongside system firewalls.
		</p>
	</button>

	<!-- Disabled Mode -->
	<button
		type="button"
		class="flex flex-col text-left rounded-xl border p-4 transition-all duration-150 {mode === 'disabled' ? 'border-destructive bg-destructive/5 ring-1 ring-destructive shadow-xs' : 'border-border bg-card hover:bg-muted/40'} {disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}"
		onclick={() => !disabled && onSelect("disabled")}
		{disabled}
	>
		<div class="flex items-center justify-between w-full mb-1.5">
			<div class="flex items-center gap-2">
				<ShieldOffIcon class="size-4 text-muted-foreground" />
				<span class="font-semibold text-sm text-foreground">Disabled</span>
			</div>
			<Badge variant="outline" class="text-[10px]">
				Unmanaged
			</Badge>
		</div>
		<p class="text-xs text-muted-foreground leading-relaxed">
			Completely flushes and disables the Lanforge nftables table. Packet filtering and forwarding offload are left unmanaged.
		</p>
	</button>
</div>
