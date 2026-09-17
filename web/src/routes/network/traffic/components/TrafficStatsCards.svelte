<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import MoonIcon from "@lucide/svelte/icons/moon";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import InfoPopover from "$lib/components/InfoPopover.svelte";

	import type { TrafficStatusResponse } from "$lib/api/types";

	interface Props {
		status?: TrafficStatusResponse | null;
	}

	let { status = null }: Props = $props();

	const stateStr = $derived((status?.service_state ?? "inactive").toLowerCase());
	const isOnline = $derived(stateStr === "online" || stateStr === "active");
	const isStarting = $derived(stateStr === "starting");
</script>

<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
	<!-- 1. Runtime Subsystem State -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span class="flex items-center gap-1.5">
					Service Runtime
					<InfoPopover
						title="Service Lifecycle"
						description="Daemon supervisor state for the traffic and queue management subsystem."
					>
						<p class="text-xs text-muted-foreground leading-relaxed">
							<strong>Running:</strong> Actively maintaining kernel queues and driver tuning.<br />
							<strong>Dormant:</strong> Standing by with zero CPU overhead until interfaces or shaping are enabled.
						</p>
					</InfoPopover>
				</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						isOnline
							? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
							: isStarting
								? "border-amber-500/30 bg-amber-500/10 text-amber-400 animate-pulse"
								: "border-border text-muted-foreground",
					].join(" ")}
				>
					{isOnline ? "Online" : isStarting ? "Starting" : "Dormant"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if isOnline}
					<CheckCircleIcon class="size-5 text-emerald-500 shrink-0" />
					<span class="text-base font-bold text-emerald-400">Running</span>
				{:else if isStarting}
					<RefreshCwIcon class="size-5 text-amber-500 shrink-0 animate-spin" />
					<span class="text-base text-amber-400 font-bold">Starting...</span>
				{:else}
					<MoonIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Dormant (Standby)</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Reload</span>
					<span class="font-mono text-emerald-500">In-place (~10ms)</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Target Uplink</span>
					<span class="font-mono font-medium text-foreground truncate">
						{status?.wan_interface ?? "Auto"}
					</span>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- 2. Smart Queue Management (SQM CAKE) -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span class="flex items-center gap-1.5">
					CAKE Shaper
					<InfoPopover
						title="Smart Queue Management"
						description="Active Queue Management (CAKE) bounds buffer latency to prevent lag spikes under load."
					>
						<p class="text-xs text-muted-foreground leading-relaxed">
							Shapes traffic to ISP limits on ingress and egress, isolates client flows fairly, and keeps ping low during large file transfers.
						</p>
					</InfoPopover>
				</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						status?.sqm_active
							? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
							: "border-border text-muted-foreground",
					].join(" ")}
				>
					{status?.sqm_active ? "Active" : "Disabled"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if status?.sqm_active}
					<GaugeIcon class="size-5 text-emerald-500 shrink-0" />
					<span class="text-base font-bold text-foreground">
						{status.download_mbps}M Down / {status.upload_mbps}M Up
					</span>
				{:else}
					<XCircleIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Shaper Disabled</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Profile & Framing</span>
					<span class="font-mono text-[11px] text-foreground truncate">
						{status?.diffserv ?? "diffserv4"} · {status?.overhead ?? "auto"}
					</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Ingress Device</span>
					<span class="font-mono text-[11px] text-muted-foreground truncate">
						{status?.ingress_device ?? "None"}
					</span>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- 3. Hardware & NIC Tuning -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span class="flex items-center gap-1.5">
					NIC Tuning
					<InfoPopover
						title="Hardware & Driver Tuning"
						description="Kernel-level tuning for network interface controllers."
					>
						<p class="text-xs text-muted-foreground leading-relaxed">
							Spreads packet interrupts across CPU threads via RPS/RFS, sets driver ring buffers to maximum capacity, and disables 802.3az EEE power-saving drops.
						</p>
					</InfoPopover>
				</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						status?.tuning_applied
							? "border-primary/30 bg-primary/10 text-primary"
							: "border-border text-muted-foreground",
					].join(" ")}
				>
					{status?.tuning_applied ? "Tuned" : "Default"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if status?.tuning_applied}
					<CpuIcon class="size-5 text-primary shrink-0" />
					<span class="text-base font-bold text-foreground">
						{status.tuned_interfaces.length} NIC{status.tuned_interfaces.length === 1 ? '' : 's'} Tuned
					</span>
				{:else}
					<CpuIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Kernel Default</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">RPS CPU Mask</span>
					<span class="font-mono font-medium text-foreground">
						{status?.effective_cpu_mask ? `0x${status.effective_cpu_mask}` : "auto"}
					</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Tuned Ports</span>
					<span class="font-mono text-[11px] text-muted-foreground truncate" title={status?.tuned_interfaces?.join(", ") ?? ""}>
						{status?.tuned_interfaces?.join(", ") || "None"}
					</span>
				</div>
			</div>
		</Card.Content>
	</Card.Root>
</div>
