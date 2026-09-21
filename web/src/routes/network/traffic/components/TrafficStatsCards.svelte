<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import MoonIcon from "@lucide/svelte/icons/moon";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowDownIcon from "@lucide/svelte/icons/arrow-down";
	import ArrowUpIcon from "@lucide/svelte/icons/arrow-up";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import { formatBytes, formatBps } from "$lib/utils";

	import type { TrafficStatusResponse, TrafficTelemetryResponse } from "$lib/api/types";

	interface Props {
		status?: TrafficStatusResponse | null;
		telemetry?: TrafficTelemetryResponse | null;
	}

	let { status = null, telemetry = null }: Props = $props();

	const stateStr = $derived((status?.service_state ?? "inactive").toLowerCase());
	const isOnline = $derived(stateStr === "online" || stateStr === "active");
	const isStarting = $derived(stateStr === "starting");

	// Instantaneous rates for gateway uplink and physical interfaces (excluding IFB mirrors and container veths)
	const wanIface = $derived(telemetry?.wan_interface ?? status?.wan_interface);
	const totalRxBps = $derived.by(() => {
		if (wanIface) {
			const found = telemetry?.interfaces?.find((i) => i.interface === wanIface);
			if (found) return found.rx_rate_bps;
		}
		return (
			telemetry?.interfaces
				?.filter((i) => !i.interface.startsWith("ifb") && !i.interface.startsWith("veth"))
				?.reduce((acc, i) => acc + i.rx_rate_bps, 0) ?? 0
		);
	});
	const totalTxBps = $derived.by(() => {
		if (wanIface) {
			const found = telemetry?.interfaces?.find((i) => i.interface === wanIface);
			if (found) return found.tx_rate_bps;
		}
		return (
			telemetry?.interfaces
				?.filter((i) => !i.interface.startsWith("ifb") && !i.interface.startsWith("veth"))
				?.reduce((acc, i) => acc + i.tx_rate_bps, 0) ?? 0
		);
	});
	const totalRxBytes = $derived.by(() => {
		if (wanIface) {
			const found = telemetry?.interfaces?.find((i) => i.interface === wanIface);
			if (found) return found.rx_bytes;
		}
		return (
			telemetry?.interfaces
				?.filter((i) => !i.interface.startsWith("ifb") && !i.interface.startsWith("veth"))
				?.reduce((acc, i) => acc + i.rx_bytes, 0) ?? 0
		);
	});
	const totalTxBytes = $derived.by(() => {
		if (wanIface) {
			const found = telemetry?.interfaces?.find((i) => i.interface === wanIface);
			if (found) return found.tx_bytes;
		}
		return (
			telemetry?.interfaces
				?.filter((i) => !i.interface.startsWith("ifb") && !i.interface.startsWith("veth"))
				?.reduce((acc, i) => acc + i.tx_bytes, 0) ?? 0
		);
	});
	const totalDrops = $derived(
		telemetry?.interfaces
			?.filter((i) => !i.interface.startsWith("ifb"))
			?.reduce((acc, i) => acc + i.rx_dropped + i.tx_dropped, 0) ?? 0
	);
	const totalErrors = $derived(
		telemetry?.interfaces
			?.filter((i) => !i.interface.startsWith("ifb"))
			?.reduce((acc, i) => acc + i.rx_errors + i.tx_errors, 0) ?? 0
	);

	const conntrack = $derived(telemetry?.conntrack);
</script>

<div class="flex flex-col gap-4">
	<!-- Top 5 Core Telemetry Cards -->
	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
		<!-- 1. Runtime Subsystem State -->
		<Card.Root class="relative overflow-hidden">
			<Card.Header class="pb-2 p-3 sm:p-4">
				<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
					<span class="flex items-center gap-1.5">
						Runtime
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
						<span class="text-base text-muted-foreground font-normal">Dormant</span>
					{/if}
				</Card.Title>
			</Card.Header>
			<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
				<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">Reload</span>
						<span class="font-mono text-emerald-500">In-place</span>
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">Uplink</span>
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
							{status.download_mbps}M / {status.upload_mbps}M
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
						<span class="text-[11px] text-muted-foreground">Profile</span>
						<span class="font-mono text-[11px] text-foreground truncate">
							{status?.diffserv ?? "diffserv4"}
						</span>
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">Ingress</span>
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
						<span class="text-[11px] text-muted-foreground">RPS Mask</span>
						<span class="font-mono font-medium text-foreground">
							{status?.effective_cpu_mask ? `0x${status.effective_cpu_mask}` : "auto"}
						</span>
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">Interfaces</span>
						<span class="font-mono text-[11px] text-muted-foreground truncate" title={status?.tuned_interfaces?.join(", ") ?? ""}>
							{status?.tuned_interfaces?.join(", ") || "None"}
						</span>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- 4. Real-Time Network Throughput -->
		<Card.Root class="relative overflow-hidden">
			<Card.Header class="pb-2 p-3 sm:p-4">
				<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
					<span class="flex items-center gap-1.5">
						Throughput
						<InfoPopover
							title="Instantaneous Network Rates"
							description="Real-time traffic throughput calculated from Linux kernel /proc/net/dev counters."
						>
							<p class="text-xs text-muted-foreground leading-relaxed">
								Calculated in bits per second across all active LAN, WAN, and bridge interfaces.
							</p>
						</InfoPopover>
					</span>
					<Badge
						variant="outline"
						class="text-[10px] uppercase font-mono px-1.5 py-0 border-sky-500/30 bg-sky-500/10 text-sky-400"
					>
						Live
					</Badge>
				</Card.Description>
				<Card.Title class="flex items-center gap-2 pt-0.5">
					<ActivityIcon class="size-5 text-sky-400 shrink-0" />
					<div class="flex items-baseline gap-1.5 overflow-hidden">
						<span class="text-base font-bold text-foreground font-mono truncate">
							{formatBps(totalRxBps)}
						</span>
						<span class="text-xs text-muted-foreground font-mono">↓</span>
						<span class="text-base font-bold text-foreground font-mono truncate ml-1">
							{formatBps(totalTxBps)}
						</span>
						<span class="text-xs text-muted-foreground font-mono">↑</span>
					</div>
				</Card.Title>
			</Card.Header>
			<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
				<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">Volume (Rx/Tx)</span>
						<span class="font-mono text-[11px] text-foreground truncate">
							{formatBytes(totalRxBytes)} / {formatBytes(totalTxBytes)}
						</span>
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">Errors / Drops</span>
						<span class={[
							"font-mono text-[11px] truncate",
							totalDrops > 0 || totalErrors > 0 ? "text-amber-400 font-medium" : "text-emerald-500"
						].join(" ")}>
							{totalDrops + totalErrors === 0 ? "0 Clean" : `${totalDrops} drops · ${totalErrors} err`}
						</span>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- 5. Firewall & Conntrack State -->
		<Card.Root class="relative overflow-hidden">
			<Card.Header class="pb-2 p-3 sm:p-4">
				<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
					<span class="flex items-center gap-1.5">
						Conntrack
						<InfoPopover
							title="Netfilter Stateful Tracking"
							description="Kernel connection tracking table capacity and session state."
						>
							<p class="text-xs text-muted-foreground leading-relaxed">
								Tracks state for all NAT translations, routed WAN forward streams, and local firewall inspections.
							</p>
						</InfoPopover>
					</span>
					<Badge
						variant="outline"
						class={[
							"text-[10px] uppercase font-mono px-1.5 py-0",
							(conntrack?.utilization_percent ?? 0) < 70
								? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
								: (conntrack?.utilization_percent ?? 0) < 90
									? "border-amber-500/30 bg-amber-500/10 text-amber-400"
									: "border-rose-500/30 bg-rose-500/10 text-rose-400",
						].join(" ")}
					>
						{conntrack ? `${conntrack.utilization_percent.toFixed(1)}%` : "0%"}
					</Badge>
				</Card.Description>
				<Card.Title class="flex items-center gap-2 pt-0.5">
					<ShieldCheckIcon class="size-5 text-violet-400 shrink-0" />
					<span class="text-base font-bold text-foreground font-mono">
						{conntrack ? conntrack.active_connections.toLocaleString() : "—"}
						<span class="text-xs text-muted-foreground font-normal ml-1">sessions</span>
					</span>
				</Card.Title>
			</Card.Header>
			<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
				<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">Capacity Max</span>
						<span class="font-mono text-[11px] text-foreground truncate">
							{conntrack?.max_connections.toLocaleString() ?? "65,536"}
						</span>
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-[11px] text-muted-foreground">New / Drops</span>
						<span class="font-mono text-[11px] text-muted-foreground truncate">
							{conntrack ? `${conntrack.new.toLocaleString()} / ${conntrack.drop.toLocaleString()}` : "0 / 0"}
						</span>
					</div>
				</div>
			</Card.Content>
		</Card.Root>
	</div>

	<!-- Active Interfaces Throughput Panel -->
	{#if telemetry?.interfaces && telemetry.interfaces.length > 0}
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<NetworkIcon class="size-4 text-primary" />
						<Card.Title class="text-sm font-semibold">Active Network Interfaces</Card.Title>
					</div>
					<Badge variant="secondary" class="font-mono text-xs">
						{telemetry.interfaces.length} Interfaces
					</Badge>
				</div>
			</Card.Header>
			<Card.Content class="p-0">
				<div class="overflow-x-auto">
					<table class="w-full text-xs text-left">
						<thead class="bg-muted/40 text-muted-foreground font-medium border-b border-border/50">
							<tr>
								<th class="py-2.5 px-4">Interface</th>
								<th class="py-2.5 px-4 text-right">Download (Rx)</th>
								<th class="py-2.5 px-4 text-right">Upload (Tx)</th>
								<th class="py-2.5 px-4 text-right">Cumulative Volume</th>
								<th class="py-2.5 px-4 text-right">Packets</th>
								<th class="py-2.5 px-4 text-center">Status</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-border/40 font-mono">
							{#each telemetry.interfaces as iface (iface.interface)}
								<tr class="hover:bg-muted/20 transition-colors">
									<td class="py-2.5 px-4 font-semibold text-foreground flex items-center gap-2">
										<span class="size-2 rounded-full bg-emerald-500 inline-block shrink-0"></span>
										<span>{iface.interface}</span>
										{#if iface.interface === wanIface || iface.interface.startsWith("ppp")}
											<Badge variant="outline" class="text-[10px] px-1 py-0 border-sky-500/30 text-sky-400 font-sans">WAN</Badge>
										{:else if iface.interface.startsWith("ifb")}
											<Badge variant="outline" class="text-[10px] px-1 py-0 border-amber-500/30 text-amber-400 font-sans">SQM Ingress</Badge>
										{:else if iface.interface.startsWith("tailscale")}
											<Badge variant="outline" class="text-[10px] px-1 py-0 border-violet-500/30 text-violet-400 font-sans">Tailscale VPN</Badge>
										{:else if iface.interface.startsWith("veth") || iface.interface.startsWith("podman") || iface.interface.startsWith("docker")}
											<Badge variant="outline" class="text-[10px] px-1 py-0 border-zinc-500/30 text-zinc-400 font-sans">Container</Badge>
										{:else if iface.interface.startsWith("lan") || iface.interface.startsWith("br-")}
											<Badge variant="outline" class="text-[10px] px-1 py-0 border-emerald-500/30 text-emerald-400 font-sans">LAN</Badge>
										{/if}
									</td>
									<td class="py-2.5 px-4 text-right">
										<div class="flex items-center justify-end gap-1 text-sky-400">
											<ArrowDownIcon class="size-3 shrink-0" />
											<span class="font-semibold">{formatBps(iface.rx_rate_bps)}</span>
										</div>
									</td>
									<td class="py-2.5 px-4 text-right">
										<div class="flex items-center justify-end gap-1 text-emerald-400">
											<ArrowUpIcon class="size-3 shrink-0" />
											<span class="font-semibold">{formatBps(iface.tx_rate_bps)}</span>
										</div>
									</td>
									<td class="py-2.5 px-4 text-right text-muted-foreground font-sans">
										<span>{formatBytes(iface.rx_bytes)}</span>
										<span class="text-zinc-500 mx-1">/</span>
										<span>{formatBytes(iface.tx_bytes)}</span>
									</td>
									<td class="py-2.5 px-4 text-right text-muted-foreground">
										{(iface.rx_packets + iface.tx_packets).toLocaleString()}
									</td>
									<td class="py-2.5 px-4 text-center">
										{#if iface.rx_dropped + iface.tx_dropped + iface.rx_errors + iface.tx_errors === 0}
											<Badge variant="outline" class="text-[10px] border-emerald-500/30 bg-emerald-500/10 text-emerald-400 font-sans">
												Healthy
											</Badge>
										{:else}
											<Badge variant="outline" class="text-[10px] border-amber-500/30 bg-amber-500/10 text-amber-400 font-sans">
												{iface.rx_dropped + iface.tx_dropped} Drops
											</Badge>
										{/if}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}
</div>
