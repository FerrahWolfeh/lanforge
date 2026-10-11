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
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";
	import StatusDot from "$lib/components/StatusDot.svelte";
	import ThroughputDisplay from "$lib/components/ThroughputDisplay.svelte";
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
	<StatCardGrid cols={5}>
		<!-- 1. Runtime Subsystem State -->
		<StatCard
			label="Runtime"
			popover={{
				title: "Service Lifecycle",
				description: "Daemon supervisor state for the traffic and queue management subsystem.",
			}}
			badge={{
				text: isOnline ? "Online" : isStarting ? "Starting" : "Dormant",
				variant: isOnline ? "online" : isStarting ? "starting" : "dormant",
				showDot: true,
			}}
		>
			{#snippet valueExtra()}
				<div class="flex items-center gap-2 pt-0.5">
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
				</div>
			{/snippet}
			{#snippet footer()}
				<StatCardFooterItem label="Reload" value="In-place" color="text-emerald-500" />
				<StatCardFooterItem label="Uplink" value={status?.wan_interface ?? "Auto"} />
			{/snippet}
		</StatCard>

		<!-- 2. Smart Queue Management (SQM CAKE) -->
		<StatCard
			label="CAKE Shaper"
			popover={{
				title: "Smart Queue Management",
				description: "Active Queue Management (CAKE) bounds buffer latency to prevent lag spikes under load.",
			}}
			badge={{
				text: status?.sqm_active ? "Active" : "Disabled",
				variant: status?.sqm_active ? "online" : "dormant",
				showDot: true,
			}}
		>
			{#snippet valueExtra()}
				<div class="flex items-center gap-2 pt-0.5">
					{#if status?.sqm_active}
						<GaugeIcon class="size-5 text-emerald-500 shrink-0" />
						<span class="text-base font-bold text-foreground">
							{status.download_mbps}M / {status.upload_mbps}M
						</span>
					{:else}
						<XCircleIcon class="size-5 text-muted-foreground shrink-0" />
						<span class="text-base text-muted-foreground font-normal">Shaper Disabled</span>
					{/if}
				</div>
			{/snippet}
			{#snippet footer()}
				<StatCardFooterItem label="Profile" value={status?.diffserv ?? "diffserv4"} />
				<StatCardFooterItem label="Ingress" value={status?.ingress_device ?? "None"} />
			{/snippet}
		</StatCard>

		<!-- 3. Hardware & NIC Tuning -->
		<StatCard
			label="NIC Tuning"
			popover={{
				title: "Hardware & Driver Tuning",
				description: "Kernel-level tuning for network interface controllers.",
			}}
			badge={{
				text: status?.tuning_applied ? "Tuned" : "Default",
				variant: status?.tuning_applied ? "primary" : "dormant",
			}}
		>
			{#snippet valueExtra()}
				<div class="flex items-center gap-2 pt-0.5">
					{#if status?.tuning_applied}
						<CpuIcon class="size-5 text-primary shrink-0" />
						<span class="text-base font-bold text-foreground">
							{status.tuned_interfaces.length} NIC{status.tuned_interfaces.length === 1 ? '' : 's'} Tuned
						</span>
					{:else}
						<CpuIcon class="size-5 text-muted-foreground shrink-0" />
						<span class="text-base text-muted-foreground font-normal">Kernel Default</span>
					{/if}
				</div>
			{/snippet}
			{#snippet footer()}
				<StatCardFooterItem label="RPS Mask" value={status?.effective_cpu_mask ? `0x${status.effective_cpu_mask}` : "auto"} />
				<StatCardFooterItem label="Interfaces" value={status?.tuned_interfaces?.join(", ") || "None"} />
			{/snippet}
		</StatCard>

		<!-- 4. Real-Time Network Throughput -->
		<StatCard
			label="Throughput"
			popover={{
				title: "Instantaneous Network Rates",
				description: "Real-time traffic throughput calculated from Linux kernel /proc/net/dev counters.",
			}}
			badge={{
				text: "Live",
				variant: "sky",
			}}
		>
			{#snippet valueExtra()}
				<div class="flex items-center gap-2 pt-0.5">
					<ActivityIcon class="size-5 text-sky-400 shrink-0" />
					<ThroughputDisplay rxBps={totalRxBps} txBps={totalTxBps} size="sm" />
				</div>
			{/snippet}
			{#snippet footer()}
				<StatCardFooterItem label="Volume (Rx/Tx)" value={`${formatBytes(totalRxBytes)} / ${formatBytes(totalTxBytes)}`} />
				<StatCardFooterItem
					label="Errors / Drops"
					value={totalDrops + totalErrors === 0 ? "0 Clean" : `${totalDrops} drops · ${totalErrors} err`}
					color={totalDrops > 0 || totalErrors > 0 ? "text-amber-400 font-medium" : "text-emerald-500"}
				/>
			{/snippet}
		</StatCard>

		<!-- 5. Firewall & Conntrack State -->
		<StatCard
			label="Conntrack"
			popover={{
				title: "Netfilter Stateful Tracking",
				description: "Kernel connection tracking table capacity and session state.",
			}}
			badge={{
				text: `${conntrack ? conntrack.utilization_percent.toFixed(1) : "0"}%`,
				variant: (conntrack?.utilization_percent ?? 0) < 70 ? "online" : (conntrack?.utilization_percent ?? 0) < 90 ? "warning" : "error",
			}}
		>
			{#snippet valueExtra()}
				<div class="flex items-center gap-2 pt-0.5">
					<ShieldCheckIcon class="size-5 text-violet-400 shrink-0" />
					<span class="text-base font-bold text-foreground font-mono">
						{conntrack ? conntrack.active_connections.toLocaleString() : "—"}
						<span class="text-xs text-muted-foreground font-normal ml-1">sessions</span>
					</span>
				</div>
			{/snippet}
			{#snippet footer()}
				<StatCardFooterItem label="Capacity Max" value={conntrack?.max_connections.toLocaleString() ?? "65,536"} />
				<StatCardFooterItem
					label="New / Drops"
					value={conntrack ? `${conntrack.new.toLocaleString()} / ${conntrack.drop.toLocaleString()}` : "0 / 0"}
				/>
			{/snippet}
		</StatCard>
	</StatCardGrid>

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
										<StatusDot state="online" size="sm" />
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
											<StatusBadge variant="online" text="Healthy" />
										{:else}
											<StatusBadge variant="warning" text={`${iface.rx_dropped + iface.tx_dropped} Drops`} />
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
