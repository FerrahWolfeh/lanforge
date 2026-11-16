<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ArrowDownIcon from "@lucide/svelte/icons/arrow-down";
	import ArrowUpIcon from "@lucide/svelte/icons/arrow-up";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";
	import StatusDot from "$lib/components/StatusDot.svelte";
	import { formatBytes, formatBps } from "$lib/utils";
	import { IsMobile } from "$lib/hooks/is-mobile.svelte";

	import type { TrafficStatusResponse, TrafficTelemetryResponse } from "$lib/api/types";

	interface Props {
		status?: TrafficStatusResponse | null;
		telemetry?: TrafficTelemetryResponse | null;
	}

	let { status = null, telemetry = null }: Props = $props();

	const sqmWaiting = $derived(!!status?.flow_offload_suppressed && !status?.sqm_active);
	const wanIface = $derived(telemetry?.wan_interface ?? status?.wan_interface);
	const isMobile = new IsMobile();

</script>

<div class="flex flex-col gap-4">
	<!-- Top Core Telemetry Cards -->
	<StatCardGrid cols={2}>
		<!-- 2. Smart Queue Management (SQM CAKE) -->
		<StatCard
			label="Queue Management (CAKE)"
			popover={{
				title: "Queue management",
				description: "CAKE keeps latency low while the line is full, so calls and games do not lag during a download.",
			}}
			badge={{
				text: status?.sqm_active ? "On" : sqmWaiting ? "Waiting for WAN" : "Off",
				variant: status?.sqm_active ? "online" : sqmWaiting ? "starting" : "dormant",
				showDot: true,
			}}
		>
			{#snippet valueExtra()}
				<div class="flex items-center gap-2 pt-0.5">
					{#if status?.sqm_active}
						<GaugeIcon class="size-5 text-muted-foreground shrink-0" />
						<span class="text-base font-bold text-foreground">
							{status.download_mbps}M / {status.upload_mbps}M
						</span>
					{:else}
						<XCircleIcon class="size-5 text-muted-foreground shrink-0" />
						<span class="text-base text-muted-foreground font-normal">
							{sqmWaiting ? "Starts when the WAN is up" : "Off"}
						</span>
					{/if}
				</div>
			{/snippet}
			{#snippet footer()}
				<StatCardFooterItem label="Profile" value={status?.diffserv ?? "—"} />
				<StatCardFooterItem label="Download shaping on" value={status?.ingress_device ?? "—"} />
			{/snippet}
		</StatCard>

		<!-- 3. Hardware & NIC Tuning -->
		<StatCard
			label="NIC Tuning"
			popover={{
				title: "NIC tuning",
				description: "Spreads packet processing over the CPU cores and sets the network card's offloads.",
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
						<span class="text-base text-muted-foreground font-normal">Kernel defaults</span>
					{/if}
				</div>
			{/snippet}
			{#snippet footer()}
				<StatCardFooterItem label="CPU Mask (RPS)" value={status?.effective_cpu_mask ? `0x${status.effective_cpu_mask}` : "—"} />
				<StatCardFooterItem label="Interfaces" value={status?.tuned_interfaces?.join(", ") || "—"} />
			{/snippet}
		</StatCard>

	</StatCardGrid>

	<!-- Active Interfaces Throughput Panel -->
	{#if telemetry?.interfaces && telemetry.interfaces.length > 0}
		<Card.Root>
			<Card.Header class="pt-4 sm:pt-5 !pb-3.5 sm:!pb-4 px-4 sm:px-6 border-b border-border/50">
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
				{#if isMobile.current}
					<div class="divide-y divide-border/60">
						{#each telemetry.interfaces as iface (iface.interface)}
							<div class="flex flex-col gap-1 px-4 py-3">
								<div class="flex items-center justify-between gap-2">
									<span class="flex min-w-0 items-center gap-2">
										<StatusDot state="online" size="sm" />
										<span class="truncate font-mono text-sm font-semibold text-foreground">{iface.interface}</span>
										{#if iface.interface === wanIface || iface.interface.startsWith("ppp")}
											<Badge variant="outline" class="text-xs px-1 py-0 border-border text-muted-foreground">WAN</Badge>
										{:else if iface.interface.startsWith("lan") || iface.interface.startsWith("br-")}
											<Badge variant="outline" class="text-xs px-1 py-0 border-border text-muted-foreground">LAN</Badge>
										{/if}
									</span>
									{#if iface.rx_dropped + iface.tx_dropped + iface.rx_errors + iface.tx_errors === 0}
										<StatusBadge variant="online" text="Healthy" />
									{:else}
										<StatusBadge variant="warning" text={`${iface.rx_dropped + iface.tx_dropped} Drops`} />
									{/if}
								</div>
								<div class="flex items-center gap-4 font-mono text-xs">
									<span class="flex items-center gap-1 text-[var(--chart-1)]">
										<ArrowDownIcon class="size-3 shrink-0" />
										<span class="font-semibold">{formatBps(iface.rx_rate_bps)}</span>
									</span>
									<span class="flex items-center gap-1 text-[var(--chart-2)]">
										<ArrowUpIcon class="size-3 shrink-0" />
										<span class="font-semibold">{formatBps(iface.tx_rate_bps)}</span>
									</span>
								</div>
								<span class="text-xs text-muted-foreground">
									{formatBytes(iface.rx_bytes)} / {formatBytes(iface.tx_bytes)}
								</span>
							</div>
						{/each}
					</div>
				{:else}
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
											<Badge variant="outline" class="text-xs px-1 py-0 border-border text-muted-foreground font-sans">WAN</Badge>
										{:else if iface.interface.startsWith("ifb")}
											<Badge variant="outline" class="text-xs px-1 py-0 border-border text-muted-foreground font-sans">SQM Ingress</Badge>
										{:else if iface.interface.startsWith("tailscale")}
											<Badge variant="outline" class="text-xs px-1 py-0 border-border text-muted-foreground font-sans">Tailscale VPN</Badge>
										{:else if iface.interface.startsWith("veth") || iface.interface.startsWith("podman") || iface.interface.startsWith("docker")}
											<Badge variant="outline" class="text-xs px-1 py-0 border-border text-muted-foreground font-sans">Container</Badge>
										{:else if iface.interface.startsWith("lan") || iface.interface.startsWith("br-")}
											<Badge variant="outline" class="text-xs px-1 py-0 border-border text-muted-foreground font-sans">LAN</Badge>
										{/if}
									</td>
									<td class="py-2.5 px-4 text-right">
										<div class="flex items-center justify-end gap-1 text-[var(--chart-1)]">
											<ArrowDownIcon class="size-3 shrink-0" />
											<span class="font-semibold">{formatBps(iface.rx_rate_bps)}</span>
										</div>
									</td>
									<td class="py-2.5 px-4 text-right">
										<div class="flex items-center justify-end gap-1 text-[var(--chart-2)]">
											<ArrowUpIcon class="size-3 shrink-0" />
											<span class="font-semibold">{formatBps(iface.tx_rate_bps)}</span>
										</div>
									</td>
									<td class="py-2.5 px-4 text-right text-muted-foreground font-sans">
										<span>{formatBytes(iface.rx_bytes)}</span>
										<span class="text-muted-foreground mx-1">/</span>
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
				{/if}
			</Card.Content>
		</Card.Root>
	{/if}
</div>
