<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Select from "$lib/components/ui/select";
	import * as Collapsible from "$lib/components/ui/collapsible";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Label } from "$lib/components/ui/label";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import UsersIcon from "@lucide/svelte/icons/users";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ChevronUpIcon from "@lucide/svelte/icons/chevron-up";
	import ArrowDownIcon from "@lucide/svelte/icons/arrow-down";
	import ArrowUpIcon from "@lucide/svelte/icons/arrow-up";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import { formatBytes } from "$lib/utils";

	import type { SqmOverhead, SqmDiffserv, NetworkInterfaceInfo, TrafficTelemetryResponse } from "$lib/api/types";

	let {
		enabled = $bindable(false),
		downloadMbps = $bindable(0),
		uploadMbps = $bindable(0),
		interface: iface = $bindable("auto"),
		overhead = $bindable("auto" as SqmOverhead),
		diffserv = $bindable("diffserv4" as SqmDiffserv),
		perHostIsolation = $bindable(true),
		rttMs = $bindable<number | null>(null),
		ingressDevice = $bindable("ifb4lanforge"),
		availableInterfaces = [],
		detectedWan = null,
		telemetry = null,
	}: {
		enabled?: boolean;
		downloadMbps?: number;
		uploadMbps?: number;
		interface?: string;
		overhead?: SqmOverhead;
		diffserv?: SqmDiffserv;
		perHostIsolation?: boolean;
		rttMs?: number | null;
		ingressDevice?: string;
		availableInterfaces?: NetworkInterfaceInfo[];
		detectedWan?: string | null;
		telemetry?: TrafficTelemetryResponse | null;
	} = $props();

	let advancedOpen = $state(false);

	// Filter interfaces: exclude virtual ifb devices
	const eligibleInterfaces = $derived(
		availableInterfaces.filter((i) => !i.name.startsWith("ifb") && !i.name.startsWith("teql"))
	);

	function formatOverheadLabel(oh: SqmOverhead): string {
		switch (oh) {
			case "auto": return "Auto-detect (Recommended)";
			case "pppoe": return "PPPoE (+34 bytes · FTTH / DSL)";
			case "ethernet": return "Ethernet (+14 bytes · DHCP / IPoE)";
			case "docsis": return "DOCSIS (+18 bytes · Cable)";
			case "none": return "None (0 bytes)";
			default: return oh;
		}
	}

	function formatDiffservLabel(ds: SqmDiffserv): string {
		switch (ds) {
			case "diffserv4": return "diffserv4 (Gaming, Voice, Video & Best-effort)";
			case "diffserv3": return "diffserv3 (3 Priority Queues)";
			case "besteffort": return "besteffort (Single Queue)";
			default: return ds;
		}
	}
</script>

<div class="flex flex-col gap-6">
	<!-- Top Container: Discreet SQM Switch Header -->
	<Card.Root>
		<Card.Header class="p-4 sm:p-5">
			<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
				<div class="flex items-start gap-3">
					<div class="mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-xl border border-sky-500/30 bg-sky-500/10 text-sky-400">
						<GaugeIcon class="size-5" />
					</div>
					<div>
						<div class="flex items-center gap-2">
							<Card.Title class="text-sm sm:text-base font-semibold">Smart Queue Management (CAKE)</Card.Title>
							<HelpPopover
								title="Bufferbloat & Active Queue Management"
								description="CAKE (Common Applications Kept Enhanced) manages network buffer latency in the Linux kernel."
							>
								<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
									<p>
										<strong class="text-foreground">Why it matters:</strong> Without queue management, ISP modems buffer packets when your connection is maxed out, causing ping in games and video calls to spike from 15ms to 500ms+.
									</p>
									<p>
										<strong class="text-foreground">How CAKE works:</strong> It bounds upload and download rates slightly below your physical link speed and uses active queue management (CoDel) to pace traffic, ensuring interactive packets are delivered with minimal latency.
									</p>
								</div>
							</HelpPopover>
						</div>
						<p class="text-xs text-muted-foreground mt-0.5">
							Maintains low latency and prevents bufferbloat lag spikes during intensive uploads or downloads.
						</p>
					</div>
				</div>

				<div class="flex items-center gap-3 shrink-0 self-end sm:self-center">
					<Badge variant={enabled ? "default" : "outline"} class="text-xs font-mono">
						{enabled ? "Active" : "Disabled"}
					</Badge>
					<Switch
						bind:checked={enabled}
						aria-label="Toggle Smart Queue Management"
					/>
				</div>
			</div>
		</Card.Header>
	</Card.Root>

	{#if enabled}
		<!-- Real-time CAKE Telemetry Card (When active in kernel) -->
		{#if telemetry?.sqm?.active}
		<Card.Root class="border-emerald-500/30 bg-card/60 overflow-hidden !py-0 !pt-0 gap-0 [--card-spacing:0]">
			<Card.Header class="pt-5 sm:pt-6 !pb-4 sm:!pb-5 px-4 sm:px-6 border-b border-border/50 bg-emerald-500/10 rounded-t-3xl flex flex-col gap-2 w-full !items-stretch">
				<div class="flex items-center justify-between w-full gap-4">
					<div class="flex items-center gap-2">
						<GaugeIcon class="size-4 text-emerald-500" />
						<Card.Title class="text-sm font-semibold text-foreground">
							Live CAKE Queue & Latency Telemetry
						</Card.Title>
					</div>
					<Badge variant="outline" class="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[10px] font-mono shrink-0">
						<span class="relative flex size-1.5 mr-1.5">
							<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
							<span class="relative inline-flex rounded-full size-1.5 bg-emerald-500"></span>
						</span>
						Kernel AQM Active
					</Badge>
				</div>
				<Card.Description class="text-xs text-muted-foreground/90 mt-0.5 leading-relaxed w-full">
					Real-time buffer latency, ECN marks, packet pacing, and DiffServ flow isolation measured directly from the Linux kernel.
				</Card.Description>
			</Card.Header>
			<Card.Content class="p-5 sm:p-6 flex flex-col gap-5">
				<!-- Ingress & Egress 2-Column Overview -->
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<!-- Ingress (Download) -->
					{#if telemetry.sqm.ingress}
						{@const ing = telemetry.sqm.ingress}
						{@const peakDelay = Math.max(...ing.tins.map((t) => t.peak_delay_us), 0)}
						{@const avgDelay = Math.round(ing.tins.reduce((a, t) => a + t.avg_delay_us, 0) / Math.max(1, ing.tins.length))}
						{@const totalEcn = ing.tins.reduce((a, t) => a + t.ecn_mark, 0)}
						{@const sparseFlows = ing.tins.reduce((a, t) => a + t.sparse_flows, 0)}
						{@const bulkFlows = ing.tins.reduce((a, t) => a + t.bulk_flows, 0)}
						<div class="flex flex-col gap-2.5 rounded-xl border p-3.5 bg-muted/20">
							<div class="flex items-center justify-between">
								<span class="text-xs font-semibold text-foreground flex items-center gap-1.5">
									<ArrowDownIcon class="size-3.5 text-sky-400" />
									Ingress Shaper ({ing.dev})
								</span>
								<span class="font-mono text-xs font-bold text-sky-400">
									{ing.bandwidth > 0 ? `${(ing.bandwidth / 1_000_000).toFixed(1)} Mbps` : "Unlimited"}
								</span>
							</div>
							<div class="grid grid-cols-2 gap-2 text-xs border-t pt-2 font-mono">
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Buffer Latency</span>
									<span class="text-foreground font-semibold">
										{peakDelay} µs <span class="text-muted-foreground font-normal text-[10px]">(avg {avgDelay} µs)</span>
									</span>
								</div>
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Drops / ECN Marks</span>
									<span class="text-foreground font-semibold">
										<span class={ing.drops > 0 ? "text-amber-400" : "text-emerald-500"}>{ing.drops.toLocaleString()} drops</span>
										<span class="text-muted-foreground font-normal text-[10px]"> / {totalEcn} ECN</span>
									</span>
								</div>
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Active Flows</span>
									<span class="text-foreground">
										<span class="text-emerald-400">{sparseFlows} sparse</span> / <span class="text-sky-400">{bulkFlows} bulk</span>
									</span>
								</div>
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Packets / Volume</span>
									<span class="text-muted-foreground">
										{ing.packets.toLocaleString()} pkts ({formatBytes(ing.bytes)})
									</span>
								</div>
							</div>
						</div>
					{/if}

					<!-- Egress (Upload) -->
					{#if telemetry.sqm.egress}
						{@const eg = telemetry.sqm.egress}
						{@const peakDelay = Math.max(...eg.tins.map((t) => t.peak_delay_us), 0)}
						{@const avgDelay = Math.round(eg.tins.reduce((a, t) => a + t.avg_delay_us, 0) / Math.max(1, eg.tins.length))}
						{@const totalEcn = eg.tins.reduce((a, t) => a + t.ecn_mark, 0)}
						{@const sparseFlows = eg.tins.reduce((a, t) => a + t.sparse_flows, 0)}
						{@const bulkFlows = eg.tins.reduce((a, t) => a + t.bulk_flows, 0)}
						<div class="flex flex-col gap-2.5 rounded-xl border p-3.5 bg-muted/20">
							<div class="flex items-center justify-between">
								<span class="text-xs font-semibold text-foreground flex items-center gap-1.5">
									<ArrowUpIcon class="size-3.5 text-emerald-400" />
									Egress Shaper ({eg.dev})
								</span>
								<span class="font-mono text-xs font-bold text-emerald-400">
									{eg.bandwidth > 0 ? `${(eg.bandwidth / 1_000_000).toFixed(1)} Mbps` : "Unlimited"}
								</span>
							</div>
							<div class="grid grid-cols-2 gap-2 text-xs border-t pt-2 font-mono">
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Buffer Latency</span>
									<span class="text-foreground font-semibold">
										{peakDelay} µs <span class="text-muted-foreground font-normal text-[10px]">(avg {avgDelay} µs)</span>
									</span>
								</div>
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Drops / ECN Marks</span>
									<span class="text-foreground font-semibold">
										<span class={eg.drops > 0 ? "text-amber-400" : "text-emerald-500"}>{eg.drops.toLocaleString()} drops</span>
										<span class="text-muted-foreground font-normal text-[10px]"> / {totalEcn} ECN</span>
									</span>
								</div>
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Active Flows</span>
									<span class="text-foreground">
										<span class="text-emerald-400">{sparseFlows} sparse</span> / <span class="text-sky-400">{bulkFlows} bulk</span>
									</span>
								</div>
								<div class="flex flex-col gap-0.5">
									<span class="text-[11px] text-muted-foreground font-sans">Packets / Volume</span>
									<span class="text-muted-foreground">
										{eg.packets.toLocaleString()} pkts ({formatBytes(eg.bytes)})
									</span>
								</div>
							</div>
						</div>
					{/if}
				</div>

				<!-- DiffServ Tins Latency Visual Bars -->
				{#if telemetry.sqm.egress || telemetry.sqm.ingress}
					{@const displayQdisc = telemetry.sqm.egress ?? telemetry.sqm.ingress}
					<div class="flex flex-col gap-2 pt-1">
						<div class="flex items-center justify-between">
							<span class="text-xs font-semibold text-foreground">DiffServ Tins Bufferbloat Latency Gauge</span>
							<span class="text-[11px] text-muted-foreground font-mono">Target Delay: 5,000 µs (5 ms)</span>
						</div>
						<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
							{#each displayQdisc?.tins ?? [] as tin (tin.tin_index)}
								{@const pct = Math.min(100, Math.round((tin.peak_delay_us / 5000) * 100))}
								<div class="flex flex-col gap-2 rounded-xl border p-3 bg-muted/20">
									<div class="flex items-center justify-between">
										<span class="text-xs font-semibold text-foreground">{tin.name}</span>
										<Badge variant="outline" class="text-[10px] font-mono py-0">
											Tin {tin.tin_index}
										</Badge>
									</div>
									<div class="flex items-baseline justify-between text-xs font-mono">
										<span class="text-[11px] text-muted-foreground font-sans">Peak Delay:</span>
										<span class={[
											"font-bold",
											tin.peak_delay_us < 1000 ? "text-emerald-400" : tin.peak_delay_us < 3000 ? "text-sky-400" : tin.peak_delay_us <= 5000 ? "text-amber-400" : "text-rose-400"
										].join(" ")}>
											{tin.peak_delay_us} µs
										</span>
									</div>
									<!-- Visual Latency Bar -->
									<div class="h-2 w-full rounded-full bg-muted/60 overflow-hidden">
										<div
											class={[
												"h-full rounded-full transition-all duration-300",
												tin.peak_delay_us < 1000 ? "bg-emerald-500" : tin.peak_delay_us < 3000 ? "bg-sky-500" : tin.peak_delay_us <= 5000 ? "bg-amber-500" : "bg-rose-500"
											].join(" ")}
											style={`width: ${Math.max(4, pct)}%`}
										></div>
									</div>
									<div class="flex items-center justify-between text-[11px] text-muted-foreground pt-0.5 border-t border-border/40 font-mono">
										<span>Flows:</span>
										<span>
											<span class="text-emerald-400">{tin.sparse_flows} sparse</span> / <span class="text-sky-400">{tin.bulk_flows} bulk</span>
										</span>
									</div>
								</div>
							{/each}
						</div>
					</div>
				{/if}

				<!-- DiffServ Tins Detailed Priority Queues Table -->
				{#if (telemetry.sqm.ingress?.tins.length ?? 0) > 0 || (telemetry.sqm.egress?.tins.length ?? 0) > 0}
					<div class="flex flex-col gap-1.5 pt-1">
						<span class="text-xs font-semibold text-foreground">DiffServ Priority Tins Breakdown</span>
						<div class="overflow-x-auto rounded-lg border border-border/50">
							<table class="w-full text-xs text-left">
								<thead class="bg-muted/40 text-muted-foreground font-medium border-b border-border/50">
									<tr>
										<th class="py-2 px-3">Tin Queue</th>
										<th class="py-2 px-3 text-center">Direction</th>
										<th class="py-2 px-3 text-right">Packets Sent</th>
										<th class="py-2 px-3 text-right">Volume</th>
										<th class="py-2 px-3 text-right">Buffer Delay</th>
										<th class="py-2 px-3 text-right">Drops / ECN</th>
										<th class="py-2 px-3 text-right">Flows (Sparse/Bulk)</th>
									</tr>
								</thead>
								<tbody class="divide-y divide-border/40 font-mono text-[11px]">
									{#if telemetry.sqm.ingress}
										{#each telemetry.sqm.ingress.tins as tin (tin.tin_index)}
											<tr class="hover:bg-muted/20">
												<td class="py-2 px-3 font-semibold text-foreground font-sans">{tin.name}</td>
												<td class="py-2 px-3 text-center">
													<Badge variant="outline" class="text-[10px] px-1 py-0 border-sky-500/30 text-sky-400 font-sans">Ingress</Badge>
												</td>
												<td class="py-2 px-3 text-right">{tin.sent_packets.toLocaleString()}</td>
												<td class="py-2 px-3 text-right">{formatBytes(tin.sent_bytes)}</td>
												<td class="py-2 px-3 text-right">{tin.peak_delay_us} µs <span class="text-muted-foreground">({tin.avg_delay_us} µs)</span></td>
												<td class="py-2 px-3 text-right">
													<span class={tin.drops > 0 ? "text-amber-400" : "text-muted-foreground"}>{tin.drops} drops</span>
													{#if tin.ecn_mark > 0}
														<span class="text-emerald-400 ml-1">· {tin.ecn_mark} ecn</span>
													{/if}
												</td>
												<td class="py-2 px-3 text-right">
													<span class="text-emerald-400">{tin.sparse_flows}s</span> / <span class="text-sky-400">{tin.bulk_flows}b</span>
												</td>
											</tr>
										{/each}
									{/if}
									{#if telemetry.sqm.egress}
										{#each telemetry.sqm.egress.tins as tin (tin.tin_index)}
											<tr class="hover:bg-muted/20">
												<td class="py-2 px-3 font-semibold text-foreground font-sans">{tin.name}</td>
												<td class="py-2 px-3 text-center">
													<Badge variant="outline" class="text-[10px] px-1 py-0 border-emerald-500/30 text-emerald-400 font-sans">Egress</Badge>
												</td>
												<td class="py-2 px-3 text-right">{tin.sent_packets.toLocaleString()}</td>
												<td class="py-2 px-3 text-right">{formatBytes(tin.sent_bytes)}</td>
												<td class="py-2 px-3 text-right">{tin.peak_delay_us} µs <span class="text-muted-foreground">({tin.avg_delay_us} µs)</span></td>
												<td class="py-2 px-3 text-right">
													<span class={tin.drops > 0 ? "text-amber-400" : "text-muted-foreground"}>{tin.drops} drops</span>
													{#if tin.ecn_mark > 0}
														<span class="text-emerald-400 ml-1">· {tin.ecn_mark} ecn</span>
													{/if}
												</td>
												<td class="py-2 px-3 text-right">
													<span class="text-emerald-400">{tin.sparse_flows}s</span> / <span class="text-sky-400">{tin.bulk_flows}b</span>
												</td>
											</tr>
										{/each}
									{/if}
								</tbody>
							</table>
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	{/if}

	<!-- Bandwidth & Interface Configuration -->
	<Card.Root>
			<Card.Header class="pt-5 sm:pt-6 !pb-4 sm:!pb-5 px-4 sm:px-6 border-b border-border/50">
				<Card.Title class="text-base font-semibold">Bandwidth Limits & Target WAN</Card.Title>
				<Card.Description class="text-xs text-muted-foreground/90 mt-0.5">
					Set bandwidth shaping limits to 90–95% of your measured connection speed to maintain queue authority.
				</Card.Description>
			</Card.Header>
			<Card.Content class="p-5 sm:p-6 flex flex-col gap-5">
				<div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
					<!-- WAN Interface Select -->
					<div class="flex flex-col gap-1.5">
						<Label class="text-xs font-semibold flex items-center gap-1.5">
							WAN Interface
							<InfoPopover
								title="Target WAN Interface"
								description="Interface where traffic shaping and rate limits are applied."
							>
								<p class="text-xs text-muted-foreground leading-relaxed">
									<strong>Auto (Recommended):</strong> Automatically identifies the active PPPoE session interface (e.g. <code>ppp0</code>) or the primary physical WAN port.
								</p>
							</InfoPopover>
						</Label>
						<Select.Root
							type="single"
							bind:value={iface}
						>
							<Select.Trigger class="h-9 text-xs font-mono">
								{iface === "auto"
									? `Auto (${detectedWan || "auto-detect"})`
									: iface}
							</Select.Trigger>
							<Select.Content>
								<Select.Item value="auto" class="text-xs font-mono">
									Auto {detectedWan ? `(${detectedWan})` : ""}
								</Select.Item>
								{#each eligibleInterfaces as item (item.name)}
									<Select.Item value={item.name} class="text-xs font-mono">
										<div class="flex items-center justify-between w-full gap-2">
											<span>{item.name}</span>
											<span class="text-[10px] text-muted-foreground">{item.bus_type}</span>
										</div>
									</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</div>

					<!-- Download Bandwidth Limit -->
					<div class="flex flex-col gap-1.5">
						<div class="flex items-center justify-between">
							<Label for="sqm-down" class="text-xs font-semibold">Download Limit</Label>
							<span class="text-[10px] text-muted-foreground font-mono">~90-95% speedtest</span>
						</div>
						<div class="relative">
							<Input
								id="sqm-down"
								type="number"
								min="0"
								step="5"
								bind:value={downloadMbps}
								placeholder="e.g. 450"
								class="h-9 text-xs pr-14 font-mono"
							/>
							<span class="absolute right-3 top-2.5 text-xs font-mono text-muted-foreground">Mbps</span>
						</div>
						<span class="text-[11px] text-muted-foreground">
							{downloadMbps > 0 ? `Shaped via IFB mirror at ${downloadMbps} Mbps` : "0 = Unlimited download"}
						</span>
					</div>

					<!-- Upload Bandwidth Limit -->
					<div class="flex flex-col gap-1.5">
						<div class="flex items-center justify-between">
							<Label for="sqm-up" class="text-xs font-semibold">Upload Limit</Label>
							<span class="text-[10px] text-muted-foreground font-mono">~90-95% speedtest</span>
						</div>
						<div class="relative">
							<Input
								id="sqm-up"
								type="number"
								min="0"
								step="5"
								bind:value={uploadMbps}
								placeholder="e.g. 250"
								class="h-9 text-xs pr-14 font-mono"
							/>
							<span class="absolute right-3 top-2.5 text-xs font-mono text-muted-foreground">Mbps</span>
						</div>
						<span class="text-[11px] text-muted-foreground">
							{uploadMbps > 0 ? `Shaped on WAN egress at ${uploadMbps} Mbps` : "0 = Unlimited upload"}
						</span>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Queue Framing & Priority Tuning -->
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<Card.Title class="text-base font-semibold">Queue Profiles & Client Isolation</Card.Title>
				<Card.Description class="text-xs">
					Configure link framing compensation and fair queue distribution across internal devices.
				</Card.Description>
			</Card.Header>
			<Card.Content class="p-4 flex flex-col gap-5">
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
					<!-- Framing Overhead Select -->
					<div class="flex flex-col gap-1.5">
						<Label class="text-xs font-semibold flex items-center gap-1.5">
							Framing Overhead Compensation
							<InfoPopover
								title="Link Framing Overhead"
								description="Compensates for layer 2 encapsulation headers added by your ISP."
							>
								<div class="flex flex-col gap-1 text-xs text-muted-foreground">
									<p><strong>PPPoE:</strong> +34 bytes (PPP and PPPoE headers + FCS).</p>
									<p><strong>Ethernet:</strong> +14 bytes (standard MAC header + CRC).</p>
									<p><strong>DOCSIS:</strong> +18 bytes (Cable modem encapsulation).</p>
								</div>
							</InfoPopover>
						</Label>
						<Select.Root
							type="single"
							bind:value={overhead}
						>
							<Select.Trigger class="h-9 text-xs">
								{formatOverheadLabel(overhead)}
							</Select.Trigger>
							<Select.Content>
								<Select.Item value="auto" class="text-xs">Auto-detect (Recommended)</Select.Item>
								<Select.Item value="pppoe" class="text-xs">PPPoE (+34 bytes · FTTH / DSL)</Select.Item>
								<Select.Item value="ethernet" class="text-xs">Ethernet (+14 bytes · DHCP / IPoE)</Select.Item>
								<Select.Item value="docsis" class="text-xs">DOCSIS (+18 bytes · Cable)</Select.Item>
								<Select.Item value="none" class="text-xs">None (0 bytes)</Select.Item>
							</Select.Content>
						</Select.Root>
					</div>

					<!-- DiffServ Mode Select -->
					<div class="flex flex-col gap-1.5">
						<Label class="text-xs font-semibold flex items-center gap-1.5">
							DiffServ Traffic Prioritization
							<InfoPopover
								title="DiffServ Priority Queues"
								description="Puts packets into priority queues using DSCP marks."
							>
								<div class="flex flex-col gap-1 text-xs text-muted-foreground">
									<p><strong>diffserv4:</strong> 4 queues (Voice/Gaming, Video, Best-effort, Background).</p>
									<p><strong>diffserv3:</strong> 3 queues (Voice, Video/Best-effort, Background).</p>
									<p><strong>besteffort:</strong> Single fair queue without DSCP prioritization.</p>
								</div>
							</InfoPopover>
						</Label>
						<Select.Root
							type="single"
							bind:value={diffserv}
						>
							<Select.Trigger class="h-9 text-xs">
								{formatDiffservLabel(diffserv)}
							</Select.Trigger>
							<Select.Content>
								<Select.Item value="diffserv4" class="text-xs">diffserv4 (Recommended: Gaming, Voice, Video)</Select.Item>
								<Select.Item value="diffserv3" class="text-xs">diffserv3 (3 Priority Queues)</Select.Item>
								<Select.Item value="besteffort" class="text-xs">besteffort (Single Queue)</Select.Item>
							</Select.Content>
						</Select.Root>
					</div>
				</div>

				<!-- Per-Host Isolation Toggle -->
				<div class="flex items-center justify-between rounded-xl border p-3.5 bg-muted/20">
					<div class="flex items-start gap-3">
						<div class="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-500 shrink-0 mt-0.5">
							<UsersIcon class="size-4" />
						</div>
						<div class="flex flex-col gap-0.5">
							<span class="text-xs font-semibold text-foreground">Per-Host Fair Bandwidth Sharing</span>
							<p class="text-[11px] text-muted-foreground leading-relaxed max-w-xl">
								Enables <code>nat dual-srchost / dual-dsthost</code> tracking. Ensures heavy downloads on one computer do not starve other family or homelab devices on your LAN.
							</p>
						</div>
					</div>
					<Switch
						bind:checked={perHostIsolation}
						aria-label="Per-Host Fair Bandwidth Sharing"
					/>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Advanced Kernel Parameters Collapsible -->
		<Collapsible.Root bind:open={advancedOpen} class="flex flex-col gap-2">
			<Card.Root>
				<Card.Header class="p-4 flex flex-row items-center justify-between">
					<div class="flex items-center gap-2">
						<SlidersIcon class="size-4 text-muted-foreground" />
						<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
							Advanced CAKE Parameters
						</span>
					</div>
					<Button
						variant="ghost"
						size="sm"
						onclick={() => (advancedOpen = !advancedOpen)}
						class="h-8 gap-1 text-xs text-muted-foreground hover:text-foreground"
					>
						<span>{advancedOpen ? "Collapse" : "Expand"}</span>
						{#if advancedOpen}
							<ChevronUpIcon class="size-3.5" />
						{:else}
							<ChevronDownIcon class="size-3.5" />
						{/if}
					</Button>
				</Card.Header>

				<Collapsible.Content class="px-4 pb-4 border-t pt-4">
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
						<!-- Target RTT -->
						<div class="flex flex-col gap-1.5">
							<Label for="sqm-rtt" class="text-xs font-semibold text-foreground">
								Target RTT (ms) · Optional
							</Label>
							<Input
								id="sqm-rtt"
								type="number"
								min="5"
								max="1000"
								bind:value={rttMs}
								placeholder="Default: 100ms (Auto)"
								class="h-9 text-xs font-mono"
							/>
							<span class="text-[11px] text-muted-foreground">
								Leave empty for standard Internet default (100ms), or set lower (e.g. 20ms) for direct fiber links.
							</span>
						</div>

						<!-- Ingress Virtual Device -->
						<div class="flex flex-col gap-1.5">
							<Label for="ingress-dev" class="text-xs font-semibold text-foreground">
								Virtual Ingress Device (IFB)
							</Label>
							<Input
								id="ingress-dev"
								type="text"
								bind:value={ingressDevice}
								placeholder="ifb4lanforge"
								class="h-9 text-xs font-mono"
							/>
							<span class="text-[11px] text-muted-foreground">
								Intermediate Functional Block interface created for download shaping.
							</span>
						</div>
					</div>
				</Collapsible.Content>
			</Card.Root>
		</Collapsible.Root>
	{:else}
		<div class="p-8 text-center text-muted-foreground text-xs flex flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-border/70 bg-muted/10">
			<GaugeIcon class="size-8 text-muted-foreground/40" />
			<span class="max-w-md">Smart Queue Management is currently disabled. Toggle the switch above to activate CAKE bufferbloat mitigation, configure bandwidth bounds, and view live queue latency telemetry.</span>
		</div>
	{/if}
</div>
