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

	import type { SqmOverhead, SqmDiffserv, NetworkInterfaceInfo } from "$lib/api/types";

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
	<!-- Master Enable Switch Card -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<Card.Title class="text-base font-semibold">Smart Queue Management (CAKE)</Card.Title>
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
				<Badge variant={enabled ? "default" : "secondary"} class="text-xs">
					{enabled ? "Enabled" : "Disabled"}
				</Badge>
			</div>
			<Card.Description class="text-xs">
				Maintains low ping and prevents network lag spikes during intensive uploads or downloads.
			</Card.Description>
		</Card.Header>
		<Card.Content class="p-4 flex flex-col gap-5">
			<div class="flex items-center justify-between rounded-xl border p-3.5 bg-muted/20">
				<div class="flex flex-col gap-0.5">
					<Label class="text-xs font-semibold">Enable SQM Shaper</Label>
					<p class="text-[11px] text-muted-foreground">
						When enabled, Lanforge attaches CAKE qdiscs to your WAN interface and IFB ingress mirror device.
					</p>
				</div>
				<Switch
					bind:checked={enabled}
					aria-label="Enable SQM Shaper"
				/>
			</div>
		</Card.Content>
	</Card.Root>

	{#if enabled}
		<!-- Bandwidth & Interface Configuration -->
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<Card.Title class="text-base font-semibold">Bandwidth Limits & Target WAN</Card.Title>
				<Card.Description class="text-xs">
					Set bandwidth shaping limits to 90–95% of your measured connection speed to maintain queue authority.
				</Card.Description>
			</Card.Header>
			<Card.Content class="p-4 flex flex-col gap-5">
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
	{/if}
</div>
