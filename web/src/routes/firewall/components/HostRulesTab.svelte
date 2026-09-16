<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as ToggleGroup from "$lib/components/ui/toggle-group";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import TrashIcon from "@lucide/svelte/icons/trash-2";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import InfoIcon from "@lucide/svelte/icons/info";
	import ArrowLeftRightIcon from "@lucide/svelte/icons/arrow-left-right";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import type { FirewallZone, HostPortRule, L4Protocol } from "$lib/api/types";

	interface Props {
		zones: FirewallZone[];
		onZonesUpdate: (zones: FirewallZone[]) => void;
	}

	let { zones, onZonesUpdate }: Props = $props();

	// Inline add state for host ports
	let addingZone = $state<string | null>(null);
	let newPort = $state<number | "">(22);
	let newProto = $state<L4Protocol>("Tcp");
	let newComment = $state("");

	function handleAddPort(zoneName: string) {
		if (typeof newPort !== "number" || newPort < 1 || newPort > 65535) return;
		const portNumber = newPort;
		const updatedZones = zones.map((z) => {
			if (z.name !== zoneName) return z;
			const newRule: HostPortRule = {
				port: portNumber,
				protocol: newProto,
				comment: newComment.trim() ? newComment.trim() : null,
			};
			return { ...z, open_ports: [...z.open_ports, newRule] };
		});
		onZonesUpdate(updatedZones);
		addingZone = null;
		newPort = 22;
		newComment = "";
	}

	function handleRemovePort(zoneName: string, portIndex: number) {
		const updatedZones = zones.map((z) => {
			if (z.name !== zoneName) return z;
			return { ...z, open_ports: z.open_ports.filter((_, i) => i !== portIndex) };
		});
		onZonesUpdate(updatedZones);
	}
</script>

<div class="flex flex-col gap-4">
	<!-- Header row with HelpPopover -->
	<div class="flex items-center justify-between">
		<div>
			<div class="flex items-center gap-2">
				<h3 class="text-sm font-semibold tracking-tight text-foreground">Router Host Rules</h3>
				<HelpPopover
					title="Router Host Rules Guide"
					description="How inbound connections to services running on the Lanforge router itself are controlled."
				>
					<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
						<p>
							<strong class="text-foreground">Host Rules vs Port Forwarding:</strong> Host Rules open ports for services running on the router hardware itself (e.g. SSH on port 22, WebUI on port 8080, DNS on port 53). Port Forwarding redirects traffic through the router to another machine on your LAN.
						</p>
						<p>
							<strong class="text-foreground">Zone Policies:</strong> If a zone's Input Policy is <em>Accept</em> (like LAN), all router ports are accessible. If Input Policy is <em>Drop</em> (like WAN/External), only the ports explicitly listed here will be accepted.
						</p>
						<p>
							<strong class="text-foreground">Looking for LAN Devices?</strong> To open ports for PCs or servers on your home network (via IPv4 DNAT or IPv6 Pinhole), use the <em>Port Forwarding</em> tab.
						</p>
					</div>
				</HelpPopover>
			</div>
			<p class="text-xs text-muted-foreground">Manage listening ports and ingress access directly to the router hardware.</p>
		</div>
	</div>

	<!-- Informational banner -->
	<div class="flex items-center justify-between gap-3 text-xs text-muted-foreground bg-muted/40 rounded-xl p-3 border border-border">
		<div class="flex items-center gap-2">
			<InfoIcon class="size-4 shrink-0 text-primary" />
			<span>
				Open ports for direct inbound access to router host services (SSH, WebUI, DNS). Rules managed dynamically by daemons are badged accordingly.
			</span>
		</div>
		<div class="hidden sm:flex items-center gap-1 shrink-0 text-[11px] text-muted-foreground">
			<ArrowLeftRightIcon class="size-3.5" />
			<span>Opening ports for LAN devices? Use <strong>Port Forwarding</strong></span>
		</div>
	</div>

	<!-- Zone cards grid -->
	<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
		{#each zones as zone (zone.name)}
			<Card.Root>
				<Card.Header class="pb-3">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<Card.Title class="text-sm font-semibold capitalize font-mono">
								{zone.name}
							</Card.Title>
							<Badge
								variant={zone.input_policy === "Accept" ? "default" : "outline"}
								class="text-[10px] uppercase font-mono"
							>
								Input: {zone.input_policy}
							</Badge>
						</div>
						{#if addingZone !== zone.name}
							<Button
								variant="outline"
								size="sm"
								class="h-7 text-xs gap-1"
								onclick={() => {
									addingZone = zone.name;
									newPort = 22;
									newComment = "";
								}}
							>
								<PlusIcon class="size-3" />
								Open Port
							</Button>
						{/if}
					</div>
					<Card.Description class="text-xs text-muted-foreground">
						{zone.interfaces.length > 0 ? zone.interfaces.join(", ") : "No interfaces assigned"}
					</Card.Description>
				</Card.Header>

				<Card.Content class="flex flex-col gap-2.5">
					<!-- Static open ports list -->
					{#if zone.open_ports.length === 0}
						<p class="text-xs text-muted-foreground italic py-1">
							No static ports opened for this zone.
						</p>
					{:else}
						<div class="flex flex-col gap-1.5">
							{#each zone.open_ports as rule, index (index)}
								<div class="flex items-center justify-between text-xs py-1 px-2 rounded-md bg-muted/50 border border-border/50">
									<div class="flex items-center gap-2">
										<span class="font-mono font-semibold text-foreground">{rule.port}</span>
										<Badge variant="outline" class="text-[10px] font-mono uppercase">
											{rule.protocol}
										</Badge>
										{#if rule.comment}
											<span class="text-muted-foreground truncate max-w-[140px]">{rule.comment}</span>
										{/if}
									</div>
									<Button
										variant="ghost"
										size="icon"
										class="size-6 text-muted-foreground hover:text-destructive"
										onclick={() => handleRemovePort(zone.name, index)}
										aria-label="Remove port"
									>
										<TrashIcon class="size-3" />
									</Button>
								</div>
							{/each}
						</div>
					{/if}

					<!-- Inline Add Form -->
					{#if addingZone === zone.name}
						<div class="flex flex-col gap-2 p-2.5 rounded-lg border border-primary/30 bg-primary/5 mt-1">
							<span class="text-xs font-semibold text-foreground">Open New Port</span>
							<div class="grid grid-cols-2 gap-2">
								<div>
									<label class="text-[10px] text-muted-foreground block mb-0.5" for={`port-${zone.name}`}>Port Number</label>
									<Input
										id={`port-${zone.name}`}
										type="number"
										min="1"
										max="65535"
										bind:value={newPort}
										class="h-7 text-xs font-mono"
									/>
								</div>
								<div>
									<span class="text-[10px] text-muted-foreground block mb-0.5">Protocol</span>
									<ToggleGroup.Root
										type="single"
										bind:value={newProto}
										variant="outline"
										class="w-full h-7"
									>
										<ToggleGroup.Item value="Tcp" class="flex-1 text-[10px] h-7 px-1">TCP</ToggleGroup.Item>
										<ToggleGroup.Item value="Udp" class="flex-1 text-[10px] h-7 px-1">UDP</ToggleGroup.Item>
										<ToggleGroup.Item value="Both" class="flex-1 text-[10px] h-7 px-1">Both</ToggleGroup.Item>
									</ToggleGroup.Root>
								</div>
							</div>
							<div>
								<label class="text-[10px] text-muted-foreground block mb-0.5" for={`comment-${zone.name}`}>Comment</label>
								<Input
									id={`comment-${zone.name}`}
									type="text"
									placeholder="e.g. SSH custom, Metrics"
									bind:value={newComment}
									class="h-7 text-xs"
								/>
							</div>
							<div class="flex justify-end gap-1.5 pt-1">
								<Button
									variant="ghost"
									size="sm"
									class="h-6 text-xs px-2"
									onclick={() => { addingZone = null; }}
								>
									Cancel
								</Button>
								<Button
									size="sm"
									class="h-6 text-xs px-2"
									onclick={() => handleAddPort(zone.name)}
								>
									Save
								</Button>
							</div>
						</div>
					{/if}

					<!-- Dynamic service badges -->
					{#if zone.name === "internal" || zone.name === "trusted"}
						<div class="pt-2 border-t border-border flex flex-wrap items-center gap-1.5">
							<span class="text-[10px] text-muted-foreground w-full">Daemon dynamic ports:</span>
							<Badge variant="secondary" class="text-[10px] gap-1 font-mono">
								<ShieldCheckIcon class="size-2.5 text-emerald-500" />
								DNS · 53 (udp/tcp)
							</Badge>
							<Badge variant="secondary" class="text-[10px] gap-1 font-mono">
								<ShieldCheckIcon class="size-2.5 text-emerald-500" />
								WebUI · 8080/443 (tcp)
							</Badge>
						</div>
					{/if}
				</Card.Content>
			</Card.Root>
		{/each}
	</div>
</div>
