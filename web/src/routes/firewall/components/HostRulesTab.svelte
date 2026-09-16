<script lang="ts">
	import * as Tabs from "$lib/components/ui/tabs";
	import * as Table from "$lib/components/ui/table";
	import * as Card from "$lib/components/ui/card";
	import * as ToggleGroup from "$lib/components/ui/toggle-group";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import TrashIcon from "@lucide/svelte/icons/trash-2";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import InfoIcon from "@lucide/svelte/icons/info";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import type { FirewallZone, HostPortRule, PortForwardRule, L4Protocol } from "$lib/api/types";

	interface Props {
		zones: FirewallZone[];
		portForwards: PortForwardRule[];
		onZonesUpdate: (zones: FirewallZone[]) => void;
		onPortForwardsUpdate: (rules: PortForwardRule[]) => void;
	}

	let { zones, portForwards, onZonesUpdate, onPortForwardsUpdate }: Props = $props();

	let innerTab = $state("router-ports");

	// Inline add state for host ports
	let addingZone = $state<string | null>(null);
	let newPort = $state<number | "">(22);
	let newProto = $state<L4Protocol>("Tcp");
	let newComment = $state("");

	// Inline add state for IPv6 Pinholes
	let addingPinhole = $state(false);
	let pinholeIp = $state("");
	let pinholeExtPort = $state<number | "">(80);
	let pinholeIntPort = $state<number | "">(80);
	let pinholeProto = $state<L4Protocol>("Tcp");
	let pinholeComment = $state("");

	// IPv6 rules are those where internal_ip contains ":"
	const ipv6Pinholes = $derived(
		portForwards
			.map((rule, originalIndex) => ({ rule, originalIndex }))
			.filter(({ rule }) => rule.internal_ip.includes(":"))
	);

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

	function handleAddPinhole() {
		if (
			!pinholeIp.trim() ||
			typeof pinholeExtPort !== "number" ||
			pinholeExtPort < 1 ||
			pinholeExtPort > 65535 ||
			typeof pinholeIntPort !== "number" ||
			pinholeIntPort < 1 ||
			pinholeIntPort > 65535
		) {
			return;
		}

		const newRule: PortForwardRule = {
			comment: pinholeComment.trim() || null,
			src_zone: "external",
			internal_ip: pinholeIp.trim(),
			external_port: pinholeExtPort,
			internal_port: pinholeIntPort,
			protocol: pinholeProto,
			enable_hairpin: false,
		};

		onPortForwardsUpdate([...portForwards, newRule]);
		addingPinhole = false;
		pinholeIp = "";
		pinholeExtPort = 80;
		pinholeIntPort = 80;
		pinholeComment = "";
	}

	function handleRemovePinhole(originalIndex: number) {
		onPortForwardsUpdate(portForwards.filter((_, i) => i !== originalIndex));
	}
</script>

<div class="flex flex-col gap-4">
	<!-- Actions row with HelpPopover -->
	<div class="flex items-center justify-between">
		<div>
			<div class="flex items-center gap-2">
				<h3 class="text-sm font-semibold tracking-tight text-foreground">Host Rules & Access Control</h3>
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
							<strong class="text-foreground">IPv6 Pinholes:</strong> Open routed inbound ports directly to globally-routable IPv6 addresses on your LAN without NAT.
						</p>
					</div>
				</HelpPopover>
			</div>
			<p class="text-xs text-muted-foreground">Manage local router listening ports and routed IPv6 pinholes.</p>
		</div>
	</div>

	<Tabs.Root bind:value={innerTab} class="w-full">
		<Tabs.List class="w-full sm:w-auto p-1 mb-2">
			<Tabs.Trigger value="router-ports">Router Ports (Host)</Tabs.Trigger>
			<Tabs.Trigger value="ipv6-pinholes">IPv6 Pinholes</Tabs.Trigger>
		</Tabs.List>

		<!-- Tab 1: Router Host Ports -->
		<Tabs.Content value="router-ports" class="flex flex-col gap-4">
			<div class="flex items-center gap-2 text-xs text-muted-foreground bg-muted/40 rounded-xl p-3 border border-border">
				<InfoIcon class="size-4 shrink-0 text-primary" />
				<span>
					Open ports for direct inbound access to router host services (SSH, WebUI, DNS). Rules managed dynamically by daemons are badged accordingly.
				</span>
			</div>

			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				{#each zones as zone (zone.name)}
					<Card.Root>
						<Card.Header class="pb-3">
							<div class="flex items-center justify-between">
								<div class="flex items-center gap-2">
									<Card.Title class="text-sm font-semibold capitalize font-mono">
										{zone.name}
									</Card.Title>
									<Badge variant="outline" class="text-[10px]">
										{zone.open_ports.length} {zone.open_ports.length === 1 ? "port" : "ports"}
									</Badge>
								</div>
								{#if addingZone !== zone.name}
									<Button
										variant="outline"
										size="sm"
										class="h-7 text-xs"
										onclick={() => {
											addingZone = zone.name;
											newPort = 22;
											newComment = "";
										}}
									>
										<PlusIcon data-icon="inline-start" />
										Add Port
									</Button>
								{/if}
							</div>
						</Card.Header>

						<Card.Content class="flex flex-col gap-3">
							<!-- Static ports list -->
							{#if zone.open_ports.length === 0 && addingZone !== zone.name}
								<p class="text-xs text-muted-foreground italic">No static host ports configured.</p>
							{:else}
								<div class="flex flex-col gap-1.5">
									{#each zone.open_ports as portRule, pIndex (pIndex)}
										<div class="flex items-center justify-between gap-2 rounded-md bg-muted/40 px-2.5 py-1.5 text-xs border border-border">
											<div class="flex items-center gap-2">
												<span class="font-mono font-semibold text-foreground">{portRule.port}</span>
												<Badge variant="outline" class="text-[10px] uppercase font-mono px-1 py-0">
													{portRule.protocol}
												</Badge>
												{#if portRule.comment}
													<span class="text-muted-foreground truncate max-w-[140px] text-[11px]">
														{portRule.comment}
													</span>
												{/if}
											</div>
											<Button
												variant="ghost"
												size="icon"
												class="size-6 text-muted-foreground hover:text-destructive cursor-pointer"
												onclick={() => handleRemovePort(zone.name, pIndex)}
												aria-label="Remove port"
											>
												<TrashIcon class="size-3" />
												<span class="sr-only">Remove</span>
											</Button>
										</div>
									{/each}
								</div>
							{/if}

							<!-- Inline Add Form -->
							{#if addingZone === zone.name}
								<div class="flex flex-col gap-2 rounded-lg border border-primary/30 bg-primary/5 p-2.5">
									<div class="grid grid-cols-2 gap-2">
										<div>
											<label class="text-[10px] text-muted-foreground block mb-0.5" for="new-port-{zone.name}">Port</label>
											<Input
												id="new-port-{zone.name}"
												type="number"
												min="1"
												max="65535"
												bind:value={newPort}
												placeholder="22"
												class="h-7 text-xs font-mono"
											/>
										</div>
										<div>
											<span class="text-[10px] text-muted-foreground block mb-0.5">Protocol</span>
											<ToggleGroup.Root
												type="single"
												bind:value={newProto}
												variant="outline"
												size="sm"
												class="h-7 w-full"
											>
												<ToggleGroup.Item value="Tcp" class="flex-1 text-[10px] px-1">TCP</ToggleGroup.Item>
												<ToggleGroup.Item value="Udp" class="flex-1 text-[10px] px-1">UDP</ToggleGroup.Item>
												<ToggleGroup.Item value="Both" class="flex-1 text-[10px] px-1">Both</ToggleGroup.Item>
											</ToggleGroup.Root>
										</div>
									</div>
									<Input
										bind:value={newComment}
										placeholder="Comment (optional)"
										class="h-7 text-xs"
									/>
									<div class="flex items-center justify-end gap-1.5 pt-1">
										<Button
											variant="outline"
											size="sm"
											class="h-6 text-xs px-2"
											onclick={() => (addingZone = null)}
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
		</Tabs.Content>

		<!-- Tab 2: IPv6 Pinholes -->
		<Tabs.Content value="ipv6-pinholes" class="flex flex-col gap-4">
			<div class="flex items-center justify-between">
				<div>
					<h3 class="text-sm font-semibold tracking-tight text-foreground">IPv6 Pinholes</h3>
					<p class="text-xs text-muted-foreground">
						Inbound traffic pinholes for specific global IPv6 addresses (routed directly without NAT).
					</p>
				</div>
				{#if !addingPinhole}
					<Button size="sm" onclick={() => (addingPinhole = true)}>
						<PlusIcon data-icon="inline-start" />
						Add Pinhole
					</Button>
				{/if}
			</div>

			<!-- Inline Add Pinhole Form -->
			{#if addingPinhole}
				<div class="rounded-xl border border-primary/30 bg-card p-4 flex flex-col gap-3 shadow-xs">
					<h4 class="text-xs font-semibold text-foreground">New IPv6 Pinhole</h4>
					<div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
						<div class="col-span-1 sm:col-span-2">
							<label class="text-[11px] text-muted-foreground block mb-1" for="pinhole-ip">Global IPv6 Address (GUA)</label>
							<Input
								id="pinhole-ip"
								bind:value={pinholeIp}
								placeholder="2001:db8::10"
								class="font-mono text-xs"
							/>
						</div>
						<div>
							<label class="text-[11px] text-muted-foreground block mb-1" for="pinhole-ext-port">External Port</label>
							<Input
								id="pinhole-ext-port"
								type="number"
								min="1"
								max="65535"
								bind:value={pinholeExtPort}
								class="font-mono text-xs"
							/>
						</div>
						<div>
							<label class="text-[11px] text-muted-foreground block mb-1" for="pinhole-int-port">Internal Port</label>
							<Input
								id="pinhole-int-port"
								type="number"
								min="1"
								max="65535"
								bind:value={pinholeIntPort}
								class="font-mono text-xs"
							/>
						</div>
					</div>
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-3 items-center">
						<Input
							bind:value={pinholeComment}
							placeholder="Comment (e.g. IPv6 Web Server)"
							class="text-xs"
						/>
						<ToggleGroup.Root
							type="single"
							bind:value={pinholeProto}
							variant="outline"
							class="w-full h-9"
						>
							<ToggleGroup.Item value="Tcp" class="flex-1 text-xs">TCP</ToggleGroup.Item>
							<ToggleGroup.Item value="Udp" class="flex-1 text-xs">UDP</ToggleGroup.Item>
							<ToggleGroup.Item value="Both" class="flex-1 text-xs">Both</ToggleGroup.Item>
						</ToggleGroup.Root>
					</div>
					<div class="flex items-center justify-end gap-2 pt-1">
						<Button variant="outline" size="sm" onclick={() => (addingPinhole = false)}>
							Cancel
						</Button>
						<Button size="sm" onclick={handleAddPinhole}>
							Add Pinhole
						</Button>
					</div>
				</div>
			{/if}

			<!-- IPv6 pinholes table -->
			{#if ipv6Pinholes.length === 0}
				<div class="rounded-xl border border-dashed p-8 text-center text-xs text-muted-foreground">
					No IPv6 pinholes configured. Pinholes allow inbound traffic to specific global IPv6 addresses without NAT rewriting.
				</div>
			{:else}
				<div class="rounded-xl border border-border overflow-hidden bg-card">
					<Table.Root>
						<Table.Header>
							<Table.Row class="bg-muted/40 text-xs">
								<Table.Head>Comment</Table.Head>
								<Table.Head>Protocol</Table.Head>
								<Table.Head>External Port</Table.Head>
								<Table.Head>IPv6 Destination</Table.Head>
								<Table.Head>Internal Port</Table.Head>
								<Table.Head class="w-16 text-right">Action</Table.Head>
							</Table.Row>
						</Table.Header>
						<Table.Body>
							{#each ipv6Pinholes as { rule, originalIndex } (originalIndex)}
								<Table.Row class="text-xs">
									<Table.Cell class="font-medium text-foreground">
										{rule.comment || "—"}
									</Table.Cell>
									<Table.Cell>
										<Badge variant="outline" class="font-mono text-[11px]">
											{rule.protocol}
										</Badge>
									</Table.Cell>
									<Table.Cell>
										<span class="font-mono font-semibold">{rule.external_port}</span>
									</Table.Cell>
									<Table.Cell>
										<span class="font-mono text-muted-foreground">{rule.internal_ip}</span>
									</Table.Cell>
									<Table.Cell>
										<span class="font-mono font-semibold">{rule.internal_port}</span>
									</Table.Cell>
									<Table.Cell class="text-right">
										<Button
											variant="ghost"
											size="icon"
											class="size-8 text-destructive hover:bg-destructive/10 hover:text-destructive cursor-pointer"
											onclick={() => handleRemovePinhole(originalIndex)}
											aria-label="Remove pinhole"
										>
											<TrashIcon class="size-3.5" />
											<span class="sr-only">Remove</span>
										</Button>
									</Table.Cell>
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				</div>
			{/if}
		</Tabs.Content>
	</Tabs.Root>
</div>
