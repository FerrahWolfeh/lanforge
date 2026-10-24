<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Select from "$lib/components/ui/select";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import { toast } from "svelte-sonner";
	import { fly, scale } from "svelte/transition";
	import { cubicOut } from "svelte/easing";

	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import FloatingSaveBar from "$lib/components/FloatingSaveBar.svelte";

	import type {
		RouterPriority,
		RaPrefix,
		PrefixSource,
		NetworkInterfaceInfo,
		RaStatusResponse,
	} from "$lib/api/types";

	let {
		formEnabled = $bindable(true),
		formIface = $bindable("end0"),
		formManaged = $bindable(false),
		formOtherConfig = $bindable(false),
		formHopLimit = $bindable(64),
		formPriority = $bindable<RouterPriority>("medium"),
		formMaxInterval = $bindable(200),
		formMinInterval = $bindable<number | null>(null),
		formLifetime = $bindable<number | null>(null),
		formReachableTime = $bindable(0),
		formRetransTimer = $bindable(0),
		formMtu = $bindable<number | null>(null),
		formPrefixes = $bindable<RaPrefix[]>([]),
		formRdnss = $bindable<string[]>([]),
		formDnssl = $bindable<string[]>([]),
		interfaceOptions = [],
		status = null,
		isDirty = false,
		saving = false,
		onSave = async () => {},
		onDiscard = () => {},
	}: {
		formEnabled?: boolean;
		formIface?: string;
		formManaged?: boolean;
		formOtherConfig?: boolean;
		formHopLimit?: number;
		formPriority?: RouterPriority;
		formMaxInterval?: number;
		formMinInterval?: number | null;
		formLifetime?: number | null;
		formReachableTime?: number;
		formRetransTimer?: number;
		formMtu?: number | null;
		formPrefixes?: RaPrefix[];
		formRdnss?: string[];
		formDnssl?: string[];
		interfaceOptions?: NetworkInterfaceInfo[];
		status?: RaStatusResponse | null;
		isDirty?: boolean;
		saving?: boolean;
		onSave?: () => Promise<void>;
		onDiscard?: () => void;
	} = $props();

	// Local helper inputs
	let newPrefixStr = $state("");
	let newPrefixAutonomous = $state(true);
	let newPrefixOnLink = $state(true);
	let newRdnssAddr = $state("");
	let newDnsslDomain = $state("");

	function getPrefixKey(pref: RaPrefix, i: number): string {
		return `${i}-${pref.source}-${pref.address || "none"}-${pref.prefix_len || 64}`;
	}

	function formatPrefixLabel(p: RaPrefix): string {
		if (p.source === "auto_gua") {
			return `auto_gua (/${p.prefix_len || 64})`;
		}
		if (p.source === "ula") {
			return p.address
				? `${p.address}/${p.prefix_len || 64}`
				: `ula (/${p.prefix_len || 64})`;
		}
		return p.address
			? `${p.address}/${p.prefix_len || 64}`
			: `${p.source} (/${p.prefix_len || 64})`;
	}

	function addPrefix() {
		const raw = newPrefixStr.trim();
		if (!raw) {
			toast.error("Prefix subnet cannot be empty");
			return;
		}

		if (raw.toLowerCase() === "auto_gua" || raw.toLowerCase() === "dynamic_gua") {
			const isDuplicate = formPrefixes.some((x) => x.source === "auto_gua");
			if (isDuplicate) {
				toast.error("auto_gua is already configured");
				return;
			}
			formPrefixes = [
				...formPrefixes,
				{
					source: "auto_gua",
					address: null,
					prefix_len: 64,
					autonomous: newPrefixAutonomous,
					on_link: newPrefixOnLink,
					router_addr: true,
					valid_lifetime: 2592000,
					preferred_lifetime: 604800,
				},
			];
			newPrefixStr = "";
			return;
		}

		let formatted = raw;
		if (!formatted.includes("/")) {
			if (formatted.endsWith("::")) {
				formatted = `${formatted}/64`;
			} else {
				toast.error("Invalid prefix. Enter a subnet prefix (e.g. 2001:db8:1::/64), not a host IP address.");
				return;
			}
		}

		const [addrPart, lenPart] = formatted.split("/");
		const prefixLen = Number(lenPart);
		if (isNaN(prefixLen) || prefixLen < 1 || prefixLen > 64) {
			toast.error("Prefix length must be between /1 and /64 (/64 is required for standard SLAAC).");
			return;
		}

		if (!/^[0-9a-fA-F:]+$/.test(addrPart) || (addrPart.match(/::/g) || []).length > 1) {
			toast.error("Invalid IPv6 prefix format.");
			return;
		}

		if (prefixLen === 64 && !addrPart.endsWith("::")) {
			toast.error("A /64 subnet prefix must end with '::' (e.g. 2001:db8:1::/64).");
			return;
		}

		const isUla = addrPart.toLowerCase().startsWith("fd") || addrPart.toLowerCase().startsWith("fc");
		const source: PrefixSource = isUla ? "ula" : "static";
		const address = addrPart;

		const isDuplicate = formPrefixes.some((x) => {
			if (x.source !== source) return false;
			return (
				x.address?.toLowerCase() === address.toLowerCase() &&
				(x.prefix_len || 64) === prefixLen
			);
		});

		if (isDuplicate) {
			toast.error("Prefix already configured");
			return;
		}

		formPrefixes = [
			...formPrefixes,
			{
				source,
				address,
				prefix_len: prefixLen,
				autonomous: newPrefixAutonomous,
				on_link: newPrefixOnLink,
				router_addr: true,
				valid_lifetime: 2592000,
				preferred_lifetime: 604800,
			},
		];
		newPrefixStr = "";
	}

	function removePrefix(index: number) {
		formPrefixes = formPrefixes.filter((_, i) => i !== index);
	}

	function addRdnss() {
		const a = newRdnssAddr.trim();
		if (!a) {
			toast.error("DNS address cannot be empty");
			return;
		}
		if (formRdnss.includes(a)) {
			toast.error("DNS server already in list");
			return;
		}
		formRdnss = [...formRdnss, a];
		newRdnssAddr = "";
	}

	function removeRdnss(index: number) {
		formRdnss = formRdnss.filter((_, i) => i !== index);
	}

	function addDnssl() {
		const d = newDnsslDomain.trim().toLowerCase();
		if (!d) {
			toast.error("Domain cannot be empty");
			return;
		}
		if (formDnssl.includes(d)) {
			toast.error("Domain already in search list");
			return;
		}
		formDnssl = [...formDnssl, d];
		newDnsslDomain = "";
	}

	function removeDnssl(index: number) {
		formDnssl = formDnssl.filter((_, i) => i !== index);
	}
</script>

<div class="flex flex-col gap-6">
	<div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
		<!-- Left Column: Core Identity, Flags & Prefixes -->
		<div class="lg:col-span-7 flex flex-col gap-6">
			<!-- General Service Settings -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<Card.Title class="text-base font-semibold">Service & Operation</Card.Title>
					<Card.Description class="text-xs">
						Target network interface, operational toggle, and address auto-configuration modes.
					</Card.Description>
				</Card.Header>
				<Card.Content class="p-4 flex flex-col gap-4">
					<div class="flex items-center justify-between">
						<div class="flex flex-col gap-0.5">
							<Label class="text-xs font-semibold">Service Enabled</Label>
							<p class="text-[11px] text-muted-foreground">
								ICMPv6 listener and periodic broadcast engine.
							</p>
						</div>
						<Switch bind:checked={formEnabled} />
					</div>

					<Separator />

					<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
						<div class="flex flex-col gap-1.5">
							<Label class="text-xs font-semibold">Network Interface</Label>
							{#if interfaceOptions.length > 0}
								<Select.Root
									type="single"
									value={formIface}
									onValueChange={(val) => {
										if (val) formIface = val;
									}}
								>
									<Select.Trigger class="h-9 text-xs font-mono">
										{formIface || "Select interface..."}
									</Select.Trigger>
									<Select.Content>
										{#each interfaceOptions as iface (iface.name)}
											<Select.Item value={iface.name} class="text-xs">
												<div class="flex items-center justify-between w-full gap-3">
													<div class="flex items-center gap-2">
														<span class="font-mono font-medium">{iface.name}</span>
														{#if iface.carrier_up}
															<span class="size-1.5 rounded-full bg-emerald-500" title="Link active"></span>
														{:else}
															<span class="size-1.5 rounded-full bg-muted-foreground/40" title="Link down"></span>
														{/if}
													</div>
													<div class="flex items-center gap-1.5 text-[10px] text-muted-foreground">
														{#if iface.is_physical}
															<Badge variant="secondary" class="text-[9px] px-1 py-0 font-normal">Physical</Badge>
														{/if}
														{#if iface.ips && iface.ips.length > 0}
															<span class="truncate max-w-[110px] font-mono text-[10px]">{iface.ips[0]}</span>
														{/if}
													</div>
												</div>
											</Select.Item>
										{/each}
									</Select.Content>
								</Select.Root>
							{:else}
								<Input
									id="ra-iface"
									bind:value={formIface}
									placeholder="end0"
									class="h-9 font-mono text-xs"
								/>
							{/if}
							<p class="text-[11px] text-muted-foreground">
								LAN interface for raw ICMPv6 socket.
							</p>
						</div>

						<div class="flex flex-col gap-1.5">
							<Label class="text-xs font-semibold">Router Priority (RFC 4191)</Label>
							<Select.Root
								type="single"
								value={formPriority}
								onValueChange={(val) => {
									if (val) formPriority = val as RouterPriority;
								}}
							>
								<Select.Trigger class="h-9 text-xs capitalize">
									{formPriority}
								</Select.Trigger>
								<Select.Content>
									<Select.Item value="high" class="text-xs">High (Preferred Default)</Select.Item>
									<Select.Item value="medium" class="text-xs">Medium (Standard)</Select.Item>
									<Select.Item value="low" class="text-xs">Low (Secondary / Backup)</Select.Item>
								</Select.Content>
							</Select.Root>
							<p class="text-[11px] text-muted-foreground">
								Client default router preference.
							</p>
						</div>
					</div>

					<Separator />

					<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
						<div class="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/20">
							<div class="flex items-center gap-1.5 min-w-0">
								<Label class="text-xs font-semibold">Managed (M-Flag)</Label>
								<InfoPopover
									title="M-Flag (Managed Address Configuration)"
									text="RFC 4861. Instructs hosts to use stateful DHCPv6 for acquiring IPv6 addresses rather than autonomous SLAAC."
								/>
							</div>
							<Switch bind:checked={formManaged} />
						</div>

						<div class="flex items-center justify-between gap-3 p-3 rounded-lg border bg-muted/20">
							<div class="flex items-center gap-1.5 min-w-0">
								<Label class="text-xs font-semibold">Other Config (O-Flag)</Label>
								<InfoPopover
									title="O-Flag (Other Stateful Configuration)"
									text="RFC 4861. Instructs hosts to use stateless DHCPv6 for other configuration information, such as DNS and NTP servers."
								/>
							</div>
							<Switch bind:checked={formOtherConfig} />
						</div>
					</div>
				</Card.Content>
			</Card.Root>

			<!-- Prefix Information Options (PIO) Manager -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<Card.Title class="text-base font-semibold">Prefix Information Options (PIO)</Card.Title>
					<Card.Description class="text-xs">
						Static and custom announced IPv6 prefixes. Dynamic GUA (<span class="font-mono text-foreground font-semibold">auto_gua</span>) and ULA (<span class="font-mono text-foreground font-semibold">auto_ula</span>) are automatically managed when enabled.
					</Card.Description>
				</Card.Header>
				<Card.Content class="p-4 flex flex-col gap-4">
					<div class="flex flex-col gap-2.5 p-3 rounded-lg border bg-muted/30">
						<div class="flex flex-col sm:flex-row items-end gap-3">
							<div class="flex-1 flex flex-col gap-1.5 w-full">
								<Label for="new-prefix" class="text-xs font-medium">Add Custom Subnet Prefix</Label>
								<Input
									id="new-prefix"
									bind:value={newPrefixStr}
									placeholder="2001:db8:1::/64 or fd00:cafe::/64"
									class="h-9 font-mono text-xs"
									onkeydown={(e) => e.key === "Enter" && addPrefix()}
								/>
								<p class="text-[11px] text-muted-foreground">
									Enter an IPv6 prefix ending with <code class="font-mono text-primary font-semibold">::/64</code> (e.g. <code class="font-mono text-foreground">2001:db8:1::/64</code>). Host addresses are rejected.
								</p>
							</div>

							<div class="flex items-center gap-3">
								<div class="flex items-center gap-1.5">
									<Switch id="auto-slaac" bind:checked={newPrefixAutonomous} />
									<Label for="auto-slaac" class="text-xs">SLAAC (A)</Label>
									<InfoPopover
										title="Autonomous Address (A-Flag)"
										text="RFC 4861. Allows clients to autonomously generate IPv6 addresses using this prefix."
									/>
								</div>
								<div class="flex items-center gap-1.5">
									<Switch id="on-link" bind:checked={newPrefixOnLink} />
									<Label for="on-link" class="text-xs">On-link (L)</Label>
									<InfoPopover
										title="On-Link (L-Flag)"
										text="RFC 4861. Indicates that this prefix can be used for on-link determination."
									/>
								</div>
							</div>

							<Button
								size="sm"
								variant="secondary"
								onclick={addPrefix}
								class="h-9 gap-1 shrink-0"
							>
								<PlusIcon class="size-3.5" />
								Add
							</Button>
						</div>
					</div>

					<div class="rounded-md border overflow-x-auto">
						<Table.Root class="min-w-[500px]">
							<Table.Header class="bg-muted/40">
								<Table.Row>
									<Table.Head>Prefix</Table.Head>
									<Table.Head class="w-[100px]">SLAAC (A)</Table.Head>
									<Table.Head class="w-[100px]">On-Link (L)</Table.Head>
									<Table.Head class="text-right w-[60px]">Action</Table.Head>
								</Table.Row>
							</Table.Header>
							<Table.Body class="font-mono text-xs">
								{#if formPrefixes.length === 0}
									<Table.Row>
										<Table.Cell colspan={4} class="text-center text-xs text-muted-foreground py-6">
											No prefixes defined. RA daemon will stay idle.
										</Table.Cell>
									</Table.Row>
								{:else}
									{#each formPrefixes as pref, i (getPrefixKey(pref, i))}
										<Table.Row>
											<Table.Cell class="font-mono text-xs font-medium">
												{formatPrefixLabel(pref)}
											</Table.Cell>
											<Table.Cell>
												<Switch
													checked={pref.autonomous ?? true}
													onCheckedChange={(c) => (pref.autonomous = c)}
												/>
											</Table.Cell>
											<Table.Cell>
												<Switch
													checked={pref.on_link ?? true}
													onCheckedChange={(c) => (pref.on_link = c)}
												/>
											</Table.Cell>
											<Table.Cell class="text-right">
												<Button
													variant="ghost"
													size="icon"
													class="size-8 text-destructive hover:text-destructive"
													onclick={() => removePrefix(i)}
												>
													<Trash2Icon class="size-4" />
												</Button>
											</Table.Cell>
										</Table.Row>
									{/each}
								{/if}
							</Table.Body>
						</Table.Root>
					</div>
				</Card.Content>
			</Card.Root>
		</div>

		<!-- Right Column: Timers & DNS -->
		<div class="lg:col-span-5 flex flex-col gap-6">
			<!-- Timing & Intervals -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<Card.Title class="text-base font-semibold">Timing & Intervals</Card.Title>
					<Card.Description class="text-xs">
						Broadcast cadence, router lifetime, and interface parameters.
					</Card.Description>
				</Card.Header>
				<Card.Content class="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3.5">
					<div class="flex flex-col gap-1.5">
						<Label for="ra-max-interval" class="text-xs font-medium">Max Adv Interval (s)</Label>
						<Input
							id="ra-max-interval"
							type="number"
							min="4"
							max="1800"
							bind:value={formMaxInterval}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">Default 200s.</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="ra-min-interval" class="text-xs font-medium">Min Adv Interval (s)</Label>
						<Input
							id="ra-min-interval"
							type="number"
							min="3"
							placeholder="Auto (~66s)"
							value={formMinInterval ?? ""}
							oninput={(e) => {
								const val = e.currentTarget.value;
								formMinInterval = val ? Number(val) : null;
							}}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">1/3 of max interval.</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="ra-lifetime" class="text-xs font-medium">Router Lifetime (s)</Label>
						<Input
							id="ra-lifetime"
							type="number"
							min="0"
							max="9000"
							placeholder="Auto (3x max)"
							value={formLifetime ?? ""}
							oninput={(e) => {
								const val = e.currentTarget.value;
								formLifetime = val ? Number(val) : null;
							}}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">0 = non-default router.</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="ra-hop-limit" class="text-xs font-medium">Suggested Hop Limit</Label>
						<Input
							id="ra-hop-limit"
							type="number"
							min="0"
							max="255"
							bind:value={formHopLimit}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">Default 64.</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="ra-mtu" class="text-xs font-medium">Advertised MTU</Label>
						<Input
							id="ra-mtu"
							type="number"
							min="1280"
							max="9000"
							placeholder="Interface MTU"
							value={formMtu ?? ""}
							oninput={(e) => {
								const val = e.currentTarget.value;
								formMtu = val ? Number(val) : null;
							}}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">E.g. 1492 for PPPoE.</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="ra-reachable" class="text-xs font-medium">Reachable Time (ms)</Label>
						<Input
							id="ra-reachable"
							type="number"
							min="0"
							bind:value={formReachableTime}
							class="h-9 font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">0 = unspecified.</p>
					</div>
				</Card.Content>
			</Card.Root>

			<!-- DNS Servers (RDNSS) -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<Card.Title class="text-base font-semibold">Recursive DNS (RDNSS)</Card.Title>
					<Card.Description class="text-xs">
						IPv6 DNS nameservers advertised directly via RA.
					</Card.Description>
				</Card.Header>
				<Card.Content class="p-4 flex flex-col gap-3">
					<div class="flex gap-2">
						<Input
							bind:value={newRdnssAddr}
							placeholder="2001:4860:4860::8888 or fe80::1"
							class="h-9 font-mono text-xs"
							onkeydown={(e) => e.key === "Enter" && addRdnss()}
						/>
						<Button
							size="sm"
							variant="secondary"
							onclick={addRdnss}
							class="h-9 gap-1"
						>
							<PlusIcon class="size-3.5" />
							Add
						</Button>
					</div>

					<div class="flex flex-wrap gap-1.5 pt-1">
						{#if formRdnss.length === 0}
							<span class="text-xs text-muted-foreground italic">No specific servers added.</span>
						{:else}
							{#each formRdnss as addr, i (`form-rdnss-${i}-${addr}`)}
								<Badge variant="secondary" class="font-mono text-xs flex items-center gap-1.5 py-1">
									<span>{addr}</span>
									<button
										type="button"
										class="text-muted-foreground hover:text-destructive transition-colors ml-1 cursor-pointer"
										onclick={() => removeRdnss(i)}
									>
										&times;
									</button>
								</Badge>
							{/each}
						{/if}
					</div>
				</Card.Content>
			</Card.Root>

			<!-- Domain Search List (DNSSL) -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<Card.Title class="text-base font-semibold">Domain Search List (DNSSL)</Card.Title>
					<Card.Description class="text-xs">
						DNS search suffix domains distributed to IPv6 clients.
					</Card.Description>
				</Card.Header>
				<Card.Content class="p-4 flex flex-col gap-3">
					<div class="flex gap-2">
						<Input
							bind:value={newDnsslDomain}
							placeholder="lan or home.arpa"
							class="h-9 font-mono text-xs"
							onkeydown={(e) => e.key === "Enter" && addDnssl()}
						/>
						<Button
							size="sm"
							variant="secondary"
							onclick={addDnssl}
							class="h-9 gap-1"
						>
							<PlusIcon class="size-3.5" />
							Add
						</Button>
					</div>

					<div class="flex flex-wrap gap-1.5 pt-1">
						{#if formDnssl.length === 0}
							<span class="text-xs text-muted-foreground italic">No search domains added.</span>
						{:else}
							{#each formDnssl as dom, i (`form-dnssl-${i}-${dom}`)}
								<Badge variant="outline" class="text-xs flex items-center gap-1.5 py-1">
									<span>{dom}</span>
									<button
										type="button"
										class="text-muted-foreground hover:text-destructive transition-colors ml-1 cursor-pointer"
										onclick={() => removeDnssl(i)}
									>
										&times;
									</button>
								</Badge>
							{/each}
						{/if}
					</div>
				</Card.Content>
			</Card.Root>
		</div>
	</div>

	<!-- Floating Save/Discard Action Island -->
	<FloatingSaveBar
		show={isDirty}
		title="Unsaved RA Changes"
		description="Configuration differs from active runtime parameters"
		saveLabel="Save Configuration"
		savingLabel="Applying..."
		{saving}
		onDiscard={onDiscard}
		onSave={onSave}
	/>
</div>
