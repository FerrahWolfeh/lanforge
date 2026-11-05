<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import * as Select from "$lib/components/ui/select";
	import * as ToggleGroup from "$lib/components/ui/toggle-group";
	import * as Field from "$lib/components/ui/field";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import { Label } from "$lib/components/ui/label";
	import DeviceCombobox from "$lib/components/DeviceCombobox.svelte";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ShuffleIcon from "@lucide/svelte/icons/shuffle";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import { toast } from "svelte-sonner";
	import { cn } from "$lib/utils";
	import { untrack } from "svelte";
	import type { PortForwardRule, L4Protocol, DeviceEntry } from "$lib/api/types";
	import { z } from "zod";
	import { validateForm, ipv4Schema, ipv6Schema, portNumberSchema } from "$lib/utils/validation";

	let {
		open = $bindable(false),
		zones,
		rule,
		onSave,
		onClose,
	}: {
		open: boolean;
		zones: string[];
		rule: PortForwardRule | null;
		onSave: (rule: PortForwardRule | PortForwardRule[]) => void;
		onClose: () => void;
	} = $props();

	// ── Form state ────────────────────────────────────────────────────────────
	let comment = $state("");
	let protocol = $state<L4Protocol>("Tcp");
	let srcZone = $state("");
	let externalPort = $state<number | "">(80);
	let internalPort = $state<number | "">(80);
	let internalIp = $state("");
	let internalIpv6 = $state("");
	let ipMode = $state<"v4" | "v6" | "dual">("v4");
	let selectedDevice = $state<DeviceEntry | null>(null);
	/** `dev:<name|mac>` when the rule targets a device (follows its addresses), else null. */
	let deviceTarget = $state<string | null>(null);
	let enableHairpin = $state(false);
	let devicePickerSearch = $state("");
	let prevOpen = $state(false);
	let prevRule = $state<PortForwardRule | null>(null);

	// ── Validation errors ─────────────────────────────────────────────────────
	let errors = $state<Record<string, string>>({});

	// ── Preset templates ──────────────────────────────────────────────────────
	interface Preset {
		label: string;
		port: number;
		protocol: L4Protocol;
	}

	const PRESETS: Preset[] = [
		{ label: "qBittorrent / BitTorrent", port: 6881, protocol: "Both" },
		{ label: "Plex Media Server", port: 32400, protocol: "Tcp" },
		{ label: "Minecraft", port: 25565, protocol: "Both" },
		{ label: "WireGuard", port: 51820, protocol: "Udp" },
		{ label: "HTTP", port: 80, protocol: "Tcp" },
		{ label: "HTTPS", port: 443, protocol: "Tcp" },
		{ label: "SSH", port: 22, protocol: "Tcp" },
		{ label: "Jellyfin", port: 8096, protocol: "Tcp" },
	];

	function applyPreset(preset: Preset) {
		externalPort = preset.port;
		internalPort = preset.port;
		protocol = preset.protocol;
		errors = {};
	}

	// ── Initialise / reset form only when dialog transitions open or rule changes ──
	$effect(() => {
		const isOpening = open && !prevOpen;
		const ruleChanged = rule !== prevRule;

		if (isOpening || (open && ruleChanged)) {
			untrack(() => {
				errors = {};
				devicePickerSearch = "";
				selectedDevice = null;
				deviceTarget = null;
				if (rule) {
					comment = rule.comment ?? "";
					protocol = rule.protocol;
					srcZone = rule.src_zone;
					externalPort = rule.external_port;
					internalPort = rule.internal_port;
					enableHairpin = rule.enable_hairpin;
					if (rule.internal_ip.startsWith("dev:")) {
						deviceTarget = rule.internal_ip;
						ipMode = rule.family === "ipv4" ? "v4" : rule.family === "ipv6" ? "v6" : "dual";
						internalIp = "";
						internalIpv6 = "";
					} else if (rule.internal_ip.includes(":")) {
						ipMode = "v6";
						internalIpv6 = cleanIp(rule.internal_ip);
						internalIp = "";
					} else {
						ipMode = "v4";
						internalIp = cleanIp(rule.internal_ip);
						internalIpv6 = "";
					}
				} else {
					comment = "";
					protocol = "Tcp";
					srcZone = zones.find((z) => z === "external" || z === "wan") ?? zones[0] ?? "";
					externalPort = 80;
					internalIp = "";
					internalIpv6 = "";
					internalPort = 80;
					ipMode = "v4";
					enableHairpin = false;
				}
			});
		}
		prevOpen = open;
		prevRule = rule;
	});

	// ── IP cleaner: strip any trailing '?', ' ?', or non-numeric tokens ──────
	function cleanIp(raw: string | undefined | null): string {
		if (!raw) return "";
		return raw.trim().replace(/\s*\?.*$/, "").replace(/[?]/g, "").trim();
	}

	// ── DeviceCombobox callback ───────────────────────────────────────────────
	// A picked device is targeted by name (MAC when nameless): the forward follows its
	// addresses (IPv4 reservation/lease, IPv6 on the current prefix), no IP typed or kept.
	function handleDeviceSelect(dev: DeviceEntry) {
		selectedDevice = dev;
		// `dev:<name>` takes letters, digits and hyphens; other names go by MAC.
		const name = (dev.hostname || "").toLowerCase();
		const usable = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(name);
		deviceTarget = `dev:${usable ? name : dev.mac.toLowerCase()}`;
		internalIp = "";
		internalIpv6 = "";
		if (!rule) ipMode = "dual";
		errors = {};
		devicePickerSearch = "";
	}

	// ── Schemas ───────────────────────────────────────────────────────────────
	const portForwardBaseSchema = z.object({
		srcZone: z.string().trim().min(1, "Please select a source zone"),
		externalPort: portNumberSchema,
		internalPort: portNumberSchema,
		comment: z.string().trim().max(128, "Comment cannot exceed 128 characters").optional(),
	});

	const v4PortForwardSchema = portForwardBaseSchema.extend({
		internalIp: ipv4Schema,
	});

	const v6PortForwardSchema = portForwardBaseSchema.extend({
		internalIpv6: ipv6Schema,
	});

	const dualPortForwardSchema = portForwardBaseSchema.extend({
		internalIp: ipv4Schema,
		internalIpv6: ipv6Schema,
	});

	// ── Submit ────────────────────────────────────────────────────────────────
	function handleSave() {
		if (deviceTarget) {
			const validation = validateForm(portForwardBaseSchema, {
				srcZone,
				externalPort: externalPort === "" ? NaN : externalPort,
				internalPort: internalPort === "" ? NaN : internalPort,
				comment: comment.trim() || undefined,
			});
			if (!validation.success) {
				errors = validation.errors as Record<string, string>;
				toast.error("Please correct the invalid fields highlighted below");
				return;
			}
			errors = {};
			onSave({
				comment: comment.trim() || null,
				src_zone: srcZone,
				internal_ip: deviceTarget,
				external_port: Number(externalPort),
				// An IPv6 pinhole is routed: it keeps the external port.
				internal_port: ipMode === "v4" ? Number(internalPort) : Number(externalPort),
				protocol,
				enable_hairpin: ipMode === "v6" ? false : enableHairpin,
				family: ipMode === "dual" ? null : ipMode === "v4" ? "ipv4" : "ipv6",
			});
			return;
		}

		const cleanV4 = cleanIp(internalIp);
		const cleanV6 = cleanIp(internalIpv6);

		const rawData = {
			srcZone,
			externalPort: externalPort === "" ? NaN : externalPort,
			internalPort: internalPort === "" ? NaN : internalPort,
			comment: comment.trim() || undefined,
			internalIp: cleanV4,
			internalIpv6: cleanV6,
		};

		let validation;
		if (ipMode === "dual") {
			validation = validateForm(dualPortForwardSchema, rawData);
		} else if (ipMode === "v6") {
			validation = validateForm(v6PortForwardSchema, rawData);
		} else {
			validation = validateForm(v4PortForwardSchema, rawData);
		}

		if (!validation.success) {
			errors = validation.errors as Record<string, string>;
			toast.error("Please correct the invalid fields highlighted below");
			return;
		}
		// A ULA is not routed on the internet: a pinhole to it never receives anything.
		if ((ipMode === "v6" || ipMode === "dual") && /^f[cd]/i.test(cleanV6)) {
			errors = { internalIpv6: "A ULA is not reachable from the internet: pick the device or use its GUA" };
			toast.error("IPv6 pinholes need a GUA, not a ULA");
			return;
		}
		// An IPv6 pinhole is routed, not NATed: the host gets the port the WAN asked for.
		if (ipMode === "v6" && Number(internalPort) !== Number(externalPort)) {
			errors = { externalPort: "IPv6 pinholes cannot change the port: the host gets this port" };
			toast.error("IPv6 pinholes cannot change the port");
			return;
		}

		errors = {};

		if (ipMode === "dual") {
			const v4Rule: PortForwardRule = {
				comment: comment.trim() || null,
				src_zone: srcZone,
				internal_ip: cleanV4,
				external_port: Number(externalPort),
				internal_port: Number(internalPort),
				protocol,
				enable_hairpin: enableHairpin,
			};
			const v6Rule: PortForwardRule = {
				comment: comment.trim() ? `${comment.trim()} [IPv6]` : null,
				src_zone: srcZone,
				internal_ip: cleanV6,
				external_port: Number(externalPort),
				// Routed, not NATed: the pinhole keeps the external port.
				internal_port: Number(externalPort),
				protocol,
				enable_hairpin: false,
			};
			onSave([v4Rule, v6Rule]);
		} else if (ipMode === "v4") {
			onSave({
				comment: comment.trim() || null,
				src_zone: srcZone,
				internal_ip: cleanV4,
				external_port: Number(externalPort),
				internal_port: Number(internalPort),
				protocol,
				enable_hairpin: enableHairpin,
			});
		} else {
			onSave({
				comment: comment.trim() || null,
				src_zone: srcZone,
				internal_ip: cleanV6,
				external_port: Number(externalPort),
				internal_port: Number(internalPort),
				protocol,
				enable_hairpin: false,
			});
		}
	}

	function handleOpenChange(v: boolean) {
		if (!v) onClose();
		open = v;
	}
</script>

<Dialog.Root bind:open onOpenChange={handleOpenChange}>
	<Dialog.Content class="sm:max-w-lg w-[95vw]">
		<!-- Header with Presets dropdown -->
		<Dialog.Header>
			<div class="flex items-start justify-between gap-3">
				<div class="flex flex-col gap-0.5">
					<Dialog.Title class="flex items-center gap-2 text-base font-semibold">
						<ShuffleIcon data-icon="inline-start" class="text-primary" />
						{rule ? "Edit Inbound Port Rule" : "New Inbound Port Rule"}
					</Dialog.Title>
					<Dialog.Description class="text-xs text-muted-foreground">
						Forward external traffic to an internal LAN host or container (IPv4 DNAT or IPv6 Pinhole).
					</Dialog.Description>
				</div>

				<!-- Presets dropdown -->
				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Button variant="outline" size="sm" class="shrink-0 gap-1 text-xs" {...props}>
								Presets
								<ChevronDownIcon data-icon="inline-end" />
							</Button>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="end" class="w-52">
						<DropdownMenu.Label class="text-[11px] uppercase tracking-wide text-muted-foreground">
							Apply Preset
						</DropdownMenu.Label>
						<DropdownMenu.Separator />
						{#each PRESETS as preset (preset.label)}
							<DropdownMenu.Item
								class="text-xs flex justify-between gap-3"
								onclick={() => applyPreset(preset)}
							>
								<span>{preset.label}</span>
								<span class="font-mono text-muted-foreground">{preset.port}/{preset.protocol}</span>
							</DropdownMenu.Item>
						{/each}
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</div>
		</Dialog.Header>

		<!-- Form -->
		<div class="flex flex-col gap-4 py-2">
			<!-- Device Picker -->
			<div class="flex flex-col gap-1.5 p-3 rounded-xl border border-border bg-muted/30">
				<div class="flex items-center justify-between">
					<Label class="text-xs font-semibold flex items-center gap-1.5 text-foreground">
						<LaptopIcon class="size-3.5 text-primary" />
						Target LAN Device
					</Label>
					{#if selectedDevice}
						<Badge variant="outline" class="text-[10px] font-mono text-emerald-500 bg-emerald-500/10 border-emerald-500/20">
							{selectedDevice.origin === "Static" || selectedDevice.v6 !== null ? "Pinned / Static" : "Dynamic Discovery"}
						</Badge>
					{/if}
				</div>
				<DeviceCombobox
					bind:value={devicePickerSearch}
					placeholder="Search LAN device by name, MAC, or IP to auto-fill…"
					onselect={handleDeviceSelect}
				/>
				{#if selectedDevice}
					<div class="flex flex-wrap items-center gap-1.5 text-[11px] pt-1">
						<span class="text-muted-foreground">Detected:</span>
						<span class="font-semibold text-foreground">{selectedDevice.hostname || selectedDevice.mac}</span>
						{#if selectedDevice.primary_v4}
							<Badge variant="secondary" class="font-mono text-[10px] h-5">
								v4: {selectedDevice.primary_v4}
							</Badge>
						{/if}
						{#if selectedDevice.primary_v6}
							<Badge variant="secondary" class="font-mono text-[10px] h-5 text-purple-400">
								v6: {selectedDevice.primary_v6}
							</Badge>
						{/if}
					</div>
				{/if}
			</div>

			<!-- IP Mode Selector (Dual-Stack vs IPv4 vs IPv6) -->
			<Field.Field>
				<Field.Label class="text-xs">IP Addressing Stack</Field.Label>
				<Field.Content>
					<ToggleGroup.Root
						type="single"
						bind:value={ipMode}
						variant="outline"
						class="w-full"
					>
						<ToggleGroup.Item value="dual" class="flex-1 text-xs gap-1.5" disabled={!!rule && !deviceTarget}>
							<NetworkIcon class="size-3.5 text-primary" />
							Dual-Stack (v4 + v6)
						</ToggleGroup.Item>
						<ToggleGroup.Item value="v4" class="flex-1 text-xs gap-1.5">
							<span class="text-blue-400 font-bold text-[10px]">IPv4</span>
							DNAT Only
						</ToggleGroup.Item>
						<ToggleGroup.Item value="v6" class="flex-1 text-xs gap-1.5">
							<GlobeIcon class="size-3.5 text-purple-400" />
							IPv6 Pinhole
						</ToggleGroup.Item>
					</ToggleGroup.Root>
				</Field.Content>
			</Field.Field>

			<!-- Target: a device (follows its addresses) or fixed IPs -->
			{#if deviceTarget}
				<div class="flex flex-col gap-1.5 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-3 text-[11px]">
					<div class="flex items-center justify-between gap-2">
						<span class="font-mono font-semibold text-foreground">{deviceTarget}</span>
						<Button
							size="sm"
							variant="ghost"
							class="h-6 text-[11px]"
							onclick={() => {
								deviceTarget = null;
								selectedDevice = null;
							}}
						>
							Use fixed addresses instead
						</Button>
					</div>
					<span class="text-muted-foreground">
						Follows the device: IPv4 goes to its reservation or lease; the IPv6 pinhole opens on its fixed
						suffix or DHCPv6 lease on the current delegated prefix, and moves when the ISP renumbers it.
					</span>
				</div>
			{:else if ipMode === "v4" || ipMode === "dual"}
				<Field.Field data-invalid={!!errors.internalIp || undefined}>
					<Field.Label class="text-xs flex items-center justify-between">
						<span>Internal IPv4 Address</span>
						<span class="text-[10px] text-muted-foreground">Private LAN IP (DNAT)</span>
					</Field.Label>
					<Field.Content>
						<Input
							bind:value={internalIp}
							placeholder="192.168.0.128"
							class={cn("font-mono text-xs", errors.internalIp && "border-destructive")}
							aria-invalid={Boolean(errors.internalIp)}
							oninput={() => {
								internalIp = internalIp.replace(/[?]/g, "");
								if (errors.internalIp) errors = { ...errors, internalIp: "" };
							}}
						/>
					</Field.Content>
					{#if errors.internalIp}
						<Field.Error class="flex items-center gap-1 text-[11px]">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							<span>{errors.internalIp}</span>
						</Field.Error>
					{/if}
				</Field.Field>
			{/if}

			{#if !deviceTarget && (ipMode === "v6" || ipMode === "dual")}
				<Field.Field data-invalid={!!errors.internalIpv6 || undefined}>
					<Field.Label class="text-xs flex items-center justify-between">
						<span>Target IPv6 Address</span>
						<span class="text-[10px] text-purple-400">Routed global address (GUA)</span>
					</Field.Label>
					<Field.Content>
						<Input
							bind:value={internalIpv6}
							placeholder="2804:xxxx:xxxx:xxxx::1057:cafe"
							class={cn("font-mono text-xs", errors.internalIpv6 && "border-destructive")}
							aria-invalid={Boolean(errors.internalIpv6)}
							oninput={() => {
								internalIpv6 = internalIpv6.replace(/[?]/g, "");
								if (errors.internalIpv6) errors = { ...errors, internalIpv6: "" };
							}}
						/>
					</Field.Content>
					{#if errors.internalIpv6}
						<Field.Error class="flex items-center gap-1 text-[11px]">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							<span>{errors.internalIpv6}</span>
						</Field.Error>
					{/if}

					<!-- Quick switch between GUA and ULA if available -->
					{#if selectedDevice && selectedDevice.ipv6_addrs && selectedDevice.ipv6_addrs.length > 1}
						<div class="flex items-center gap-1.5 pt-1">
							<span class="text-[10px] text-muted-foreground">Available on host:</span>
							{#each selectedDevice.ipv6_addrs as addr}
								<Button
									type="button"
									variant="ghost"
									size="sm"
									class={cn(
										"h-5 px-1.5 text-[10px] font-mono",
										internalIpv6 === addr.addr && "bg-primary/15 text-primary font-semibold"
									)}
									onclick={() => { internalIpv6 = addr.addr; if (errors.internalIpv6) errors = { ...errors, internalIpv6: "" }; }}
								>
									{addr.kind}: {addr.addr.slice(0, 12)}…
								</Button>
							{/each}
						</div>
					{/if}
				</Field.Field>
			{/if}

			<!-- External Port / Internal Port side-by-side -->
			<div class="grid grid-cols-2 gap-3">
				<Field.Field data-invalid={!!errors.externalPort || undefined}>
					<Field.Label class="text-xs">External Port</Field.Label>
					<Field.Content>
						<Input
							type="number"
							min="1"
							max="65535"
							bind:value={externalPort}
							placeholder="80"
							class={cn("font-mono text-xs", errors.externalPort && "border-destructive")}
							aria-invalid={Boolean(errors.externalPort)}
							oninput={() => { if (errors.externalPort) errors = { ...errors, externalPort: "" }; }}
						/>
					</Field.Content>
					{#if errors.externalPort}
						<Field.Error class="flex items-center gap-1 text-[11px]">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							<span>{errors.externalPort}</span>
						</Field.Error>
					{/if}
				</Field.Field>

				<Field.Field data-invalid={!!errors.internalPort || undefined}>
					<Field.Label class="text-xs">Internal Port</Field.Label>
					<Field.Content>
						<Input
							type="number"
							min="1"
							max="65535"
							bind:value={internalPort}
							placeholder="80"
							class={cn("font-mono text-xs", errors.internalPort && "border-destructive")}
							aria-invalid={Boolean(errors.internalPort)}
							oninput={() => { if (errors.internalPort) errors = { ...errors, internalPort: "" }; }}
						/>
					</Field.Content>
					{#if errors.internalPort}
						<Field.Error class="flex items-center gap-1 text-[11px]">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							<span>{errors.internalPort}</span>
						</Field.Error>
					{/if}
				</Field.Field>
			</div>

			<!-- Protocol & Source Zone -->
			<div class="grid grid-cols-2 gap-3">
				<!-- Protocol -->
				<Field.Field>
					<Field.Label class="text-xs">Protocol</Field.Label>
					<Field.Content>
						<ToggleGroup.Root
							type="single"
							bind:value={protocol}
							variant="outline"
							class="w-full"
						>
							<ToggleGroup.Item value="Tcp" class="flex-1 text-xs">TCP</ToggleGroup.Item>
							<ToggleGroup.Item value="Udp" class="flex-1 text-xs">UDP</ToggleGroup.Item>
							<ToggleGroup.Item value="Both" class="flex-1 text-xs">Both</ToggleGroup.Item>
						</ToggleGroup.Root>
					</Field.Content>
				</Field.Field>

				<!-- Source Zone -->
				<Field.Field data-invalid={!!errors.srcZone || undefined}>
					<Field.Label class="text-xs">Source Zone</Field.Label>
					<Field.Content>
						<Select.Root
							type="single"
							value={srcZone}
							onValueChange={(v) => {
								srcZone = v ?? "";
								if (errors.srcZone) errors = { ...errors, srcZone: "" };
							}}
						>
							<Select.Trigger class={cn("h-9 text-xs", errors.srcZone && "border-destructive")} aria-invalid={Boolean(errors.srcZone)}>
								{srcZone || "Select zone…"}
							</Select.Trigger>
							<Select.Content>
								{#each zones as z (z)}
									<Select.Item value={z} class="text-xs">{z}</Select.Item>
								{/each}
							</Select.Content>
						</Select.Root>
					</Field.Content>
					{#if errors.srcZone}
						<Field.Error class="flex items-center gap-1 text-[11px]">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							<span>{errors.srcZone}</span>
						</Field.Error>
					{/if}
				</Field.Field>
			</div>

			<!-- Comment -->
			<Field.Field data-invalid={!!errors.comment || undefined}>
				<Field.Label class="text-xs">Comment <span class="text-muted-foreground">(optional)</span></Field.Label>
				<Field.Content>
					<Input
						bind:value={comment}
						placeholder="e.g. qBittorrent, Plex Server"
						class={cn("text-xs", errors.comment && "border-destructive")}
						aria-invalid={Boolean(errors.comment)}
						oninput={() => { if (errors.comment) errors = { ...errors, comment: "" }; }}
					/>
				</Field.Content>
				{#if errors.comment}
					<Field.Error class="flex items-center gap-1 text-[11px]">
						<AlertCircleIcon class="size-3.5 shrink-0" />
						<span>{errors.comment}</span>
					</Field.Error>
				{/if}
			</Field.Field>

			<Separator />

			<!-- Hairpin NAT toggle (only for IPv4) -->
			{#if ipMode !== "v6"}
				<Field.Field orientation="horizontal">
					<Field.Label class="text-xs flex-1">
						Hairpin NAT <span class="text-[11px] text-muted-foreground">(IPv4 only)</span>
						<Field.Description class="text-[11px] font-normal text-muted-foreground">
							Allows internal LAN devices to access this service using your public WAN IP or DDNS hostname.
						</Field.Description>
					</Field.Label>
					<Field.Content>
						<Switch bind:checked={enableHairpin} aria-label="Hairpin NAT" />
					</Field.Content>
				</Field.Field>
			{:else}
				<div class="text-[11px] text-muted-foreground bg-muted/40 rounded-lg p-2.5 border border-border/60">
					<strong class="text-foreground">IPv6 Direct Routing:</strong> Hairpin NAT is not required on IPv6 because LAN devices communicate directly with the target device's global address without address translation.
				</div>
			{/if}
		</div>

		<Dialog.Footer class="gap-2">
			<Button variant="outline" onclick={onClose}>Cancel</Button>
			<Button onclick={handleSave}>
				{rule ? "Save Changes" : ipMode === "dual" ? "Add Dual-Stack Rules" : "Add Rule"}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
