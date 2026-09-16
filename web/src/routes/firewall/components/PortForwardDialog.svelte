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
	import { cn } from "$lib/utils";
	import { untrack } from "svelte";
	import type { PortForwardRule, L4Protocol, DeviceEntry } from "$lib/api/types";

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
				if (rule) {
					comment = rule.comment ?? "";
					protocol = rule.protocol;
					srcZone = rule.src_zone;
					externalPort = rule.external_port;
					internalPort = rule.internal_port;
					enableHairpin = rule.enable_hairpin;
					if (rule.internal_ip.includes(":")) {
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
	function handleDeviceSelect(dev: DeviceEntry) {
		selectedDevice = dev;
		const v4 = cleanIp(dev.v4?.ip || dev.display_v4);
		if (v4 && v4 !== "—") internalIp = v4;

		// Extract GUA or ULA or primary display_v6
		const v6Gua = dev.ipv6_addrs?.find((a) => a.kind.toLowerCase() === "gua")?.addr;
		const v6Ula = dev.ipv6_addrs?.find((a) => a.kind.toLowerCase() === "ula")?.addr;
		const primaryV6 = cleanIp(v6Gua || dev.display_v6 || v6Ula);
		if (primaryV6 && primaryV6 !== "—") internalIpv6 = primaryV6;

		// Auto-switch mode based on available addresses
		if (internalIp && internalIpv6 && !rule) {
			ipMode = "dual";
		} else if (internalIpv6 && !internalIp) {
			ipMode = "v6";
		} else {
			ipMode = "v4";
		}

		errors = {};
		devicePickerSearch = "";
	}

	// ── Port validator ────────────────────────────────────────────────────────
	function validPort(v: number | ""): boolean {
		return typeof v === "number" && v >= 1 && v <= 65535;
	}

	// ── Submit ────────────────────────────────────────────────────────────────
	function handleSave() {
		const next: Record<string, string> = {};
		const cleanV4 = cleanIp(internalIp);
		const cleanV6 = cleanIp(internalIpv6);

		if (!validPort(externalPort)) next.externalPort = "Port must be 1–65535";
		if (!validPort(internalPort)) next.internalPort = "Port must be 1–65535";
		if (!srcZone) next.srcZone = "Please select a source zone";

		if (ipMode === "v4" || ipMode === "dual") {
			if (!cleanV4) next.internalIp = "IPv4 address is required";
		}
		if (ipMode === "v6" || ipMode === "dual") {
			if (!cleanV6) next.internalIpv6 = "IPv6 address is required";
		}

		errors = next;
		if (Object.values(next).some(Boolean)) return;

		if (ipMode === "dual") {
			const v4Rule: PortForwardRule = {
				comment: comment.trim() || null,
				src_zone: srcZone,
				internal_ip: cleanV4,
				external_port: externalPort as number,
				internal_port: internalPort as number,
				protocol,
				enable_hairpin: enableHairpin,
			};
			const v6Rule: PortForwardRule = {
				comment: comment.trim() ? `${comment.trim()} [IPv6]` : null,
				src_zone: srcZone,
				internal_ip: cleanV6,
				external_port: externalPort as number,
				internal_port: internalPort as number,
				protocol,
				enable_hairpin: false,
			};
			onSave([v4Rule, v6Rule]);
		} else if (ipMode === "v4") {
			onSave({
				comment: comment.trim() || null,
				src_zone: srcZone,
				internal_ip: cleanV4,
				external_port: externalPort as number,
				internal_port: internalPort as number,
				protocol,
				enable_hairpin: enableHairpin,
			});
		} else {
			onSave({
				comment: comment.trim() || null,
				src_zone: srcZone,
				internal_ip: cleanV6,
				external_port: externalPort as number,
				internal_port: internalPort as number,
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
						{#if selectedDevice.display_v4}
							<Badge variant="secondary" class="font-mono text-[10px] h-5">
								v4: {selectedDevice.display_v4}
							</Badge>
						{/if}
						{#if selectedDevice.display_v6}
							<Badge variant="secondary" class="font-mono text-[10px] h-5 text-purple-400">
								v6: {selectedDevice.display_v6}
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
						<ToggleGroup.Item value="dual" class="flex-1 text-xs gap-1.5" disabled={!!rule}>
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

			<!-- Target IP Inputs based on Mode -->
			{#if ipMode === "v4" || ipMode === "dual"}
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
							oninput={() => {
								internalIp = internalIp.replace(/[?]/g, "");
								errors = { ...errors, internalIp: "" };
							}}
						/>
					</Field.Content>
					{#if errors.internalIp}
						<Field.Error>{errors.internalIp}</Field.Error>
					{/if}
				</Field.Field>
			{/if}

			{#if ipMode === "v6" || ipMode === "dual"}
				<Field.Field data-invalid={!!errors.internalIpv6 || undefined}>
					<Field.Label class="text-xs flex items-center justify-between">
						<span>Target IPv6 Address</span>
						<span class="text-[10px] text-purple-400">Routed Global GUA / ULA</span>
					</Field.Label>
					<Field.Content>
						<Input
							bind:value={internalIpv6}
							placeholder="2804:xxxx:xxxx:xxxx::1057:cafe"
							class={cn("font-mono text-xs", errors.internalIpv6 && "border-destructive")}
							oninput={() => {
								internalIpv6 = internalIpv6.replace(/[?]/g, "");
								errors = { ...errors, internalIpv6: "" };
							}}
						/>
					</Field.Content>
					{#if errors.internalIpv6}
						<Field.Error>{errors.internalIpv6}</Field.Error>
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
									onclick={() => { internalIpv6 = addr.addr; errors = { ...errors, internalIpv6: "" }; }}
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
							oninput={() => { errors = { ...errors, externalPort: "" }; }}
						/>
					</Field.Content>
					{#if errors.externalPort}
						<Field.Error>{errors.externalPort}</Field.Error>
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
							oninput={() => { errors = { ...errors, internalPort: "" }; }}
						/>
					</Field.Content>
					{#if errors.internalPort}
						<Field.Error>{errors.internalPort}</Field.Error>
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
								errors = { ...errors, srcZone: "" };
							}}
						>
							<Select.Trigger class={cn("h-9 text-xs", errors.srcZone && "border-destructive")}>
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
						<Field.Error>{errors.srcZone}</Field.Error>
					{/if}
				</Field.Field>
			</div>

			<!-- Comment -->
			<Field.Field>
				<Field.Label class="text-xs">Comment <span class="text-muted-foreground">(optional)</span></Field.Label>
				<Field.Content>
					<Input
						bind:value={comment}
						placeholder="e.g. qBittorrent, Plex Server"
						class="text-xs"
					/>
				</Field.Content>
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
