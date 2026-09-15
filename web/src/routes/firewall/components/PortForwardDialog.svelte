<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import * as Select from "$lib/components/ui/select";
	import * as ToggleGroup from "$lib/components/ui/toggle-group";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import { Label } from "$lib/components/ui/label";
	import DeviceCombobox from "$lib/components/DeviceCombobox.svelte";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ShuffleIcon from "@lucide/svelte/icons/shuffle";
	import { cn } from "$lib/utils";
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
		onSave: (rule: PortForwardRule) => void;
		onClose: () => void;
	} = $props();

	// ── Form state ────────────────────────────────────────────────────────────
	let comment = $state("");
	let protocol = $state<L4Protocol>("Tcp");
	let srcZone = $state("");
	let externalPort = $state<number | "">(80);
	let internalIp = $state("");
	let internalPort = $state<number | "">(80);
	let enableHairpin = $state(false);

	// ── Validation errors ─────────────────────────────────────────────────────
	let errors = $state<Record<string, string>>({});

	// ── Preset templates ──────────────────────────────────────────────────────
	interface Preset {
		label: string;
		port: number;
		protocol: L4Protocol;
	}

	const PRESETS: Preset[] = [
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

	// ── Initialise / reset form when dialog opens ─────────────────────────────
	$effect(() => {
		if (open) {
			errors = {};
			if (rule) {
				comment = rule.comment ?? "";
				protocol = rule.protocol;
				srcZone = rule.src_zone;
				externalPort = rule.external_port;
				internalIp = rule.internal_ip;
				internalPort = rule.internal_port;
				enableHairpin = rule.enable_hairpin;
			} else {
				comment = "";
				protocol = "Tcp";
				srcZone = zones[0] ?? "";
				externalPort = 80;
				internalIp = "";
				internalPort = 80;
				enableHairpin = false;
			}
		}
	});

	// ── DeviceCombobox callback ───────────────────────────────────────────────
	function handleDeviceSelect(dev: DeviceEntry) {
		const ip = dev.v4?.ip ?? dev.display_v4 ?? "";
		if (ip) {
			internalIp = ip;
			errors = { ...errors, internalIp: "" };
		}
	}

	// ── Port validator ────────────────────────────────────────────────────────
	function validPort(v: number | ""): boolean {
		return typeof v === "number" && v >= 1 && v <= 65535;
	}

	// ── Submit ────────────────────────────────────────────────────────────────
	function handleSave() {
		const next: Record<string, string> = {};

		if (!validPort(externalPort)) next.externalPort = "Porta deve ser 1–65535";
		if (!validPort(internalPort)) next.internalPort = "Porta deve ser 1–65535";
		if (!internalIp.trim()) next.internalIp = "IP interno obrigatório";
		if (!srcZone) next.srcZone = "Selecione uma zona de origem";

		errors = next;
		if (Object.values(next).some(Boolean)) return;

		onSave({
			comment: comment.trim() || null,
			src_zone: srcZone,
			internal_ip: internalIp.trim(),
			external_port: externalPort as number,
			internal_port: internalPort as number,
			protocol,
			enable_hairpin: enableHairpin,
		});
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
						{rule ? "Editar Regra de Port Forward" : "Nova Regra de Port Forward"}
					</Dialog.Title>
					<Dialog.Description class="text-xs text-muted-foreground">
						Redireciona tráfego externo para um dispositivo interno.
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
					<DropdownMenu.Content align="end" class="w-48">
						<DropdownMenu.Label class="text-[11px] uppercase tracking-wide text-muted-foreground">
							Aplicar preset
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
			<!-- Comment -->
			<Field.Field>
				<Field.Label class="text-xs">Comentário <span class="text-muted-foreground">(opcional)</span></Field.Label>
				<Field.Content>
					<Input
						bind:value={comment}
						placeholder="ex: Plex server da sala"
						class="text-xs"
					/>
				</Field.Content>
			</Field.Field>

			<!-- Protocol -->
			<Field.Field>
				<Field.Label class="text-xs">Protocolo</Field.Label>
				<Field.Content>
					<ToggleGroup.Root
						type="single"
						bind:value={protocol}
						variant="outline"
						class="w-full"
					>
						<ToggleGroup.Item value="Tcp" class="flex-1 text-xs">TCP</ToggleGroup.Item>
						<ToggleGroup.Item value="Udp" class="flex-1 text-xs">UDP</ToggleGroup.Item>
						<ToggleGroup.Item value="Both" class="flex-1 text-xs">Ambos</ToggleGroup.Item>
					</ToggleGroup.Root>
				</Field.Content>
			</Field.Field>

			<!-- Source Zone -->
			<Field.Field data-invalid={!!errors.srcZone || undefined}>
				<Field.Label class="text-xs">Zona de Origem</Field.Label>
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
							{srcZone || "Selecionar zona…"}
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

			<!-- External Port / Internal Port side-by-side -->
			<div class="grid grid-cols-2 gap-3">
				<Field.Field data-invalid={!!errors.externalPort || undefined}>
					<Field.Label class="text-xs">Porta Externa</Field.Label>
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
					<Field.Label class="text-xs">Porta Interna</Field.Label>
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

			<!-- Internal IP + DeviceCombobox -->
			<Field.Field data-invalid={!!errors.internalIp || undefined}>
				<Field.Label class="text-xs">IP Interno</Field.Label>
				<Field.Content>
					<Input
						bind:value={internalIp}
						placeholder="192.168.1.100"
						class={cn("font-mono text-xs", errors.internalIp && "border-destructive")}
						oninput={() => { errors = { ...errors, internalIp: "" }; }}
					/>
				</Field.Content>
				{#if errors.internalIp}
					<Field.Error>{errors.internalIp}</Field.Error>
				{/if}
				<!-- Device picker below the input -->
				<div class="flex flex-col gap-1 pt-1">
					<Label class="text-[11px] text-muted-foreground">Selecionar dispositivo</Label>
					<DeviceCombobox
						value={internalIp}
						placeholder="Buscar dispositivo LAN…"
						onselect={handleDeviceSelect}
					/>
				</div>
			</Field.Field>

			<Separator />

			<!-- Hairpin NAT toggle -->
			<Field.Field orientation="horizontal">
				<Field.Label class="text-xs flex-1">
					Hairpin NAT
					<Field.Description class="text-[11px] font-normal text-muted-foreground">
						Permite que dispositivos internos se conectem via IP externo.
					</Field.Description>
				</Field.Label>
				<Field.Content>
					<Switch bind:checked={enableHairpin} />
				</Field.Content>
			</Field.Field>
		</div>

		<Dialog.Footer class="gap-2">
			<Button variant="outline" onclick={onClose}>Cancelar</Button>
			<Button onclick={handleSave}>
				{rule ? "Salvar Alterações" : "Adicionar Regra"}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
