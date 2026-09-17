<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Collapsible from "$lib/components/ui/collapsible";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ZapOffIcon from "@lucide/svelte/icons/zap-off";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ChevronUpIcon from "@lucide/svelte/icons/chevron-up";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import XIcon from "@lucide/svelte/icons/x";

	import type { NicTuningConfig, NetworkInterfaceInfo } from "$lib/api/types";

	interface Props {
		tuning: NicTuningConfig;
		availableInterfaces: NetworkInterfaceInfo[];
		effectiveCpuMask?: string;
		onUpdate: (updated: NicTuningConfig) => void;
	}

	let { tuning, availableInterfaces, effectiveCpuMask = "", onUpdate }: Props = $props();

	let advancedOpen = $state(false);
	let customIfaceInput = $state("");

	function updateField<K extends keyof NicTuningConfig>(key: K, value: NicTuningConfig[K]) {
		onUpdate({ ...tuning, [key]: value });
	}

	function addInterface(name: string) {
		const trimmed = name.trim();
		if (!trimmed || tuning.interfaces.includes(trimmed)) return;
		onUpdate({ ...tuning, interfaces: [...tuning.interfaces, trimmed] });
		customIfaceInput = "";
	}

	function removeInterface(name: string) {
		onUpdate({ ...tuning, interfaces: tuning.interfaces.filter((i) => i !== name) });
	}

	// Filter interfaces: exclude virtual ifb devices
	const eligibleInterfaces = $derived(
		availableInterfaces.filter((i) => !i.name.startsWith("ifb") && !i.name.startsWith("teql"))
	);
</script>

<div class="flex flex-col gap-5">
	<!-- Master Switch Card -->
	<Card.Root class="p-5 border-border">
		<div class="flex items-start justify-between gap-4">
			<div class="flex items-start gap-3">
				<div class="flex size-10 items-center justify-center rounded-xl bg-primary/10 text-primary shrink-0 mt-0.5">
					<CpuIcon class="size-5" />
				</div>
				<div class="flex flex-col gap-1">
					<div class="flex items-center gap-2">
						<h3 class="text-base font-semibold text-foreground">Habilitar Otimização de Hardware & NICs</h3>
						<HelpPopover
							title="Otimizações de Baixo Nível no Kernel"
							description="Ajuste fino de filas de interrupção, afinidade de CPU e buffers do controlador de rede."
						>
							<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
								<p>
									<strong class="text-foreground">RPS & RFS:</strong> Distribui o processamento de pacotes recebidos entre todos os núcleos da CPU (evita gargalo de 100% em um único núcleo).
								</p>
								<p>
									<strong class="text-foreground">Ring Buffers Máximos:</strong> Expande os anéis de recepção e transmissão para absorver rajadas intensas de tráfego sem perdas de pacotes (drops).
								</p>
								<p>
									<strong class="text-foreground">Desativação de EEE:</strong> Desativa a economia de energia no padrão IEEE 802.3az, eliminando atrasos de retorno de suspensão (micro-sleeps).
								</p>
							</div>
						</HelpPopover>
						<Badge variant={tuning.enabled ? "default" : "secondary"} class="text-[10px]">
							{tuning.enabled ? "Habilitado" : "Desabilitado"}
						</Badge>
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed max-w-2xl">
						Maximiza a taxa de transferência e reduz o jitter configurando parâmetros essenciais de hardware via sysfs e ethtool para roteadores e mini PCs baseados em x86/ARM.
					</p>
				</div>
			</div>

			<div class="flex items-center pt-1">
				<Switch
					checked={tuning.enabled}
					onCheckedChange={(val) => updateField("enabled", val)}
					aria-label="Habilitar Otimização de Hardware & NICs"
				/>
			</div>
		</div>
	</Card.Root>

	{#if tuning.enabled}
		<!-- Target Interfaces Selection -->
		<Card.Root class="p-5 flex flex-col gap-4 border-border">
			<div class="flex items-center justify-between border-b pb-3">
				<div>
					<h4 class="text-sm font-semibold text-foreground">Interfaces Alvo do Tuning</h4>
					<p class="text-xs text-muted-foreground">
						Selecione quais interfaces de rede física devem receber os ajustes de RPS e ethtool.
					</p>
				</div>
			</div>

			<div class="flex flex-col gap-3">
				<div class="flex flex-wrap items-center gap-2">
					{#if tuning.interfaces.length === 0}
						<Badge variant="outline" class="text-xs border-dashed text-muted-foreground py-1 px-2.5">
							Padrão do Sistema: Auto-detecta interfaces ativas de LAN e WAN
						</Badge>
					{/if}
					{#each tuning.interfaces as iface}
						<Badge variant="secondary" class="gap-1.5 py-1 px-2.5 text-xs font-mono">
							<span>{iface}</span>
							<button
								type="button"
								onclick={() => removeInterface(iface)}
								class="hover:text-destructive transition-colors ml-0.5"
								aria-label={`Remover ${iface}`}
							>
								<XIcon class="size-3" />
							</button>
						</Badge>
					{/each}
				</div>

				<div class="flex items-center gap-2 max-w-md pt-1">
					<select
						class="flex h-8 w-full rounded-md border border-input bg-transparent px-2.5 py-1 text-xs shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
						value=""
						onchange={(e) => {
							const val = (e.target as HTMLSelectElement).value;
							if (val) addInterface(val);
						}}
					>
						<option value="" disabled selected>Adicionar interface detectada...</option>
						{#each eligibleInterfaces as iface}
							{#if !tuning.interfaces.includes(iface.name)}
								<option value={iface.name}>{iface.name} ({iface.bus_type})</option>
							{/if}
						{/each}
					</select>

					<div class="flex items-center gap-1 shrink-0">
						<Input
							type="text"
							placeholder="Ou nome manual..."
							bind:value={customIfaceInput}
							onkeydown={(e) => {
								if (e.key === "Enter") {
									e.preventDefault();
									addInterface(customIfaceInput);
								}
							}}
							class="h-8 text-xs w-36"
						/>
						<Button
							variant="outline"
							size="sm"
							onclick={() => addInterface(customIfaceInput)}
							disabled={!customIfaceInput.trim()}
							class="h-8 px-2"
						>
							<PlusIcon class="size-3.5" />
						</Button>
					</div>
				</div>
			</div>
		</Card.Root>

		<!-- Core Tuning Options Grid -->
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			<!-- CPU Mask / RPS Affinity -->
			<Card.Root class="p-5 border-border flex flex-col gap-3">
				<div class="flex items-center justify-between">
					<span class="text-sm font-semibold text-foreground flex items-center gap-1.5">
						Máscara de Afinidade de CPU (RPS)
						<InfoPopover
							title="Afinidade RPS"
							description="Máscara hexadecimal determinando quais núcleos da CPU processarão as interrupções de rede."
						>
							<div class="flex flex-col gap-1 text-xs text-muted-foreground">
								<p><strong>auto:</strong> O Lanforge lê <code>/sys/devices/system/cpu/online</code> e gera a máscara para todas as threads da CPU.</p>
								<p><strong>Exemplo:</strong> Em uma CPU com 8 threads (0 a 7), a máscara ideal é <code>ff</code>.</p>
							</div>
						</InfoPopover>
					</span>
					{#if effectiveCpuMask}
						<Badge variant="outline" class="font-mono text-[10px]">
							Efetiva: 0x{effectiveCpuMask}
						</Badge>
					{/if}
				</div>
				<div class="flex flex-col gap-1.5">
					<Input
						type="text"
						value={tuning.cpu_mask}
						oninput={(e) => updateField("cpu_mask", (e.target as HTMLInputElement).value.trim())}
						placeholder="auto"
						class="font-mono text-sm"
					/>
					<span class="text-[11px] text-muted-foreground">
						Digite <code>auto</code> para detectar todas as CPUs da máquina ou informe uma máscara hexadecimal (ex: <code>ff</code>).
					</span>
				</div>
			</Card.Root>

			<!-- Ring Buffers (Rx / Tx) -->
			<Card.Root class="p-5 border-border flex flex-col gap-3">
				<div class="flex items-center justify-between">
					<span class="text-sm font-semibold text-foreground flex items-center gap-1.5">
						Ring Buffers (Rx / Tx)
						<InfoPopover
							title="Ethtool Ring Buffers"
							description="Tamanho das filas circulares DMA do controlador de rede."
						>
							<p class="text-xs text-muted-foreground leading-relaxed">
								<strong>auto:</strong> Consulta os limites máximos suportados pelo chip (via <code>ethtool -g</code>) e eleva a fila até o máximo seguro (ex: 4096 ou 1024 buffers).
							</p>
						</InfoPopover>
					</span>
				</div>
				<div class="grid grid-cols-2 gap-3">
					<div class="flex flex-col gap-1">
						<label for="rx-ring" class="text-xs text-muted-foreground">RX Ring</label>
						<Input
							id="rx-ring"
							type="text"
							value={tuning.rx_ring}
							oninput={(e) => updateField("rx_ring", (e.target as HTMLInputElement).value.trim())}
							placeholder="auto"
							class="font-mono text-sm h-8"
						/>
					</div>
					<div class="flex flex-col gap-1">
						<label for="tx-ring" class="text-xs text-muted-foreground">TX Ring</label>
						<Input
							id="tx-ring"
							type="text"
							value={tuning.tx_ring}
							oninput={(e) => updateField("tx_ring", (e.target as HTMLInputElement).value.trim())}
							placeholder="auto"
							class="font-mono text-sm h-8"
						/>
					</div>
				</div>
				<span class="text-[11px] text-muted-foreground">
					Defina <code>auto</code> para aplicar o limite de fábrica do driver ou informe valores numéricos.
				</span>
			</Card.Root>
		</div>

		<!-- Switches Card (EEE & UDP GRO) -->
		<Card.Root class="p-5 border-border flex flex-col gap-4">
			<div class="flex items-start justify-between gap-4">
				<div class="flex items-start gap-3">
					<div class="flex size-9 items-center justify-center rounded-lg bg-amber-500/10 text-amber-500 shrink-0 mt-0.5">
						<ZapOffIcon class="size-4" />
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-sm font-medium text-foreground">Desativar Economia de Energia (Green Ethernet / EEE)</span>
						<p class="text-xs text-muted-foreground leading-relaxed max-w-xl">
							Desativa o modo Energy Efficient Ethernet (IEEE 802.3az). Impede que o chip PHY entre em estados de baixa energia transitórios, eliminando engasgos de latência em tráfego intermitente.
						</p>
					</div>
				</div>
				<Switch
					checked={tuning.disable_eee}
					onCheckedChange={(val) => updateField("disable_eee", val)}
					aria-label="Desativar Economia de Energia"
				/>
			</div>

			<div class="border-t pt-4 flex items-start justify-between gap-4">
				<div class="flex items-start gap-3">
					<div class="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-500 shrink-0 mt-0.5">
						<ActivityIcon class="size-4" />
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-sm font-medium text-foreground">Forwarding UDP GRO (Generic Receive Offload)</span>
						<p class="text-xs text-muted-foreground leading-relaxed max-w-xl">
							Agrega múltiplos pacotes UDP recebidos antes de encaminhar pelas regras de roteamento. Aumenta substancialmente o throughput em protocolos modernos como WireGuard, QUIC (HTTP/3) e WebRTC.
						</p>
					</div>
				</div>
				<Switch
					checked={tuning.udp_gro_forwarding}
					onCheckedChange={(val) => updateField("udp_gro_forwarding", val)}
					aria-label="Forwarding UDP GRO"
				/>
			</div>
		</Card.Root>

		<!-- Advanced RFS Flow Entries Collapsible -->
		<Collapsible.Root bind:open={advancedOpen} class="flex flex-col gap-2">
			<Card.Root class="p-4 border-border">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<SlidersIcon class="size-4 text-muted-foreground" />
						<span class="text-xs font-semibold text-foreground uppercase tracking-wider">Tabelas de Fluxo RFS Globais (Avançado)</span>
					</div>
					<Button
						variant="ghost"
						size="sm"
						onclick={() => (advancedOpen = !advancedOpen)}
						class="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
					>
						{advancedOpen ? "Recolher" : "Expandir"}
						{#if advancedOpen}
							<ChevronUpIcon class="size-3.5" />
						{:else}
							<ChevronDownIcon class="size-3.5" />
						{/if}
					</Button>
				</div>

				<Collapsible.Content class="pt-4 flex flex-col gap-4 border-t mt-3">
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
						<div class="flex flex-col gap-1.5">
							<label for="rps-entries" class="text-xs font-medium text-foreground">
								Tabela Global (rps_sock_flow_entries)
							</label>
							<Input
								id="rps-entries"
								type="number"
								step="1024"
								value={tuning.rps_flow_entries}
								oninput={(e) => updateField("rps_flow_entries", Number((e.target as HTMLInputElement).value))}
							/>
							<span class="text-[11px] text-muted-foreground">
								Padrão: 32768 entradas. Tamanho da tabela global de conexões simultâneas do kernel.
							</span>
						</div>

						<div class="flex flex-col gap-1.5">
							<label for="rps-cnt" class="text-xs font-medium text-foreground">
								Tabela por Fila (rps_flow_cnt)
							</label>
							<Input
								id="rps-cnt"
								type="number"
								step="512"
								value={tuning.rps_flow_cnt}
								oninput={(e) => updateField("rps_flow_cnt", Number((e.target as HTMLInputElement).value))}
							/>
							<span class="text-[11px] text-muted-foreground">
								Padrão: 4096 entradas por fila de recepção.
							</span>
						</div>
					</div>
				</Collapsible.Content>
			</Card.Root>
		</Collapsible.Root>
	{/if}
</div>
