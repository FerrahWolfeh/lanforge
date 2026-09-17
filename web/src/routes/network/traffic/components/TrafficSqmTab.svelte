<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Collapsible from "$lib/components/ui/collapsible";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import UsersIcon from "@lucide/svelte/icons/users";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import ChevronUpIcon from "@lucide/svelte/icons/chevron-up";
	import ZapIcon from "@lucide/svelte/icons/zap";

	import type { SqmConfig, SqmOverhead, SqmDiffserv, NetworkInterfaceInfo } from "$lib/api/types";

	interface Props {
		sqm: SqmConfig;
		availableInterfaces: NetworkInterfaceInfo[];
		detectedWan?: string | null;
		onUpdate: (updated: SqmConfig) => void;
	}

	let { sqm, availableInterfaces, detectedWan = null, onUpdate }: Props = $props();

	let advancedOpen = $state(false);

	function updateField<K extends keyof SqmConfig>(key: K, value: SqmConfig[K]) {
		onUpdate({ ...sqm, [key]: value });
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
					<GaugeIcon class="size-5" />
				</div>
				<div class="flex flex-col gap-1">
					<div class="flex items-center gap-2">
						<h3 class="text-base font-semibold text-foreground">Habilitar Modelagem SQM (CAKE)</h3>
						<HelpPopover
							title="Smart Queue Management (CAKE)"
							description="Algoritmo avançado do kernel Linux para eliminação de Bufferbloat."
						>
							<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
								<p>
									<strong class="text-foreground">Como funciona:</strong> O CAKE substitui as filas FIFO tradicionais por gerenciamento inteligente de fluxos e controle de atraso ativo (CoDel).
								</p>
								<p>
									<strong class="text-foreground">Resultado Prático:</strong> Mantém a latência em jogos online e chamadas de vídeo estável (&lt;10ms) mesmo quando múltiplos usuários estão fazendo downloads de alta velocidade ou streaming na mesma rede.
								</p>
								<p>
									<strong class="text-emerald-500 font-semibold">Precedência de Kernel:</strong> Quando habilitado, o flow offload do firewall é automaticamente suprimido para permitir que todos os pacotes sejam dosados pelas filas do CAKE.
								</p>
							</div>
						</HelpPopover>
						<Badge variant={sqm.enabled ? "default" : "secondary"} class="text-[10px]">
							{sqm.enabled ? "Habilitado" : "Desabilitado"}
						</Badge>
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed max-w-2xl">
						Elimina engasgos e picos de ping modelando o tráfego de upload e download exatamente na taxa suportada pelo seu provedor de Internet (ISP).
					</p>
				</div>
			</div>

			<div class="flex items-center pt-1">
				<Switch
					checked={sqm.enabled}
					onCheckedChange={(val) => updateField("enabled", val)}
					aria-label="Habilitar Modelagem SQM"
				/>
			</div>
		</div>
	</Card.Root>

	{#if sqm.enabled}
		<!-- Bandwidth & Interface Configuration Card -->
		<Card.Root class="p-5 flex flex-col gap-5 border-border">
			<div class="flex items-center justify-between border-b pb-3">
				<div>
					<h4 class="text-sm font-semibold text-foreground">Largura de Banda e Interface</h4>
					<p class="text-xs text-muted-foreground">
						Defina os limites de banda e a interface onde o CAKE será anexado.
					</p>
				</div>
			</div>

			<div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
				<!-- WAN Interface -->
				<div class="flex flex-col gap-1.5">
					<label for="wan-iface" class="text-xs font-medium text-foreground flex items-center gap-1.5">
						Interface WAN / Uplink
						<InfoPopover
							title="Interface Alvo"
							description="Interface por onde chega o tráfego da Internet."
						>
							<p class="text-xs text-muted-foreground leading-relaxed">
								<strong>Auto-detectar (Recomendado):</strong> O Lanforge seleciona a sessão PPPoE ativa (ex: <code>ppp0</code>) se houver, ou a interface física WAN principal.
							</p>
						</InfoPopover>
					</label>
					<select
						id="wan-iface"
						class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
						value={sqm.interface}
						onchange={(e) => updateField("interface", (e.target as HTMLSelectElement).value)}
					>
						<option value="auto">
							Auto-detectar {detectedWan ? `(${detectedWan})` : ""}
						</option>
						{#each eligibleInterfaces as iface}
							<option value={iface.name}>{iface.name} ({iface.bus_type})</option>
						{/each}
					</select>
				</div>

				<!-- Download Bandwidth -->
				<div class="flex flex-col gap-1.5">
					<label for="sqm-down" class="text-xs font-medium text-foreground flex items-center justify-between">
						<span>Download (Mbps)</span>
						<span class="text-[11px] text-muted-foreground font-mono">~90-95% contratado</span>
					</label>
					<div class="relative">
						<Input
							id="sqm-down"
							type="number"
							min="0"
							step="5"
							value={sqm.download_mbps}
							oninput={(e) => updateField("download_mbps", Number((e.target as HTMLInputElement).value))}
							placeholder="Ex: 450"
							class="pr-14"
						/>
						<span class="absolute right-3 top-2 text-xs font-mono text-muted-foreground">Mbps</span>
					</div>
					<span class="text-[11px] text-muted-foreground">
						{sqm.download_mbps > 0 ? `Modelando download em ${sqm.download_mbps} Mbps via IFB` : "0 = Ilimitado (sem shaper de download)"}
					</span>
				</div>

				<!-- Upload Bandwidth -->
				<div class="flex flex-col gap-1.5">
					<label for="sqm-up" class="text-xs font-medium text-foreground flex items-center justify-between">
						<span>Upload (Mbps)</span>
						<span class="text-[11px] text-muted-foreground font-mono">~90-95% contratado</span>
					</label>
					<div class="relative">
						<Input
							id="sqm-up"
							type="number"
							min="0"
							step="5"
							value={sqm.upload_mbps}
							oninput={(e) => updateField("upload_mbps", Number((e.target as HTMLInputElement).value))}
							placeholder="Ex: 225"
							class="pr-14"
						/>
						<span class="absolute right-3 top-2 text-xs font-mono text-muted-foreground">Mbps</span>
					</div>
					<span class="text-[11px] text-muted-foreground">
						{sqm.upload_mbps > 0 ? `Modelando upload em ${sqm.upload_mbps} Mbps direto na WAN` : "0 = Ilimitado (sem shaper de upload)"}
					</span>
				</div>
			</div>
		</Card.Root>

		<!-- CAKE Tuning & Profiles Card -->
		<Card.Root class="p-5 flex flex-col gap-5 border-border">
			<div class="flex items-center justify-between border-b pb-3">
				<div>
					<h4 class="text-sm font-semibold text-foreground">Perfis de Fila e Compensação de Framing</h4>
					<p class="text-xs text-muted-foreground">
						Ajustes de priorização DiffServ, overhead de link físico e justiça entre hosts.
					</p>
				</div>
			</div>

			<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
				<!-- Framing Overhead -->
				<div class="flex flex-col gap-1.5">
					<label for="sqm-overhead" class="text-xs font-medium text-foreground flex items-center gap-1.5">
						Compensação de Overhead
						<InfoPopover
							title="Overhead de Framing"
							description="Compensa os bytes adicionais adicionados pela tecnologia de acesso do provedor."
						>
							<div class="flex flex-col gap-1.5 text-xs text-muted-foreground">
								<p><strong>Auto:</strong> Detecta automaticamente PPPoE (+34 bytes) ou Ethernet (+14 bytes).</p>
								<p><strong>PPPoE:</strong> +34 bytes (PPP + PPPoE header + FCS).</p>
								<p><strong>Ethernet:</strong> +14 bytes (MAC header + CRC).</p>
								<p><strong>DOCSIS:</strong> +18 bytes (Cable modem encapsulation).</p>
							</div>
						</InfoPopover>
					</label>
					<select
						id="sqm-overhead"
						class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
						value={sqm.overhead}
						onchange={(e) => updateField("overhead", (e.target as HTMLSelectElement).value as SqmOverhead)}
					>
						<option value="auto">Auto-detectar (Recomendado)</option>
						<option value="pppoe">PPPoE (+34 bytes - FTTH / DSL)</option>
						<option value="ethernet">Ethernet (+14 bytes - IPoE / DHCP)</option>
						<option value="docsis">DOCSIS (+18 bytes - Cabo Coaxial)</option>
						<option value="none">Nenhum (0 bytes)</option>
					</select>
				</div>

				<!-- DiffServ Mode -->
				<div class="flex flex-col gap-1.5">
					<label for="sqm-diffserv" class="text-xs font-medium text-foreground flex items-center gap-1.5">
						Classificação DiffServ / Priorização
						<InfoPopover
							title="Perfis DiffServ no CAKE"
							description="Classifica pacotes em sub-filas de prioridade com base nos bits DSCP/TOS."
						>
							<div class="flex flex-col gap-1.5 text-xs text-muted-foreground">
								<p><strong>diffserv4 (Padrão):</strong> 4 filas (Voz/Gaming, Vídeo, Best-effort e Background/Torrents).</p>
								<p><strong>diffserv3:</strong> 3 filas simplificadas.</p>
								<p><strong>besteffort:</strong> Fila única, sem separação DSCP.</p>
							</div>
						</InfoPopover>
					</label>
					<select
						id="sqm-diffserv"
						class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
						value={sqm.diffserv}
						onchange={(e) => updateField("diffserv", (e.target as HTMLSelectElement).value as SqmDiffserv)}
					>
						<option value="diffserv4">diffserv4 (Recomendado: Gaming, VoIP, Vídeo e Best-effort)</option>
						<option value="diffserv3">diffserv3 (3 níveis de prioridade)</option>
						<option value="besteffort">besteffort (Sem diferenciação por DSCP)</option>
					</select>
				</div>
			</div>

			<!-- Per-Host Isolation Toggle -->
			<div class="flex items-start justify-between gap-4 pt-2 border-t">
				<div class="flex items-start gap-3">
					<div class="flex size-9 items-center justify-center rounded-lg bg-emerald-500/10 text-emerald-500 shrink-0 mt-0.5">
						<UsersIcon class="size-4" />
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-sm font-medium text-foreground">Isolamento Justo por Dispositivo (Per-Host Fairness)</span>
						<p class="text-xs text-muted-foreground leading-relaxed max-w-xl">
							Aplica <code>nat dual-srchost / dual-dsthost</code>. Garante que fluxos de um dispositivo da rede interna (ex: console de jogos ou PC de trabalho) não sejam estrangulados quando outro computador iniciar downloads massivos.
						</p>
					</div>
				</div>
				<Switch
					checked={sqm.per_host_isolation}
					onCheckedChange={(val) => updateField("per_host_isolation", val)}
					aria-label="Isolamento Justo por Dispositivo"
				/>
			</div>
		</Card.Root>

		<!-- Advanced Parameters Collapsible -->
		<Collapsible.Root bind:open={advancedOpen} class="flex flex-col gap-2">
			<Card.Root class="p-4 border-border">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<SlidersIcon class="size-4 text-muted-foreground" />
						<span class="text-xs font-semibold text-foreground uppercase tracking-wider">Parâmetros Avançados de Kernel & TC</span>
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
						<!-- Target RTT -->
						<div class="flex flex-col gap-1.5">
							<label for="sqm-rtt" class="text-xs font-medium text-foreground">
								Target RTT (ms) - Opcional
							</label>
							<Input
								id="sqm-rtt"
								type="number"
								min="0"
								step="10"
								value={sqm.rtt_ms ?? ""}
								oninput={(e) => {
									const v = (e.target as HTMLInputElement).value;
									updateField("rtt_ms", v ? Number(v) : null);
								}}
								placeholder="Padrão: automático (100ms)"
							/>
							<span class="text-[11px] text-muted-foreground">
								Deixe em branco para usar o RTT padrão do algoritmo CAKE (100ms para Internet global).
							</span>
						</div>

						<!-- Ingress Device Name -->
						<div class="flex flex-col gap-1.5">
							<label for="sqm-ifb" class="text-xs font-medium text-foreground">
								Dispositivo Virtual de Ingresso (IFB)
							</label>
							<Input
								id="sqm-ifb"
								type="text"
								value={sqm.ingress_device}
								oninput={(e) => updateField("ingress_device", (e.target as HTMLInputElement).value)}
								placeholder="auto"
							/>
							<span class="text-[11px] text-muted-foreground">
								Nome da interface intermediária criada no kernel. Padrão: <code>auto</code> (gera <code>ifb4&lt;iface&gt;</code>).
							</span>
						</div>
					</div>

					<!-- Raw CAKE CLI Args -->
					<div class="flex flex-col gap-1.5">
						<label for="sqm-raw-args" class="text-xs font-medium text-foreground">
							Argumentos Extras para o CAKE (CLI tc)
						</label>
						<Input
							id="sqm-raw-args"
							type="text"
							value={sqm.raw_cake_args ?? ""}
							oninput={(e) => {
								const v = (e.target as HTMLInputElement).value.trim();
								updateField("raw_cake_args", v ? v : null);
							}}
							placeholder="Ex: ack-filter wash nonat"
							class="font-mono text-xs"
						/>
						<span class="text-[11px] text-muted-foreground">
							Argumentos adicionais repassados diretamente para a invocação de <code>tc qdisc add ... cake</code>.
						</span>
					</div>
				</Collapsible.Content>
			</Card.Root>
		</Collapsible.Root>
	{/if}
</div>
