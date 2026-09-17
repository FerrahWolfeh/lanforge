<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import MoonIcon from "@lucide/svelte/icons/moon";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import InfoPopover from "$lib/components/InfoPopover.svelte";

	import type { TrafficStatusResponse } from "$lib/api/types";

	interface Props {
		status?: TrafficStatusResponse | null;
	}

	let { status = null }: Props = $props();

	const stateStr = $derived((status?.service_state ?? "inactive").toLowerCase());
	const isOnline = $derived(stateStr === "online" || stateStr === "active");
	const isStarting = $derived(stateStr === "starting");
	const isInactive = $derived(stateStr === "inactive" || stateStr === "offline");
</script>

<div class="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-4">
	<!-- 1. Runtime Subsystem State -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span class="flex items-center gap-1.5">
					Estado em Runtime
					<InfoPopover
						title="Ciclo de Vida do Subsistema"
						description="Indica a condição operacional do serviço no supervisor do daemon."
					>
						<p class="text-xs text-muted-foreground leading-relaxed">
							<strong>Em Execução:</strong> O daemon está aplicando configurações de fila ou tuning no kernel.<br />
							<strong>Dormente:</strong> O serviço está carregado, mas em repouso (módulos desativados ou aguardando uplink WAN).
						</p>
					</InfoPopover>
				</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						isOnline
							? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
							: isStarting
								? "border-amber-500/30 bg-amber-500/10 text-amber-400 animate-pulse"
								: "border-border text-muted-foreground",
					].join(" ")}
				>
					{isOnline ? "Online" : isStarting ? "Starting" : "Dormant"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if isOnline}
					<CheckCircleIcon class="size-5 text-emerald-500 shrink-0" />
					<span class="text-base font-bold text-emerald-400">Em Execução</span>
				{:else if isStarting}
					<RefreshCwIcon class="size-5 text-amber-500 shrink-0 animate-spin" />
					<span class="text-base text-amber-400 font-bold">Iniciando...</span>
				{:else}
					<MoonIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Dormente (Standby)</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Supervisor</span>
					<span class="font-medium text-foreground">Supervisionado</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Isolamento</span>
					<span class="font-mono text-emerald-500">~10ms Restart</span>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- 2. Smart Queue Management (SQM CAKE) -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>CAKE Shaper</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						status?.sqm_active
							? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
							: "border-border text-muted-foreground",
					].join(" ")}
				>
					{status?.sqm_active ? "Ativo" : "Inativo"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if status?.sqm_active}
					<GaugeIcon class="size-5 text-emerald-500 shrink-0" />
					<span class="text-base font-bold text-foreground">
						{status.download_mbps}M / {status.upload_mbps}M
					</span>
				{:else}
					<XCircleIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Sem Shaper</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Interface WAN</span>
					<span class="font-mono font-medium text-foreground truncate">
						{status?.wan_interface ?? "Nenhuma"}
					</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Ingresso Mirror</span>
					<span class="font-mono text-[11px] text-muted-foreground truncate">
						{status?.ingress_device ?? "Nenhum"}
					</span>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- 3. Hardware & NIC Tuning -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Tuning de Hardware</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						status?.tuning_applied
							? "border-primary/30 bg-primary/10 text-primary"
							: "border-border text-muted-foreground",
					].join(" ")}
				>
					{status?.tuning_applied ? "Otimizado" : "Padrão"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if status?.tuning_applied}
					<CpuIcon class="size-5 text-primary shrink-0" />
					<span class="text-base font-bold text-foreground">
						{status.tuned_interfaces.length} NIC{status.tuned_interfaces.length === 1 ? '' : 's'} Otimizada{status.tuned_interfaces.length === 1 ? '' : 's'}
					</span>
				{:else}
					<CpuIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Padrão do Kernel</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Máscara RPS</span>
					<span class="font-mono font-medium text-foreground">
						{status?.effective_cpu_mask ? `0x${status.effective_cpu_mask}` : "N/A"}
					</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Interfaces</span>
					<span class="font-mono text-[11px] text-muted-foreground truncate" title={status?.tuned_interfaces?.join(", ") ?? ""}>
						{status?.tuned_interfaces?.join(", ") || "Nenhuma"}
					</span>
				</div>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- 4. Firewall Coexistence -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Coexistência Firewall</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						status?.flow_offload_suppressed
							? "border-amber-500/30 bg-amber-500/10 text-amber-500"
							: "border-border text-muted-foreground",
					].join(" ")}
				>
					{status?.flow_offload_suppressed ? "Offload Suspenso" : "Padrão"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if status?.flow_offload_suppressed}
					<ShieldAlertIcon class="size-5 text-amber-500 shrink-0" />
					<span class="text-base font-bold text-foreground">Precedência TC</span>
				{:else}
					<ShieldCheckIcon class="size-5 text-emerald-500 shrink-0" />
					<span class="text-base text-foreground font-medium">Harmonizado</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Flowtable</span>
					<span class="font-medium text-foreground">
						{status?.flow_offload_suppressed ? "Bypass Evitado" : "Normal"}
					</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Bufferbloat</span>
					<span class="font-medium text-emerald-500">
						{status?.sqm_active ? "Garantido" : "Inativo"}
					</span>
				</div>
			</div>
		</Card.Content>
	</Card.Root>
</div>
