<script lang="ts">
	import * as Tabs from "$lib/components/ui/tabs";
	import { Button } from "$lib/components/ui/button";
	import { Switch } from "$lib/components/ui/switch";
	import { Badge } from "$lib/components/ui/badge";
	import { Separator } from "$lib/components/ui/separator";
	import { Spinner } from "$lib/components/ui/spinner";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";

	import ShieldIcon from "@lucide/svelte/icons/shield";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import ZapIcon from "@lucide/svelte/icons/zap";

	import {
		firewallStatus,
		firewallConfig,
		firewallPropose,
		firewallCommit,
		firewallConfirm,
		firewallAbort,
	} from "$lib/api/client";
	import type {
		FirewallConfig,
		FirewallStatus,
		FirewallValidationReport,
	} from "$lib/api/types";

	import FirewallStatusBar from "./components/FirewallStatusBar.svelte";
	import ZonesTab from "./components/ZonesTab.svelte";
	import MatrixTab from "./components/MatrixTab.svelte";
	import PortForwardTab from "./components/PortForwardTab.svelte";
	import HostRulesTab from "./components/HostRulesTab.svelte";
	import ProposeModal from "./components/ProposeModal.svelte";

	// ---------------------------------------------------------------------------
	// Page state
	// ---------------------------------------------------------------------------

	let fwStatus = $state<FirewallStatus | null>(null);
	let serverConfig = $state<FirewallConfig | null>(null);
	let draft = $state<FirewallConfig | null>(null);

	let loading = $state(true);
	let proposing = $state(false);
	let committing = $state(false);

	let activeTab = $state("zones");
	let highlightedZone = $state<string | null>(null);

	// 3-way handshake state
	let showProposeModal = $state(false);
	let validationReport = $state<FirewallValidationReport | null>(null);
	let activeTxId = $state<string | null>(null);

	// Auto-rollback countdown
	let rollbackSecsLeft = $state<number | null>(null);
	let rollbackInterval: ReturnType<typeof setInterval> | null = null;

	// Polling interval for status
	let statusInterval: ReturnType<typeof setInterval> | null = null;

	// ---------------------------------------------------------------------------
	// Derived
	// ---------------------------------------------------------------------------

	const isDirty = $derived.by(() => {
		if (!draft || !serverConfig) return false;
		return JSON.stringify(draft) !== JSON.stringify(serverConfig);
	});

	const changeCount = $derived.by(() => {
		if (!isDirty || !draft || !serverConfig) return 0;
		let count = 0;
		if (draft.enabled !== serverConfig.enabled) count++;
		if (draft.flow_offload !== serverConfig.flow_offload) count++;
		const draftZones = JSON.stringify(draft.zones);
		const serverZones = JSON.stringify(serverConfig.zones);
		if (draftZones !== serverZones) count++;
		const draftFwd = JSON.stringify(draft.forwardings);
		const serverFwd = JSON.stringify(serverConfig.forwardings);
		if (draftFwd !== serverFwd) count++;
		const draftPf = JSON.stringify(draft.port_forwards);
		const serverPf = JSON.stringify(serverConfig.port_forwards);
		if (draftPf !== serverPf) count++;
		return Math.max(count, 1);
	});

	// ---------------------------------------------------------------------------
	// Data loading
	// ---------------------------------------------------------------------------

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const [s, c] = await Promise.all([
				firewallStatus().catch(() => null),
				firewallConfig().catch(() => null),
			]);
			fwStatus = s;
			if (c) {
				serverConfig = c;
				// Only reset draft if user hasn't made local changes
				if (!isDirty) {
					draft = structuredClone(c);
				}
			}
		} catch {
			if (!silent) toast.error("Falha ao carregar configuração do firewall");
		} finally {
			if (!silent) loading = false;
		}
	}

	// ---------------------------------------------------------------------------
	// Draft mutations
	// ---------------------------------------------------------------------------

	function handleGlobalToggle(key: "enabled" | "flow_offload", value: boolean) {
		if (!draft) return;
		draft = { ...draft, [key]: value };
	}

	// ---------------------------------------------------------------------------
	// 3-way handshake
	// ---------------------------------------------------------------------------

	async function handlePropose() {
		if (!draft) return;
		proposing = true;
		validationReport = null;
		showProposeModal = true;
		try {
			const report = await firewallPropose(draft);
			validationReport = report;
			if (report.valid && report.tx_id) {
				activeTxId = report.tx_id;
			}
		} catch (e: unknown) {
			showProposeModal = false;
			toast.error(e instanceof Error ? e.message : "Erro ao validar configuração");
		} finally {
			proposing = false;
		}
	}

	async function handleCommit() {
		if (!activeTxId) return;
		committing = true;
		try {
			const resp = await firewallCommit({ tx_id: activeTxId, auto_rollback_secs: 20 });
			if (resp.success) {
				showProposeModal = false;
				if (resp.auto_rollback_active && resp.rollback_deadline_secs) {
					startRollbackCountdown(resp.rollback_deadline_secs);
					toast.info("Regras aplicadas — confirmando conexão para evitar rollback…");
				} else {
					toast.success("Firewall atualizado com sucesso");
					activeTxId = null;
					await loadAll(true);
				}
			} else {
				toast.error(resp.message || "Falha ao aplicar regras");
			}
		} catch (e: unknown) {
			toast.error(e instanceof Error ? e.message : "Erro ao aplicar regras");
		} finally {
			committing = false;
		}
	}

	async function handleConfirm() {
		if (!activeTxId) return;
		try {
			await firewallConfirm(activeTxId);
			stopRollbackCountdown();
			activeTxId = null;
			toast.success("Configuração confirmada e aplicada definitivamente");
			await loadAll(true);
		} catch {
			toast.error("Falha ao confirmar transação");
		}
	}

	async function handleAbort() {
		if (!activeTxId) return;
		try {
			await firewallAbort(activeTxId);
		} catch {
			// best-effort
		}
		stopRollbackCountdown();
		activeTxId = null;
		showProposeModal = false;
		validationReport = null;
		toast.info("Transação abortada — configuração anterior mantida");
	}

	function handleDiscard() {
		if (!serverConfig) return;
		draft = structuredClone(serverConfig);
		toast.info("Alterações descartadas");
	}

	// ---------------------------------------------------------------------------
	// Auto-rollback countdown
	// ---------------------------------------------------------------------------

	function startRollbackCountdown(secs: number) {
		rollbackSecsLeft = secs;
		rollbackInterval = setInterval(() => {
			if (rollbackSecsLeft === null) return;
			rollbackSecsLeft--;
			if (rollbackSecsLeft <= 0) {
				stopRollbackCountdown();
				activeTxId = null;
				toast.error("Rollback automático executado — regras anteriores restauradas");
				loadAll(true);
			}
		}, 1000);
	}

	function stopRollbackCountdown() {
		rollbackSecsLeft = null;
		if (rollbackInterval) {
			clearInterval(rollbackInterval);
			rollbackInterval = null;
		}
	}

	// ---------------------------------------------------------------------------
	// Lifecycle
	// ---------------------------------------------------------------------------

	onMount(() => {
		loadAll();
		statusInterval = setInterval(() => loadAll(true), 10_000);
	});

	onDestroy(() => {
		if (statusInterval) clearInterval(statusInterval);
		if (rollbackInterval) clearInterval(rollbackInterval);
	});
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- Page Header -->
	<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
		<div class="flex items-center gap-3.5">
			<div class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0">
				<ShieldIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-1">
				<div class="flex flex-wrap items-center gap-2.5">
					<h1 class="text-2xl font-bold tracking-tight">Firewall</h1>
					{#if draft?.enabled}
						<Badge
							variant="outline"
							class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
						>
							<span class="relative flex size-2 mr-1.5">
								<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
								<span class="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
							</span>
							Ativo
						</Badge>
					{:else if draft !== null}
						<Badge variant="secondary" class="text-muted-foreground text-xs font-medium">
							Desativado
						</Badge>
					{/if}
				</div>
				<p class="text-sm text-muted-foreground">
					Zonas, políticas de tráfego, DNAT e filtragem baseada em nftables.
				</p>
			</div>
		</div>

		<!-- Global toggles + refresh -->
		<div class="flex flex-wrap items-center gap-3">
			{#if draft !== null}
				<div class="flex items-center gap-2 text-sm">
					<Switch
						checked={draft.flow_offload}
						onCheckedChange={(v) => handleGlobalToggle("flow_offload", v)}
					/>
					<span class="text-muted-foreground flex items-center gap-1">
						<ZapIcon class="size-3.5" />
						Flow Offload
					</span>
				</div>
				<Separator orientation="vertical" class="h-5" />
				<div class="flex items-center gap-2 text-sm">
					<Switch
						checked={draft.enabled}
						onCheckedChange={(v) => handleGlobalToggle("enabled", v)}
					/>
					<span class="text-muted-foreground">Firewall</span>
				</div>
			{/if}
			<Separator orientation="vertical" class="h-5" />
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={loading ? "animate-spin" : ""} data-icon="inline-start" />
				Atualizar
			</Button>
		</div>
	</div>

	<!-- Live Status Bar -->
	<FirewallStatusBar
		status={fwStatus}
		{loading}
		{activeTxId}
		{rollbackSecsLeft}
		onAbort={handleAbort}
		onConfirmNow={handleConfirm}
	/>

	<!-- Main Tabs -->
	{#if loading && draft === null}
		<div class="flex flex-col gap-4">
			<div class="h-10 w-72 bg-muted rounded-xl animate-pulse"></div>
			<div class="h-64 w-full bg-muted rounded-2xl animate-pulse"></div>
		</div>
	{:else if draft !== null}
		<Tabs.Root bind:value={activeTab} class="w-full">
			<Tabs.List class="flex w-full overflow-x-auto justify-start sm:inline-flex sm:w-auto p-1 mb-4 no-scrollbar">
				<Tabs.Trigger value="zones">Zonas</Tabs.Trigger>
				<Tabs.Trigger value="matrix">Matriz de Tráfego</Tabs.Trigger>
				<Tabs.Trigger value="portforward">Port Forwarding</Tabs.Trigger>
				<Tabs.Trigger value="hostrules">Regras do Host</Tabs.Trigger>
			</Tabs.List>

			<Tabs.Content value="zones">
				<ZonesTab
					zones={draft.zones}
					{highlightedZone}
					onUpdate={(zones) => { if (draft) draft = { ...draft, zones }; }}
				/>
			</Tabs.Content>

			<Tabs.Content value="matrix">
				<MatrixTab
					zones={draft.zones}
					forwardings={draft.forwardings}
					{highlightedZone}
					onUpdate={(forwardings) => { if (draft) draft = { ...draft, forwardings }; }}
				/>
			</Tabs.Content>

			<Tabs.Content value="portforward">
				<PortForwardTab
					rules={draft.port_forwards}
					zones={draft.zones}
					onUpdate={(port_forwards) => { if (draft) draft = { ...draft, port_forwards }; }}
				/>
			</Tabs.Content>

			<Tabs.Content value="hostrules">
				<HostRulesTab
					zones={draft.zones}
					portForwards={draft.port_forwards}
					onZonesUpdate={(zones) => { if (draft) draft = { ...draft, zones }; }}
					onPortForwardsUpdate={(port_forwards) => { if (draft) draft = { ...draft, port_forwards }; }}
				/>
			</Tabs.Content>
		</Tabs.Root>
	{/if}

	<!-- Propose / Review Modal -->
	<ProposeModal
		open={showProposeModal}
		report={validationReport}
		{committing}
		{rollbackSecsLeft}
		onConfirm={handleCommit}
		onAbort={handleAbort}
		onClose={() => {
			showProposeModal = false;
			if (!activeTxId) validationReport = null;
		}}
	/>

	<!-- Floating pending changes bar -->
	{#if isDirty && !showProposeModal}
		<div
			transition:fly={{ y: 24, duration: 220, easing: cubicOut }}
			class="sticky bottom-4 z-30 flex items-center justify-between p-3.5 sm:p-4 rounded-xl border bg-card/90 backdrop-blur-md shadow-2xl border-primary/40 transform-gpu will-change-[transform,opacity] gap-4"
		>
			<div class="flex items-center gap-2.5">
				<span class="relative flex size-2.5">
					<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
					<span class="relative inline-flex rounded-full size-2.5 bg-amber-500"></span>
				</span>
				<div class="flex flex-col sm:flex-row sm:items-center sm:gap-2">
					<span class="text-xs font-semibold text-foreground">
						{changeCount} {changeCount === 1 ? "alteração pendente" : "alterações pendentes"}
					</span>
					<span class="text-[11px] text-muted-foreground hidden sm:inline">
						Revise e aplique para atualizar as regras no daemon
					</span>
				</div>
			</div>

			<div class="flex items-center gap-2 shrink-0">
				<Button
					variant="outline"
					size="sm"
					onclick={handleDiscard}
					disabled={proposing}
					class="h-8 text-xs transition-transform duration-150 active:scale-95 transform-gpu"
				>
					<RotateCcwIcon data-icon="inline-start" />
					Descartar
				</Button>

				<Button
					variant="default"
					size="sm"
					onclick={handlePropose}
					disabled={proposing}
					class="h-8 text-xs shadow-sm transition-all duration-150 hover:shadow-primary/20 hover:shadow-md active:scale-95 transform-gpu"
				>
					{#if proposing}
						<Spinner data-icon="inline-start" />
						Validando…
					{:else}
						<ShieldIcon data-icon="inline-start" />
						Revisar & Aplicar
					{/if}
				</Button>
			</div>
		</div>
	{/if}
</div>
