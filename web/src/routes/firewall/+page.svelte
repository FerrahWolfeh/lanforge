<script lang="ts">
	import * as Tabs from "$lib/components/ui/tabs";
	import * as Card from "$lib/components/ui/card";
	import * as Alert from "$lib/components/ui/alert";
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
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import InfoIcon from "@lucide/svelte/icons/info";

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
		FirewallMode,
	} from "$lib/api/types";

	import FirewallStatsCards from "./components/FirewallStatsCards.svelte";
	import FirewallModeSelector from "./components/FirewallModeSelector.svelte";
	import FirewallTuningCard from "./components/FirewallTuningCard.svelte";
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
		if (draft.mode !== serverConfig.mode) count++;
		if (draft.enabled !== serverConfig.enabled) count++;
		if (draft.flow_offload !== serverConfig.flow_offload) count++;
		if (JSON.stringify(draft.zones) !== JSON.stringify(serverConfig.zones)) count++;
		if (JSON.stringify(draft.forwardings) !== JSON.stringify(serverConfig.forwardings)) count++;
		if (JSON.stringify(draft.port_forwards) !== JSON.stringify(serverConfig.port_forwards)) count++;
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
			if (!silent) toast.error("Failed to load firewall configuration");
		} finally {
			if (!silent) loading = false;
		}
	}

	// ---------------------------------------------------------------------------
	// Draft mutations
	// ---------------------------------------------------------------------------

	function handleModeChange(newMode: FirewallMode) {
		if (!draft) return;
		draft = {
			...draft,
			mode: newMode,
			enabled: newMode !== "disabled",
		};
	}

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
			toast.error(e instanceof Error ? e.message : "Failed to validate firewall configuration");
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
					toast.info("Rules applied — confirming connection to avoid rollback…");
				} else {
					toast.success("Firewall updated successfully");
					activeTxId = null;
					await loadAll(true);
				}
			} else {
				toast.error(resp.message || "Failed to commit firewall rules");
			}
		} catch (e: unknown) {
			toast.error(e instanceof Error ? e.message : "Failed to commit firewall rules");
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
			toast.success("Configuration confirmed and permanently persisted");
			await loadAll(true);
		} catch {
			toast.error("Failed to confirm transaction");
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
		toast.info("Transaction aborted — previous firewall configuration preserved");
	}

	function handleDiscard() {
		if (!serverConfig) return;
		draft = structuredClone(serverConfig);
		toast.info("Pending changes discarded");
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
				toast.error("Automatic rollback executed — previous rules restored");
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

<div class="flex flex-col gap-6 w-full pb-16">
	<!-- Page Header -->
	<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
		<div class="flex items-center gap-3.5">
			<div class="flex size-11 items-center justify-center rounded-2xl bg-primary/10 text-primary shrink-0">
				<ShieldIcon class="size-6" />
			</div>
			<div class="flex flex-col gap-1">
				<div class="flex flex-wrap items-center gap-2.5">
					<h1 class="text-2xl font-bold tracking-tight">Firewall & Security</h1>
					{#if draft?.mode === "full"}
						<Badge
							variant="outline"
							class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
						>
							<span class="relative flex size-2 mr-1.5">
								<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
								<span class="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
							</span>
							Full Router
						</Badge>
					{:else if draft?.mode === "minimal"}
						<Badge variant="outline" class="border-primary/25 bg-primary/10 text-primary font-medium text-xs">
							Minimal Helper
						</Badge>
					{:else if draft !== null}
						<Badge variant="secondary" class="text-muted-foreground text-xs font-medium">
							Disabled
						</Badge>
					{/if}
				</div>
				<p class="text-sm text-muted-foreground">
					Standalone router zones, traffic matrix, DNAT, and nftables packet filtering.
				</p>
			</div>
		</div>

		<!-- Action buttons -->
		<div class="flex flex-wrap items-center gap-2.5">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading}
				class="transition-transform duration-150 active:scale-95 transform-gpu"
			>
				<RefreshCwIcon class={loading ? "animate-spin" : ""} data-icon="inline-start" />
				Refresh
			</Button>

			{#if isDirty}
				<Button
					variant="outline"
					size="sm"
					onclick={handleDiscard}
					disabled={proposing}
					class="transition-transform duration-150 active:scale-95 transform-gpu"
				>
					<RotateCcwIcon data-icon="inline-start" />
					Discard
				</Button>
				<Button
					variant="default"
					size="sm"
					onclick={handlePropose}
					disabled={proposing}
					class="shadow-xs transition-transform duration-150 active:scale-95 transform-gpu"
				>
					{#if proposing}
						<Spinner data-icon="inline-start" />
						Validating…
					{:else}
						<ShieldIcon data-icon="inline-start" />
						Review & Apply
					{/if}
				</Button>
			{/if}
		</div>
	</div>

	<!-- Live Status Cards Grid -->
	<FirewallStatsCards
		status={fwStatus}
		{loading}
		{activeTxId}
		{rollbackSecsLeft}
		onAbort={handleAbort}
		onConfirmNow={handleConfirm}
	/>

	<!-- Operation Mode Selector Card -->
	{#if draft !== null}
		<Card.Root class="p-5">
			<div class="flex items-center justify-between mb-3">
				<div>
					<h3 class="text-sm font-semibold text-foreground">Operation Mode</h3>
					<p class="text-xs text-muted-foreground">
						Select the role Lanforge plays in host packet filtering and routing offload.
					</p>
				</div>
			</div>
			<FirewallModeSelector
				mode={draft.mode}
				onSelect={handleModeChange}
				disabled={committing || proposing}
			/>
		</Card.Root>
	{/if}

	<!-- Main Content / Mode-Specific Views -->
	{#if loading && draft === null}
		<div class="flex flex-col gap-4">
			<div class="h-10 w-72 bg-muted rounded-xl animate-pulse"></div>
			<div class="h-64 w-full bg-muted rounded-2xl animate-pulse"></div>
		</div>
	{:else if draft !== null}
		{#if draft.mode === "full"}
			<!-- Full Standalone Router: 5 Tabs -->
			<Tabs.Root bind:value={activeTab} class="w-full">
				<Tabs.List class="flex w-full overflow-x-auto justify-start sm:inline-flex sm:w-auto p-1 mb-4 no-scrollbar">
					<Tabs.Trigger value="zones">Zones</Tabs.Trigger>
					<Tabs.Trigger value="matrix">Traffic Matrix</Tabs.Trigger>
					<Tabs.Trigger value="portforward">Port Forwarding</Tabs.Trigger>
					<Tabs.Trigger value="hostrules">Host Rules</Tabs.Trigger>
					<Tabs.Trigger value="tuning">Acceleration & Tuning</Tabs.Trigger>
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

				<Tabs.Content value="tuning">
					<FirewallTuningCard
						flowOffload={draft.flow_offload}
						onToggleFlowOffload={(v) => handleGlobalToggle("flow_offload", v)}
					/>
				</Tabs.Content>
			</Tabs.Root>

		{:else if draft.mode === "minimal"}
			<!-- Minimal Helper Mode: Notice + Tuning Card -->
			<div class="flex flex-col gap-4">
				<Alert.Root class="border-primary/30 bg-primary/5 text-foreground">
					<InfoIcon class="size-4 text-primary" />
					<Alert.Title class="text-sm font-semibold">Minimal Coexistence Mode Active</Alert.Title>
					<Alert.Description class="text-xs text-muted-foreground mt-1 leading-relaxed">
						Lanforge is running as a non-interfering helper table with <code class="font-mono text-foreground font-semibold">policy accept</code> at priority <code class="font-mono text-foreground font-semibold">-10</code>. General packet filtering, zones, and host firewall rules are delegated to your system firewall (<code class="font-mono text-foreground">firewalld</code> or <code class="font-mono text-foreground">ufw</code>). PPPoE hardware Flowtable acceleration, TCP MSS clamping, and NAT masquerading remain active.
					</Alert.Description>
				</Alert.Root>

				<FirewallTuningCard
					flowOffload={draft.flow_offload}
					onToggleFlowOffload={(v) => handleGlobalToggle("flow_offload", v)}
				/>
			</div>

		{:else}
			<!-- Disabled Mode -->
			<Card.Root class="p-8 text-center flex flex-col items-center justify-center gap-3">
				<div class="flex size-12 items-center justify-center rounded-2xl bg-muted text-muted-foreground">
					<ShieldOffIcon class="size-6" />
				</div>
				<div class="flex flex-col gap-1 max-w-md">
					<h3 class="text-base font-semibold text-foreground">Firewall Management Disabled</h3>
					<p class="text-xs text-muted-foreground leading-relaxed">
						Lanforge will not create or maintain any nftables tables or rules in the kernel dataplane. Select <strong>Full Router</strong> or <strong>Minimal Helper</strong> above and click "Review & Apply" to enable firewall orchestration.
					</p>
				</div>
			</Card.Root>
		{/if}
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
			class="fixed bottom-4 left-1/2 -translate-x-1/2 z-30 flex items-center justify-between p-3.5 sm:p-4 rounded-xl border bg-card/90 backdrop-blur-md shadow-2xl border-primary/40 transform-gpu will-change-[transform,opacity] gap-4 w-[92vw] max-w-3xl"
		>
			<div class="flex items-center gap-2.5">
				<span class="relative flex size-2.5">
					<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
					<span class="relative inline-flex rounded-full size-2.5 bg-amber-500"></span>
				</span>
				<div class="flex flex-col sm:flex-row sm:items-center sm:gap-2">
					<span class="text-xs font-semibold text-foreground">
						{changeCount} pending {changeCount === 1 ? "change" : "changes"}
					</span>
					<span class="text-[11px] text-muted-foreground hidden sm:inline">
						Review and apply to commit new rules to the daemon
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
					Discard
				</Button>

				<Button
					variant="default"
					size="sm"
					onclick={handlePropose}
					disabled={proposing}
					class="h-8 text-xs shadow-xs transition-all duration-150 hover:shadow-primary/20 hover:shadow-md active:scale-95 transform-gpu"
				>
					{#if proposing}
						<Spinner data-icon="inline-start" />
						Validating…
					{:else}
						<ShieldIcon data-icon="inline-start" />
						Review & Apply
					{/if}
				</Button>
			</div>
		</div>
	{/if}
</div>
