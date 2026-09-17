<script lang="ts">
	import * as Tabs from "$lib/components/ui/tabs";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import {
		trafficStatus,
		trafficConfig,
		trafficUpdateConfig,
		getSetupStatus,
	} from "$lib/api/client";
	import type {
		TrafficConfig,
		TrafficStatusResponse,
		NetworkInterfaceInfo,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";

	import SlidersHorizontalIcon from "@lucide/svelte/icons/sliders-horizontal";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import GaugeIcon from "@lucide/svelte/icons/gauge";
	import CpuIcon from "@lucide/svelte/icons/cpu";

	import TrafficStatsCards from "./components/TrafficStatsCards.svelte";
	import TrafficSqmTab from "./components/TrafficSqmTab.svelte";
	import TrafficTuningTab from "./components/TrafficTuningTab.svelte";

	// Page state
	let status = $state<TrafficStatusResponse | null>(null);
	let serverConfig = $state<TrafficConfig | null>(null);
	let draft = $state<TrafficConfig | null>(null);
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);

	let loading = $state(true);
	let saving = $state(false);
	let activeTab = $state("sqm");
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

	// Dirty tracking
	const isDirty = $derived.by(() => {
		if (!draft || !serverConfig) return false;
		return JSON.stringify(draft) !== JSON.stringify(serverConfig);
	});

	const changeCount = $derived.by(() => {
		if (!isDirty || !draft || !serverConfig) return 0;
		let count = 0;
		if (draft.sqm.enabled !== serverConfig.sqm.enabled) count++;
		if (draft.sqm.download_mbps !== serverConfig.sqm.download_mbps) count++;
		if (draft.sqm.upload_mbps !== serverConfig.sqm.upload_mbps) count++;
		if (draft.sqm.interface !== serverConfig.sqm.interface) count++;
		if (draft.sqm.overhead !== serverConfig.sqm.overhead) count++;
		if (draft.sqm.diffserv !== serverConfig.sqm.diffserv) count++;
		if (draft.sqm.per_host_isolation !== serverConfig.sqm.per_host_isolation) count++;
		if (draft.tuning.enabled !== serverConfig.tuning.enabled) count++;
		if (draft.tuning.cpu_mask !== serverConfig.tuning.cpu_mask) count++;
		if (draft.tuning.disable_eee !== serverConfig.tuning.disable_eee) count++;
		if (draft.tuning.udp_gro_forwarding !== serverConfig.tuning.udp_gro_forwarding) count++;
		if (JSON.stringify(draft.tuning.interfaces) !== JSON.stringify(serverConfig.tuning.interfaces)) count++;
		return Math.max(count, 1);
	});

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const [s, c, setupRes] = await Promise.all([
				trafficStatus().catch(() => null),
				trafficConfig().catch(() => null),
				getSetupStatus().catch(() => null),
			]);
			status = s;
			if (setupRes?.interfaces) {
				availableInterfaces = setupRes.interfaces;
			}
			if (c) {
				serverConfig = c;
				if (!isDirty) {
					draft = structuredClone(c);
				}
			}
		} catch {
			if (!silent) toast.error("Falha ao carregar configurações de tráfego");
		} finally {
			if (!silent) loading = false;
		}
	}

	function handleDiscard() {
		if (!serverConfig) return;
		draft = structuredClone(serverConfig);
		toast.info("Alterações descartadas");
	}

	async function handleSave() {
		if (!draft) return;
		saving = true;
		try {
			await trafficUpdateConfig(draft);
			serverConfig = structuredClone(draft);
			toast.success("Configuração de tráfego salva e aplicada com sucesso");
			// Refresh status after in-place reload
			setTimeout(() => {
				loadAll(true);
			}, 600);
		} catch (err) {
			toast.error(`Falha ao salvar: ${err instanceof Error ? err.message : String(err)}`);
		} finally {
			saving = false;
		}
	}

	onMount(() => {
		loadAll(false);
		refreshInterval = setInterval(() => {
			trafficStatus()
				.then((s) => {
					status = s;
				})
				.catch(() => {});
		}, 5000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});
</script>

<svelte:head>
	<title>Traffic & SQM — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 max-w-6xl pb-24">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<div class="flex items-center gap-2">
				<SlidersHorizontalIcon class="size-6 text-primary" />
				<h1 class="text-2xl font-bold tracking-tight text-foreground">Traffic & SQM</h1>
			</div>
			<p class="text-xs sm:text-sm text-muted-foreground mt-1">
				Smart Queue Management (CAKE), controle de bufferbloat e otimização de baixo nível para NICs.
			</p>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll(false)}
				disabled={loading}
				class="gap-1.5"
			>
				<RefreshCwIcon class={`size-3.5 ${loading ? "animate-spin" : ""}`} />
				<span>Atualizar</span>
			</Button>
		</div>
	</div>

	<!-- Top Telemetry Status Cards -->
	<TrafficStatsCards {status} />

	{#if loading && !draft}
		<div class="flex items-center justify-center p-12 text-muted-foreground text-sm">
			<RefreshCwIcon class="size-5 animate-spin mr-2" />
			Carregando configurações...
		</div>
	{:else if draft}
		<!-- Main Tabs -->
		<Tabs.Root bind:value={activeTab} class="flex flex-col gap-4">
			<Tabs.List class="grid grid-cols-2 max-w-md">
				<Tabs.Trigger value="sqm" class="gap-2 text-xs">
					<GaugeIcon class="size-4" />
					<span>Bufferbloat (CAKE)</span>
				</Tabs.Trigger>
				<Tabs.Trigger value="tuning" class="gap-2 text-xs">
					<CpuIcon class="size-4" />
					<span>Otimização de NICs</span>
				</Tabs.Trigger>
			</Tabs.List>

			<!-- SQM Tab -->
			<Tabs.Content value="sqm">
				<TrafficSqmTab
					sqm={draft.sqm}
					{availableInterfaces}
					detectedWan={status?.wan_interface}
					onUpdate={(updated) => {
						if (draft) draft = { ...draft, sqm: updated };
					}}
				/>
			</Tabs.Content>

			<!-- NIC Tuning Tab -->
			<Tabs.Content value="tuning">
				<TrafficTuningTab
					tuning={draft.tuning}
					{availableInterfaces}
					effectiveCpuMask={status?.effective_cpu_mask}
					onUpdate={(updated) => {
						if (draft) draft = { ...draft, tuning: updated };
					}}
				/>
			</Tabs.Content>
		</Tabs.Root>
	{/if}
</div>

<!-- Floating Action / Save Bar -->
{#if isDirty}
	<div
		transition:fly={{ y: 50, duration: 250, easing: cubicOut }}
		class="fixed bottom-6 left-1/2 -translate-x-1/2 z-40 flex items-center gap-3 px-4 py-2.5 rounded-2xl bg-card border border-border shadow-2xl shadow-black/40 backdrop-blur-md"
	>
		<div class="flex items-center gap-2">
			<span class="size-2 rounded-full bg-amber-500 animate-pulse"></span>
			<span class="text-xs font-medium text-foreground">
				{changeCount} alteraç{changeCount === 1 ? "ão" : "ões"} pendente{changeCount === 1 ? "" : "s"}
			</span>
		</div>

		<div class="h-4 w-px bg-border"></div>

		<div class="flex items-center gap-1.5">
			<Button
				variant="ghost"
				size="sm"
				onclick={handleDiscard}
				disabled={saving}
				class="h-8 px-3 text-xs gap-1.5"
			>
				<RotateCcwIcon class="size-3.5" />
				<span>Descartar</span>
			</Button>

			<Button
				size="sm"
				onclick={handleSave}
				disabled={saving}
				class="h-8 px-3 text-xs gap-1.5"
			>
				{#if saving}
					<RefreshCwIcon class="size-3.5 animate-spin" />
					<span>Aplicando...</span>
				{:else}
					<SaveIcon class="size-3.5" />
					<span>Salvar e Aplicar</span>
				{/if}
			</Button>
		</div>
	</div>
{/if}
