<script lang="ts">
	import * as Tabs from "$lib/components/ui/tabs";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import {
		raStatus,
		raConfig,
		raUpdateConfig,
		raTrigger,
		getSetupStatus,
	} from "$lib/api/client";
	import type {
		RaServerConfig,
		RaStatusResponse,
		RouterPriority,
		RaPrefix,
		RdnssConfig,
		DnsslConfig,
		NetworkInterfaceInfo,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";
	import { createPolling } from "$lib/utils/polling";

	import RadioIcon from "@lucide/svelte/icons/radio";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";

	import RaStatsCards from "./components/RaStatsCards.svelte";
	import RaStatusTab from "./components/RaStatusTab.svelte";
	import RaConfigTab from "./components/RaConfigTab.svelte";

	// Page state
	let status = $state<RaStatusResponse | null>(null);
	let config = $state<RaServerConfig | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let triggering = $state(false);
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);
	let activeTab = $state("status");

	// Editable form fields
	let formEnabled = $state(true);
	let formIface = $state("end0");
	let formManaged = $state(false);
	let formOtherConfig = $state(false);
	let formDeprecateOnRenumber = $state(true);
	let formHopLimit = $state(64);
	let formPriority = $state<RouterPriority>("medium");
	let formMaxInterval = $state(200);
	let formMinInterval = $state<number | null>(null);
	let formLifetime = $state<number | null>(null);
	let formReachableTime = $state(0);
	let formRetransTimer = $state(0);
	let formMtu = $state<number | null>(null);

	// Editable arrays
	let formPrefixes = $state<RaPrefix[]>([]);
	let formRdnss = $state<string[]>([]);
	let formDnssl = $state<string[]>([]);

	let interfaceOptions = $derived.by(() => {
		const list = [...availableInterfaces];
		if (formIface && !list.some((i) => i.name === formIface)) {
			list.unshift({
				name: formIface,
				mac: null,
				is_physical: false,
				is_up: true,
				carrier_up: true,
				ips: [],
				bus_type: "configured",
			});
		}
		return list;
	});

	let isDirty = $derived.by(() => {
		if (!config) return false;
		if (formEnabled !== config.enabled) return true;
		if (formIface !== (config.iface || "end0")) return true;
		if (formManaged !== config.managed) return true;
		if (formOtherConfig !== config.other_config) return true;
		if (formDeprecateOnRenumber !== (config.deprecate_on_renumber ?? true)) return true;
		if (formHopLimit !== config.hop_limit) return true;
		if (formPriority !== config.priority) return true;
		if (formMaxInterval !== config.max_interval_secs) return true;
		if (formMinInterval !== (config.min_interval_secs ?? null)) return true;
		if (formLifetime !== (config.lifetime_secs ?? null)) return true;
		if (formReachableTime !== config.reachable_time_ms) return true;
		if (formRetransTimer !== config.retrans_timer_ms) return true;
		if (formMtu !== (config.mtu ?? null)) return true;

		if (JSON.stringify(formPrefixes) !== JSON.stringify(config.prefixes || [])) return true;

		const cfgRdnss = (config.rdnss || []).flatMap((r) => r.servers || []);
		if (formRdnss.length !== cfgRdnss.length) return true;
		for (let i = 0; i < formRdnss.length; i++) {
			if (formRdnss[i] !== cfgRdnss[i]) return true;
		}

		const cfgDnssl = (config.dnssl || []).flatMap((d) => d.domains || []);
		if (formDnssl.length !== cfgDnssl.length) return true;
		for (let i = 0; i < formDnssl.length; i++) {
			if (formDnssl[i] !== cfgDnssl[i]) return true;
		}

		return false;
	});

	function syncFormFromConfig(c: RaServerConfig) {
		formEnabled = c.enabled;
		formIface = c.iface ?? (availableInterfaces[0]?.name || "end0");
		formManaged = c.managed;
		formOtherConfig = c.other_config;
		formDeprecateOnRenumber = c.deprecate_on_renumber ?? true;
		formHopLimit = c.hop_limit;
		formPriority = c.priority;
		formMaxInterval = c.max_interval_secs;
		formMinInterval = c.min_interval_secs ?? null;
		formLifetime = c.lifetime_secs ?? null;
		formReachableTime = c.reachable_time_ms;
		formRetransTimer = c.retrans_timer_ms;
		formMtu = c.mtu ?? null;
		formPrefixes = JSON.parse(JSON.stringify(c.prefixes || []));

		const rdnssList: string[] = [];
		for (const r of c.rdnss || []) {
			for (const addr of r.servers || []) {
				if (!rdnssList.includes(addr)) rdnssList.push(addr);
			}
		}
		formRdnss = rdnssList;

		const dnsslList: string[] = [];
		for (const d of c.dnssl || []) {
			for (const dom of d.domains || []) {
				if (!dnsslList.includes(dom)) dnsslList.push(dom);
			}
		}
		formDnssl = dnsslList;
	}

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const fetchSetup = !silent || availableInterfaces.length === 0;
			const [s, c, setupRes] = await Promise.all([
				raStatus().catch(() => null),
				raConfig().catch(() => null),
				fetchSetup ? getSetupStatus().catch(() => null) : Promise.resolve(null),
			]);
			status = s;
			if (setupRes?.interfaces) {
				availableInterfaces = setupRes.interfaces;
			}
			if (c) {
				if (!config || !isDirty) {
					config = c;
					syncFormFromConfig(c);
				} else {
					config = c;
				}
			}
		} catch (err) {
			console.error("Failed to load RA data:", err);
			if (!silent) toast.error("Failed to load Router Advertisement details");
		} finally {
			if (!silent) loading = false;
		}
	}

	async function handleSaveConfig() {
		if (!isDirty) return;
		saving = true;
		try {
			const rdnssObj: RdnssConfig[] =
				formRdnss.length > 0 ? [{ servers: formRdnss, lifetime: null }] : [];
			const dnsslObj: DnsslConfig[] =
				formDnssl.length > 0 ? [{ domains: formDnssl, lifetime: null }] : [];

			const payload: RaServerConfig = {
				enabled: formEnabled,
				iface: formIface.trim() || null,
				managed: formManaged,
				other_config: formOtherConfig,
				deprecate_on_renumber: formDeprecateOnRenumber,
				hop_limit: Number(formHopLimit) || 64,
				priority: formPriority,
				max_interval_secs: Number(formMaxInterval) || 200,
				min_interval_secs: formMinInterval ? Number(formMinInterval) : null,
				lifetime_secs: formLifetime ? Number(formLifetime) : null,
				reachable_time_ms: Number(formReachableTime) || 0,
				retrans_timer_ms: Number(formRetransTimer) || 0,
				mtu: formMtu ? Number(formMtu) : null,
				prefixes: formPrefixes,
				rdnss: rdnssObj,
				dnssl: dnsslObj,
			};

			await raUpdateConfig(payload);
			toast.success("Router Advertisement configuration saved!");
			await loadAll(true);
		} catch (err: any) {
			toast.error(err?.message || "Failed to update RA configuration");
		} finally {
			saving = false;
		}
	}

	async function handleTriggerBurst() {
		triggering = true;
		try {
			await raTrigger();
			toast.success("RA multicast burst packet triggered!");
			await loadAll(true);
		} catch (err: any) {
			toast.error(err?.message || "Failed to trigger RA burst");
		} finally {
			triggering = false;
		}
	}

	function handleDiscard() {
		if (config) {
			syncFormFromConfig(config);
			toast.info("Unsaved configuration changes reverted");
		}
	}

	onMount(() => {
		loadAll();
		const stopPolling = createPolling(() => loadAll(true), 5000);
		return () => {
			stopPolling();
		};
	});
</script>

<svelte:head>
	<title>IPv6 Router Advertisement — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 w-full">
	<!-- Page Header -->
	<PageHeader
		title="IPv6 Router Advertisement"
		description="Autonomous SLAAC orchestration, RFC 4861/8106 ICMPv6 telemetry, and runtime parameters."
		icon={RadioIcon}
	>
		{#snippet badge()}
			{#if status?.enabled}
				<StatusBadge variant="online" showDot={true} pulse={true} text="Active" />
			{:else}
				<StatusBadge variant="dormant" text="Idle / Disabled" />
			{/if}
		{/snippet}
		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading}
				class="h-8 text-xs gap-1.5"
			>
				<RefreshCwIcon class="size-3.5 {loading ? 'animate-spin' : ''}" />
				<span>Refresh</span>
			</Button>

			<Button
				size="sm"
				onclick={handleTriggerBurst}
				disabled={triggering || !status?.enabled}
				class="h-8 text-xs gap-1.5 shadow-sm"
			>
				<ZapIcon class="size-3.5 {triggering ? 'animate-pulse' : ''}" />
				<span>Trigger Burst</span>
			</Button>
		{/snippet}
	</PageHeader>

	{#if capabilitiesState.isLoaded && !capabilitiesState.isActualEnabled("ra")}
		<div class="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4 text-amber-900 dark:text-amber-200 flex items-start gap-3">
			<RadioIcon class="size-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
			<div class="flex flex-col gap-1 text-xs">
				<div class="flex items-center gap-2">
					<span class="font-semibold text-sm">Router Advertisement (RA) Module is Disabled</span>
					{#if capabilitiesState.debugMode}
						<span class="rounded bg-amber-500/20 px-1.5 py-0.5 text-[10px] font-mono font-medium text-amber-600 dark:text-amber-300 border border-amber-500/30">
							DEV OVERRIDE
						</span>
					{/if}
				</div>
				<p class="leading-relaxed opacity-90">
					IPv6 Router Advertisements are currently disabled in the daemon configuration or not compiled into this binary build. To advertise IPv6 prefixes and enable autonomous SLAAC addressing, activate the RA module in your <code class="rounded bg-muted/60 px-1 py-0.5 font-mono">/etc/lanforge/lanforge.toml</code> configuration file.
				</p>
			</div>
		</div>
	{/if}

	{#if loading && !status}
		<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
			<Skeleton class="h-28 w-full rounded-xl" />
			<Skeleton class="h-28 w-full rounded-xl" />
			<Skeleton class="h-28 w-full rounded-xl" />
			<Skeleton class="h-28 w-full rounded-xl" />
		</div>
		<Skeleton class="h-96 w-full rounded-xl" />
	{:else}
		<!-- KPI Stats Cards -->
		<RaStatsCards {status} />

		<!-- Tabs Layout -->
		<Tabs.Root bind:value={activeTab} class="w-full flex flex-col gap-6">
			<div class="flex items-center justify-between">
				<Tabs.List class="grid grid-cols-2 w-full sm:w-[320px]">
					<Tabs.Trigger value="status" class="flex items-center gap-2">
						<RadioIcon class="size-4" />
						Live State
					</Tabs.Trigger>
					<Tabs.Trigger value="config" class="flex items-center gap-2">
						<SlidersIcon class="size-4" />
						Configuration
						{#if isDirty}
							<span class="size-2 rounded-full bg-amber-500 animate-pulse"></span>
						{/if}
					</Tabs.Trigger>
				</Tabs.List>
			</div>

			<!-- TAB 1: Live State -->
			<Tabs.Content value="status">
				<RaStatusTab {status} />
			</Tabs.Content>

			<!-- TAB 2: Runtime Configuration -->
			<Tabs.Content value="config">
				<RaConfigTab
					bind:formEnabled
					bind:formIface
					bind:formManaged
					bind:formOtherConfig
					bind:formDeprecateOnRenumber
					bind:formHopLimit
					bind:formPriority
					bind:formMaxInterval
					bind:formMinInterval
					bind:formLifetime
					bind:formReachableTime
					bind:formRetransTimer
					bind:formMtu
					bind:formPrefixes
					bind:formRdnss
					bind:formDnssl
					{interfaceOptions}
					{status}
					{isDirty}
					{saving}
					onSave={handleSaveConfig}
					onDiscard={handleDiscard}
				/>
			</Tabs.Content>
		</Tabs.Root>
	{/if}
</div>
