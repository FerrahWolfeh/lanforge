<script lang="ts">
	import { onMount } from "svelte";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { toast } from "svelte-sonner";
	import HelpPopover from "$lib/components/HelpPopover.svelte";

	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";

	import {
		dhcpPools,
		dhcpPoolsConfigGet,
		dhcpPoolsConfigUpdate,
		dhcpOptionsGet,
		dhcpReconcile,
	} from "$lib/api/client";
	import { parseCsvList as parseList } from "$lib/utils";
	import type {
		DhcpPoolsResponse,
		Dhcpv4PoolConfig,
		Dhcpv6PoolConfig,
	} from "$lib/api/types";

	import PoolStatsCards from "./components/PoolStatsCards.svelte";
	import PoolV4Table from "./components/PoolV4Table.svelte";
	import PoolV6Table from "./components/PoolV6Table.svelte";
	import PoolV4Dialog from "./components/PoolV4Dialog.svelte";
	import PoolV6Dialog from "./components/PoolV6Dialog.svelte";

	let loading = $state(true);
	let saving = $state(false);
	let reconciling = $state(false);
	let isRefreshing = $state(false);

	let poolStats = $state<DhcpPoolsResponse>({ v4_pools: [], v6_pools: [] });
	let v4Pools = $state<Dhcpv4PoolConfig[]>([]);
	let v6Pools = $state<Dhcpv6PoolConfig[]>([]);
	let activeUlaPrefix = $state<string | null>(null);
	let activeGuaPrefix = $state<string | null>(null);
	let pristinePoolsJson = $state("");

	// Global Fallbacks from server options
	let globalV4Router = $state("");
	let globalV4SubnetMask = $state("255.255.255.0");
	let globalV4LeaseTime = $state(86400);
	let globalV6LeaseTime = $state(86400);

	// Dialog States
	let v4ModalOpen = $state(false);
	let editingV4Index = $state<number | null>(null);
	let v4Name = $state("");
	let v4Start = $state("");
	let v4End = $state("");
	let v4Router = $state("");
	let v4SubnetMask = $state("");
	let v4Dns = $state("");
	let v4Lease = $state<number | "">(86400);
	let v4BootFile = $state("");
	let v4TftpServer = $state("");

	let v6ModalOpen = $state(false);
	let editingV6Index = $state<number | null>(null);
	let v6Name = $state("");
	let v6Start = $state("");
	let v6End = $state("");
	let v6Addr = $state("");
	let v6Dns = $state("");
	let v6Lease = $state<number | "">(86400);
	let v6BootFile = $state("");

	const isDirty = $derived.by(() => {
		if (loading) return false;
		const currentStr = JSON.stringify({
			v4_pools: v4Pools,
			v6_pools: v6Pools,
		});
		return currentStr !== pristinePoolsJson;
	});

	// Derived metrics
	const allLivePools = $derived([...poolStats.v4_pools, ...poolStats.v6_pools]);
	const totalConfiguredCount = $derived(v4Pools.length + v6Pools.length);
	const totalManagedAddresses = $derived(
		allLivePools.reduce((acc, p) => acc + (p.total || 0), 0),
	);
	const totalUsedAddresses = $derived(
		allLivePools.reduce((acc, p) => acc + (p.used || 0), 0),
	);
	const totalAvailableAddresses = $derived(
		allLivePools.reduce((acc, p) => acc + (p.available || 0), 0),
	);
	const aggregateUtilization = $derived(
		totalManagedAddresses > 0
			? Math.round((totalUsedAddresses / totalManagedAddresses) * 1000) / 10
			: 0,
	);

	async function loadAllData(showSpinner = true) {
		if (showSpinner) loading = true;
		else isRefreshing = true;

		try {
			const [statsRes, configRes, optsRes] = await Promise.allSettled([
				dhcpPools(),
				dhcpPoolsConfigGet(),
				dhcpOptionsGet(),
			]);

			if (statsRes.status === "fulfilled") {
				poolStats = statsRes.value;
			}
			if (configRes.status === "fulfilled") {
				v4Pools = JSON.parse(JSON.stringify(configRes.value.v4_pools));
				v6Pools = JSON.parse(JSON.stringify(configRes.value.v6_pools));
				activeUlaPrefix = configRes.value.active_ula_prefix ?? "fd00::/64";
				activeGuaPrefix = configRes.value.active_gua_prefix ?? null;

				pristinePoolsJson = JSON.stringify({
					v4_pools: v4Pools,
					v6_pools: v6Pools,
				});
			}
			if (optsRes.status === "fulfilled") {
				globalV4Router = optsRes.value.v4?.router ?? "";
				globalV4SubnetMask = optsRes.value.v4?.subnet_mask ?? "255.255.255.0";
				globalV4LeaseTime = optsRes.value.v4?.lease_time ?? 86400;
				globalV6LeaseTime = optsRes.value.v6?.lease_time ?? 86400;
			}
		} catch (err: any) {
			toast.error(`Failed to load DHCP pools data: ${err.message}`);
		} finally {
			loading = false;
			isRefreshing = false;
		}
	}

	async function saveScopes() {
		saving = true;
		try {
			await dhcpPoolsConfigUpdate(v4Pools, v6Pools);
			pristinePoolsJson = JSON.stringify({
				v4_pools: v4Pools,
				v6_pools: v6Pools,
			});
			toast.success("DHCP address scopes and pools saved successfully");
			setTimeout(() => loadAllData(false), 500);
		} catch (err: any) {
			toast.error(`Failed to save scopes: ${err.message}`);
		} finally {
			saving = false;
		}
	}

	function discardChanges() {
		loadAllData(true);
		toast.info("Scope modifications discarded");
	}

	async function handleReconcile() {
		reconciling = true;
		try {
			const res = await dhcpReconcile();
			if (res.invalidated_v4_leases.length === 0) {
				toast.success(
					`DHCP Reconcile: All leases within range (${res.valid_v4_leases} active, ${res.preserved_static_leases} static preserved)`,
				);
			} else {
				toast.warning(
					`Reconcile: Invalidated ${res.invalidated_v4_leases.length} out-of-range lease(s). ForceRenew sent.`,
					{
						description:
							res.invalidated_v4_leases
								.map((l) => `${l.mac} (${l.ip})`)
								.slice(0, 3)
								.join(", ") +
							(res.invalidated_v4_leases.length > 3 ? "..." : ""),
						duration: 8000,
					},
				);
			}
			await loadAllData(false);
		} catch (err: any) {
			toast.error(`Failed to reconcile leases: ${err.message}`);
		} finally {
			reconciling = false;
		}
	}

	// IPv4 Modal Handlers
	function openAddV4() {
		editingV4Index = null;
		v4Name = `Pool ${v4Pools.length + 1}`;
		v4Start = "";
		v4End = "";
		v4Router = "";
		v4SubnetMask = globalV4SubnetMask;
		v4Dns = "";
		v4Lease = globalV4LeaseTime;
		v4BootFile = "";
		v4TftpServer = "";
		v4ModalOpen = true;
	}

	function openEditV4(idx: number) {
		editingV4Index = idx;
		const p = v4Pools[idx];
		v4Name = p.name ?? "";
		v4Start = p.range_start ?? "";
		v4End = p.range_end ?? "";
		v4Router = p.router ?? "";
		v4SubnetMask = p.subnet_mask ?? globalV4SubnetMask;
		v4Dns = (p.dns_servers ?? []).join(", ");
		v4Lease = p.lease_time ?? globalV4LeaseTime;
		v4BootFile = p.boot_file ?? "";
		v4TftpServer = p.tftp_server ?? "";
		v4ModalOpen = true;
	}

	function submitV4Modal() {
		if (!v4Start.trim() || !v4End.trim()) {
			toast.error("Range start and range end IP addresses are required");
			return;
		}
		const pool: Dhcpv4PoolConfig = {
			name: v4Name.trim() || null,
			range_start: v4Start.trim(),
			range_end: v4End.trim(),
			subnet_mask: v4SubnetMask.trim() || null,
			router: v4Router.trim() || null,
			dns_servers: parseList(v4Dns),
			lease_time: v4Lease ? Number(v4Lease) : null,
			boot_file: v4BootFile.trim() || null,
			tftp_server: v4TftpServer.trim() || null,
		};

		if (editingV4Index !== null) {
			v4Pools[editingV4Index] = pool;
			v4Pools = [...v4Pools];
			toast.info("Updated IPv4 scope. Click 'Save Scopes' to apply.");
		} else {
			v4Pools = [...v4Pools, pool];
			toast.info("Added new IPv4 scope. Click 'Save Scopes' to apply.");
		}
		v4ModalOpen = false;
	}

	function deleteV4(idx: number) {
		v4Pools = v4Pools.filter((_, i) => i !== idx);
		toast.info("Removed IPv4 scope. Click 'Save Scopes' to apply.");
	}

	// IPv6 Modal Handlers
	function openAddV6() {
		editingV6Index = null;
		v6Name = `IPv6 Scope ${v6Pools.length + 1}`;
		v6Start = "::100";
		v6End = "::1fff";
		v6Addr = "";
		v6Dns = "";
		v6Lease = globalV6LeaseTime;
		v6BootFile = "";
		v6ModalOpen = true;
	}

	function openEditV6(idx: number) {
		editingV6Index = idx;
		const p = v6Pools[idx];
		v6Name = p.name ?? "";
		v6Start = p.range_start ?? "";
		v6End = p.range_end ?? "";
		v6Addr = p.address ?? "";
		v6Dns = (p.dns_servers ?? []).join(", ");
		v6Lease = p.lease_time ?? globalV6LeaseTime;
		v6BootFile = p.boot_file ?? "";
		v6ModalOpen = true;
	}

	function submitV6Modal() {
		if (!v6Addr.trim() && (!v6Start.trim() || !v6End.trim())) {
			toast.error("Either start/end suffix or static address/prefix is required");
			return;
		}
		const pool: Dhcpv6PoolConfig = {
			name: v6Name.trim() || null,
			range_start: v6Start.trim() || null,
			range_end: v6End.trim() || null,
			address: v6Addr.trim() || null,
			dns_servers: parseList(v6Dns),
			lease_time: v6Lease ? Number(v6Lease) : null,
			boot_file: v6BootFile.trim() || null,
		};

		if (editingV6Index !== null) {
			v6Pools[editingV6Index] = pool;
			v6Pools = [...v6Pools];
			toast.info("Updated IPv6 scope. Click 'Save Scopes' to apply.");
		} else {
			v6Pools = [...v6Pools, pool];
			toast.info("Added new IPv6 scope. Click 'Save Scopes' to apply.");
		}
		v6ModalOpen = false;
	}

	function deleteV6(idx: number) {
		v6Pools = v6Pools.filter((_, i) => i !== idx);
		toast.info("Removed IPv6 scope. Click 'Save Scopes' to apply.");
	}

	onMount(() => {
		loadAllData(true);
	});
</script>

<svelte:head>
	<title>Scopes & Pools — Lanforge DHCP</title>
</svelte:head>

<div class="flex flex-col gap-6 w-full">
	<!-- Action Bar & Scope Meta -->
	<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<div class="flex flex-wrap items-center gap-2.5">
				<span class="text-sm font-semibold text-foreground">Configured Scopes</span>
				<Badge variant="outline" class="font-mono text-xs">
					{totalConfiguredCount} {totalConfiguredCount === 1 ? "Scope" : "Scopes"}
				</Badge>
				<HelpPopover
					title="DHCP Parameter Inheritance"
					description="Dynamic address scopes automatically inherit fallback parameters configured in DHCP Server Options unless overridden per pool."
				>
					{#snippet children()}
						<div class="flex flex-col gap-2 text-xs">
							<div class="flex justify-between border-b pb-1 border-border/40">
								<span class="text-muted-foreground">Default Gateway:</span>
								<code class="font-mono font-bold text-primary">{globalV4Router || "Not set"}</code>
							</div>
							<div class="flex justify-between border-b pb-1 border-border/40">
								<span class="text-muted-foreground">Subnet Mask:</span>
								<code class="font-mono font-bold text-primary">{globalV4SubnetMask}</code>
							</div>
							<div class="pt-1">
								<Button variant="outline" size="sm" href="/dhcp/server" class="w-full text-xs h-7 gap-1">
									<SlidersIcon class="size-3" />
									Configure Global Options
								</Button>
							</div>
						</div>
					{/snippet}
				</HelpPopover>
				{#if isDirty}
					<Badge
						variant="outline"
						class="text-amber-400 border-amber-500/30 bg-amber-500/10 text-xs font-semibold animate-pulse"
					>
						Unsaved Changes
					</Badge>
				{/if}
			</div>
			<p class="text-muted-foreground text-xs mt-0.5">
				Dynamic IPv4 subnets, IPv6 prefixes, and real-time lease address capacity.
			</p>
		</div>

		<!-- Action Bar -->
		<div class="flex flex-wrap items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAllData(false)}
				disabled={loading || isRefreshing}
				class="h-8 text-xs"
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={`size-3.5 mr-1 ${isRefreshing ? "animate-spin" : ""}`}
				/>
				Refresh
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={handleReconcile}
				disabled={reconciling || loading || saving}
				title="Audit active dynamic leases against current subnet & pools (RFC 3203 ForceRenew)"
				class="h-8 text-xs"
			>
				<ShieldCheckIcon
					data-icon="inline-start"
					class={`size-3.5 mr-1 ${reconciling ? "animate-spin text-primary" : "text-emerald-400"}`}
				/>
				{reconciling ? "Auditing..." : "Reconcile Leases"}
			</Button>

			<Button
				variant="outline"
				size="sm"
				href="/dhcp/server"
				class="h-8 text-xs"
			>
				<SlidersIcon data-icon="inline-start" class="size-3.5 mr-1" />
				Global Options
			</Button>

			{#if isDirty}
				<Button
					variant="ghost"
					size="sm"
					onclick={discardChanges}
					disabled={saving}
					class="h-8 text-xs"
				>
					<RotateCcwIcon data-icon="inline-start" class="size-3.5 mr-1" />
					Discard
				</Button>
				<Button
					size="sm"
					onclick={saveScopes}
					disabled={saving || loading}
					class="h-8 text-xs shadow-sm"
				>
					<SaveIcon
						data-icon="inline-start"
						class={`size-3.5 mr-1 ${saving ? "animate-spin" : ""}`}
					/>
					Save Scopes
				</Button>
			{/if}
		</div>
	</div>

	<!-- KPI Stat Cards (4 Cards) -->
	<PoolStatsCards
		{loading}
		{totalConfiguredCount}
		v4PoolsCount={v4Pools.length}
		v6PoolsCount={v6Pools.length}
		{totalManagedAddresses}
		{totalUsedAddresses}
		{totalAvailableAddresses}
		{aggregateUtilization}
	/>

	<!-- SECTION 1: IPv4 Address Scopes -->
	<PoolV4Table
		{v4Pools}
		{poolStats}
		{loading}
		{globalV4Router}
		{globalV4SubnetMask}
		{globalV4LeaseTime}
		onAdd={openAddV4}
		onEdit={openEditV4}
		onDelete={deleteV4}
	/>

	<!-- SECTION 2: IPv6 Address Scopes -->
	<PoolV6Table
		{v6Pools}
		{poolStats}
		{loading}
		{globalV6LeaseTime}
		{activeUlaPrefix}
		onAdd={openAddV6}
		onEdit={openEditV6}
		onDelete={deleteV6}
	/>
</div>

<!-- Modal: Add / Edit IPv4 Scope -->
<PoolV4Dialog
	bind:open={v4ModalOpen}
	editingIndex={editingV4Index}
	bind:v4Name
	bind:v4Start
	bind:v4End
	bind:v4Router
	bind:v4SubnetMask
	bind:v4Dns
	bind:v4Lease
	bind:v4BootFile
	bind:v4TftpServer
	{globalV4Router}
	{globalV4SubnetMask}
	{globalV4LeaseTime}
	onSubmit={submitV4Modal}
/>

<!-- Modal: Add / Edit IPv6 Scope -->
<PoolV6Dialog
	bind:open={v6ModalOpen}
	editingIndex={editingV6Index}
	bind:v6Name
	bind:v6Start
	bind:v6End
	bind:v6Addr
	bind:v6Dns
	bind:v6Lease
	bind:v6BootFile
	{globalV6LeaseTime}
	onSubmit={submitV6Modal}
/>
