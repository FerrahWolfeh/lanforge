<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { status, scan, reload } from "$lib/api/client";
	import { normalizeServices, type StatusResponse } from "$lib/api/types";
	import { degradedReason, getServiceMeta } from "$lib/services";
	import { formatBytes, formatBuild, formatUptime, formatIpv6Prefix } from "$lib/utils";
	import InfoPopover from "$lib/components/InfoPopover.svelte";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import CpuIcon from "@lucide/svelte/icons/cpu";

	import ServerIcon from "@lucide/svelte/icons/server";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";
	import type { ServerCapabilities } from "$lib/api/types";

	import LogLevelCard from "./components/LogLevelCard.svelte";

	// Scan, reload and service control are admin-only on the server.
	const isAdmin = $derived(auth.can("admin"));

	const systemTabs: NavTabItem[] = [
		{ label: "System Status", href: "/system", icon: ServerIcon },
		{ label: "Services & Daemons", href: "/system/services", icon: LayersIcon },
		{ label: "Event Stream", href: "/system/events", icon: ActivityIcon },
	];

	let data = $state<StatusResponse | null>(null);
	const serverCaps = $derived<ServerCapabilities | null>(
		data?.server_caps ??
		(data?.capabilities && "compiled" in data.capabilities
			? (data.capabilities as ServerCapabilities)
			: null) ??
		capabilitiesState.serverCaps
	);
	let loading = $state(true);
	let reloading = $state(false);
	let scanning = $state(false);

	async function loadStatus() {
		loading = true;
		try {
			data = await status();
		} catch {
			toast.error("Could not fetch system status");
		} finally {
			loading = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await scan();
			await loadStatus();
			toast.success("System status refreshed");
		} catch {
			toast.error("Failed to refresh status");
		} finally {
			scanning = false;
		}
	}

	async function triggerReload() {
		reloading = true;
		try {
			await reload();
			toast.success("Configuration reloaded");
		} catch {
			toast.error("Failed to reload configuration");
		} finally {
			reloading = false;
		}
	}

	onMount(loadStatus);

	const serviceList = $derived(normalizeServices(data));

</script>

<svelte:head>
	<title>System — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 w-full pb-12">
	<PageHeader
		title="System"
		description="Daemon version, uptime, memory and logging."
		icon={ServerIcon}
	>
	{#snippet actions()}
		<Button
			variant="outline"
			size="sm"
			onclick={loadStatus}
			disabled={loading}
		>
			<RefreshCwIcon
				data-icon="inline-start"
				class={loading ? "animate-spin" : ""}
			/>
			Refresh
		</Button>
		{#if isAdmin}
		<Button
			variant="outline"
			size="sm"
			onclick={triggerScan}
			disabled={scanning}
		>
			<ZapIcon data-icon="inline-start" />
			{scanning ? "Scanning…" : "Scan"}
		</Button>

		<AlertDialog.Root>
			<AlertDialog.Trigger>
				{#snippet child({ props })}
					<Button
						variant="outline"
						size="sm"
						{...props}
						disabled={reloading}
					>
						<RefreshCwIcon
							data-icon="inline-start"
							class={reloading ? "animate-spin" : ""}
						/>
						{reloading ? "Reloading…" : "Reload Config"}
					</Button>
				{/snippet}
			</AlertDialog.Trigger>
			<AlertDialog.Content>
				<AlertDialog.Header>
					<AlertDialog.Title>Reload configuration?</AlertDialog.Title>
					<AlertDialog.Description>
						This will re-read <code class="font-mono"
							>lanforge.toml</code
						> from disk. Active sessions and leases are not affected,
						but DNS/DHCP services may briefly restart.
					</AlertDialog.Description>
				</AlertDialog.Header>
				<AlertDialog.Footer>
					<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
					<AlertDialog.Action onclick={triggerReload}
						>Reload</AlertDialog.Action
					>
				</AlertDialog.Footer>
			</AlertDialog.Content>
		</AlertDialog.Root>
		{/if}
	{/snippet}
</PageHeader>

<!-- System Diagnostics Sub-Navigation Tabs -->
<NavTabs tabs={systemTabs} ariaLabel="System diagnostics navigation" />

<div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
	<!-- Uptime -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<ZapIcon class="text-muted-foreground size-4" />
				Daemon
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1">
			{#if loading}
				<Skeleton class="h-8 w-32" />
				<Skeleton class="h-4 w-20" />
			{:else if data}
				<span class="text-foreground text-2xl font-bold"
					>{formatUptime(data.uptime_secs)}</span
				>
				{#if data.version}
					<span class="text-muted-foreground text-xs" title={data.version}
						>{formatBuild(data.version)}</span
					>
				{/if}
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Network -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<NetworkIcon class="text-muted-foreground size-4" />
				Network
			</Card.Title>
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-4 w-full" />
				<Skeleton class="mt-2 h-4 w-3/4" />
			{:else if data}
				<dl class="text-sm">
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Interface</dt>
						<dd class="font-mono font-medium">
							{data.network.lan_iface}
						</dd>
					</div>
					{#if data.network.lan_ipv4}
						<div class="flex justify-between py-0.5">
							<dt class="text-muted-foreground">IPv4</dt>
							<dd class="font-mono text-xs">
								{data.network.lan_ipv4}
							</dd>
						</div>
					{/if}
					{#if data.network.gua}
						<div class="flex justify-between py-0.5">
							<dt class="text-muted-foreground">GUA Prefix</dt>
							<dd
								class="max-w-[170px] truncate font-mono text-xs text-foreground font-medium"
								title={data.network.gua}
							>
								{formatIpv6Prefix(data.network.gua, 64)}
							</dd>
						</div>
					{/if}
					{#if data.network.ula}
						<div class="flex justify-between py-0.5">
							<dt class="text-muted-foreground">ULA Prefix</dt>
							<dd
								class="max-w-[170px] truncate font-mono text-xs text-foreground font-medium"
								title={data.network.ula}
							>
								{formatIpv6Prefix(data.network.ula, 64)}
							</dd>
						</div>
					{/if}
				</dl>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Database -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<HardDriveIcon class="text-muted-foreground size-4" />
				Database
			</Card.Title>
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-4 w-full" />
				<Skeleton class="mt-2 h-4 w-1/2" />
			{:else if data}
				<dl class="text-sm">
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Disk Footprint</dt>
						<dd class="font-medium">
							{formatBytes(data.db.size_bytes)}
						</dd>
					</div>
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Last Disk Sync</dt>
						<dd class="text-xs font-mono">
							{data.db.last_flush_secs_ago === 0 ? '< 1s ago' : `${data.db.last_flush_secs_ago}s ago`}
						</dd>
					</div>
					<div class="flex flex-col py-0.5 gap-0.5">
						<dt class="text-muted-foreground">Storage File</dt>
						<dd
							class="text-muted-foreground truncate font-mono text-xs"
							title={data.db.path}
						>
							{data.db.path}
						</dd>
					</div>
				</dl>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Resources -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<CpuIcon class="text-muted-foreground size-4" />
				Memory & Footprint
			</Card.Title>
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-4 w-full" />
				<Skeleton class="mt-2 h-4 w-1/2" />
			{:else if data}
				<dl class="text-sm">
					<div class="flex justify-between items-center py-0.5">
						<dt class="text-muted-foreground flex items-center gap-1">
							<span>Physical RAM (RSS)</span>
							<InfoPopover
								title="Resident Set Size (RSS)"
								description="Actual non-swapped physical memory in hardware RAM occupied by daemon processes."
							/>
						</dt>
						<dd class="font-mono text-xs font-medium">
							{formatBytes(data.resources.memory_rss_bytes)}
						</dd>
					</div>
					<div class="flex justify-between items-center py-0.5">
						<dt class="text-muted-foreground flex items-center gap-1">
							<span>Virtual Memory (VMS)</span>
							<InfoPopover
								title="Virtual Memory Size (VMS)"
								description="Total virtual address space mapped by the daemon, including shared libraries and memory mappings."
							/>
						</dt>
						<dd class="font-mono text-xs font-medium">
							{formatBytes(data.resources.memory_vms_bytes)}
						</dd>
					</div>
				</dl>
			{/if}
		</Card.Content>
	</Card.Root>

	<LogLevelCard />

	<!-- Services live on their own tab; this is the one-line summary of them. -->
	{#if !loading && serviceList.length > 0}
		{@const problems = serviceList.filter((svc) => ["degraded", "error", "paused"].includes(svc.state.toLowerCase()))}
		{@const running = serviceList.filter((svc) => ["online", "active"].includes(svc.state.toLowerCase())).length}
		<a
			href="/system/services"
			class="md:col-span-2 xl:col-span-3 flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border bg-card px-4 py-3 text-sm transition-colors hover:bg-accent/40"
		>
			<span class="font-semibold">Services</span>
			<span class="text-muted-foreground tabular-nums">{running} of {serviceList.length} running</span>
			{#each problems as svc (svc.name)}
				<span class="text-warning">{getServiceMeta(svc.id, svc.name).name}: {degradedReason(svc.detail) ?? svc.summary ?? svc.state}</span>
			{/each}
			<span class="ml-auto flex items-center gap-1 text-xs font-medium text-muted-foreground">Manage <ArrowRightIcon class="size-3" /></span>
		</a>
	{/if}
</div>

<!-- Capabilities -->
{#if data}
	<Card.Root>
		<Card.Header>
			<div class="flex items-center justify-between">
				<div>
					<Card.Title class="text-sm font-medium">Server Capabilities</Card.Title>
					<Card.Description>Compiled feature flags vs. runtime enabled capabilities</Card.Description>
				</div>
				{#if capabilitiesState.debugMode}
					<Badge variant="outline" class="border-warning/40 text-warning font-mono text-xs">
						Dev Override Active
					</Badge>
				{/if}
			</div>
		</Card.Header>
		<Card.Content class="flex flex-col gap-4">
			{#if capabilitiesState.debugMode}
				<div class="rounded-lg border border-warning/30 bg-warning/10 p-3 text-xs text-foreground flex items-center justify-between gap-3">
					<p>
						<strong class="font-semibold">Vite Dev Capabilities Override:</strong> All navigation menus and sub-features are forced visible. Click the button or use Topbar to restore live filtering.
					</p>
					<Button
						variant="outline"
						size="sm"
						class="h-7 text-xs border-warning/40 text-warning hover:bg-warning/20 shrink-0"
						onclick={() => capabilitiesState.setDebugMode(false)}
					>
						Restore Live Filtering
					</Button>
				</div>
			{/if}
			{#if serverCaps}
				<div>
					<p
						class="text-muted-foreground mb-2 text-xs font-medium"
					>
						Enabled
					</p>
					<div class="flex flex-wrap gap-1.5">
						{#each serverCaps.enabled as cap (cap)}
							<Badge variant="default" class="font-mono text-xs"
								>{cap}</Badge
							>
						{/each}
					</div>
				</div>
				<Separator />
				<div>
					<p
						class="text-muted-foreground mb-2 text-xs font-medium"
					>
						Compiled (not enabled)
					</p>
					<div class="flex flex-wrap gap-1.5">
						{#each serverCaps.compiled.filter((c) => !serverCaps.enabled.includes(c)) as cap (cap)}
							<Badge
								variant="outline"
								class="text-muted-foreground font-mono text-xs"
								>{cap}</Badge
							>
						{/each}
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
{/if}
</div>
