<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { status, scan, reload, controlService } from "$lib/api/client";
	import { normalizeServices, type StatusResponse } from "$lib/api/types";
	import { getServiceMeta } from "$lib/services";
	import { formatBytes, formatUptime } from "$lib/utils";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import PlayIcon from "@lucide/svelte/icons/play";
	import SquareIcon from "@lucide/svelte/icons/square";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import LoaderIcon from "@lucide/svelte/icons/loader";

	import ServerIcon from "@lucide/svelte/icons/server";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import FolderIcon from "@lucide/svelte/icons/folder";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";
	import type { ServerCapabilities } from "$lib/api/types";

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
	let actionLoading = $state<Record<string, string | null>>({});

	async function executeServiceAction(id: string, action: "Start" | "Stop" | "Restart") {
		actionLoading[id] = action;
		try {
			await controlService(id, action);
			toast.success(`Service '${id}' received ${action.toLowerCase()} command`);
			setTimeout(async () => {
				await loadStatus();
				actionLoading[id] = null;
			}, 750);
		} catch (err) {
			actionLoading[id] = null;
			toast.error(`Failed to ${action.toLowerCase()} service: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

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

	function serviceIcon(name: string, id?: string) {
		const key = (id || name || "").toLowerCase();
		if (key.includes("dns") || key.includes("dot") || key.includes("doq")) return GlobeIcon;
		if (key.includes("dhcp")) return ServerIcon;
		if (key.includes("ra") || key.includes("router")) return NetworkIcon;
		if (key.includes("db") || key.includes("database")) return HardDriveIcon;
		if (key.includes("tftp")) return FolderIcon;
		if (key.includes("pppoe")) return ZapIcon;
		if (key.includes("discovery") || key.includes("mdns") || key.includes("ifmon") || key.includes("neighbor")) return RadioIcon;
		return CpuIcon;
	}

	function stateIcon(state: string) {
		const s = (state || "").toLowerCase();
		if (s === "online" || s === "active") return CheckCircleIcon;
		if (s === "starting") return LoaderIcon;
		return XCircleIcon;
	}

	function stateColor(state: string) {
		const s = (state || "").toLowerCase();
		if (s === "online" || s === "active") return "text-emerald-500";
		if (s === "starting") return "text-amber-500";
		if (s === "inactive" || s === "offline") return "text-muted-foreground";
		return "text-destructive";
	}

	function stateBadgeVariant(state: string): "default" | "secondary" | "outline" | "destructive" {
		const s = (state || "").toLowerCase();
		if (s === "online" || s === "active") return "default";
		if (s === "starting") return "secondary";
		if (s === "inactive" || s === "offline") return "outline";
		return "destructive";
	}

	function formatMetricKey(key: string): string {
		return key
			.replace(/_/g, " ")
			.replace(/\b\w/g, (c) => c.toUpperCase());
	}
</script>

<svelte:head>
	<title>System — Lanforge</title>
</svelte:head>

<div class="flex items-center justify-between">
	<div>
		<h1 class="text-foreground text-2xl font-bold tracking-tight">
			System
		</h1>
		<p class="text-muted-foreground text-sm">
			Daemon status and operations
		</p>
	</div>
	<div class="flex flex-wrap items-center gap-2">
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
	</div>
</div>

<!-- System Diagnostics Sub-Navigation Tabs -->
<NavTabs tabs={systemTabs} ariaLabel="System diagnostics navigation" />

<div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
	<!-- Uptime -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<ZapIcon class="text-green-400 size-4" />
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
					<span class="text-muted-foreground text-xs"
						>v{data.version}</span
					>
				{/if}
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Network -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<NetworkIcon class="text-blue-400 size-4" />
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
							<dt class="text-muted-foreground">GUA</dt>
							<dd
								class="max-w-[160px] truncate font-mono text-xs"
							>
								{data.network.gua}
							</dd>
						</div>
					{/if}
					{#if data.network.ula}
						<div class="flex justify-between py-0.5">
							<dt class="text-muted-foreground">ULA</dt>
							<dd
								class="max-w-[160px] truncate font-mono text-xs"
							>
								{data.network.ula}
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
				<HardDriveIcon class="text-indigo-400 size-4" />
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
						<dt class="text-muted-foreground">Size</dt>
						<dd class="font-medium">
							{formatBytes(data.db.size_bytes)}
						</dd>
					</div>
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Last flush</dt>
						<dd class="text-xs">
							{data.db.last_flush_secs_ago}s ago
						</dd>
					</div>
					<div class="flex flex-col py-0.5 gap-0.5">
						<dt class="text-muted-foreground">Path</dt>
						<dd
							class="text-muted-foreground truncate font-mono text-xs"
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
				<CpuIcon class="text-orange-400 size-4" />
				Resources
			</Card.Title>
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-4 w-full" />
				<Skeleton class="mt-2 h-4 w-1/2" />
			{:else if data}
				<dl class="text-sm">
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">RSS</dt>
						<dd class="font-medium">
							{formatBytes(
								data.resources.memory_rss_bytes ??
									data.resources.rss_bytes ??
									0,
							)}
						</dd>
					</div>
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">VMS</dt>
						<dd class="font-medium">
							{formatBytes(
								data.resources.memory_vms_bytes ??
									data.resources.vms_bytes ??
									0,
							)}
						</dd>
					</div>
				</dl>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Services -->
	<Card.Root class="md:col-span-2 xl:col-span-3">
		<Card.Header class="pb-3">
			<div class="flex flex-wrap items-center justify-between gap-2">
				<div>
					<Card.Title class="text-base font-semibold">Services & Daemons</Card.Title>
					<Card.Description class="text-xs">
						Background services, network listeners, and runtime status
					</Card.Description>
				</div>
				<div class="flex items-center gap-2">
					{#if !loading && serviceList.length > 0}
						{@const onlineCount = serviceList.filter(s => s.state.toLowerCase() === "online" || s.state.toLowerCase() === "active").length}
						<Badge variant="outline" class="font-mono text-xs">
							{onlineCount} / {serviceList.length} Online
						</Badge>
					{/if}
					<Button
						variant="outline"
						size="sm"
						href="/system/services"
						class="text-xs gap-1.5 h-7 px-2.5 font-medium hover:text-primary"
					>
						<span>All Services</span>
						<ArrowRightIcon class="size-3" />
					</Button>
				</div>
			</div>
		</Card.Header>
		<Card.Content class="p-0">
			{#if loading}
				<div class="flex flex-col divide-y divide-border">
					{#each { length: 6 } as _, i (i)}
						<div class="flex items-center gap-3 px-5 py-3">
							<Skeleton class="size-5 rounded-full" />
							<Skeleton class="h-4 w-32" />
							<Skeleton class="ml-auto h-4 w-24" />
						</div>
					{/each}
				</div>
			{:else if serviceList.length === 0}
				<p class="text-muted-foreground px-5 py-6 text-sm">
					No service data available
				</p>
			{:else}
				<div class="divide-border divide-y">
					{#each serviceList as svc (svc.name)}
						{@const meta = getServiceMeta(svc.id, svc.name)}
						{@const SvcIcon = meta.icon}
						{@const StatusIcon = stateIcon(svc.state)}
						{@const svcId = svc.id || svc.name.toLowerCase().replace(/\s+/g, "_")}
						{@const isBusy = !!actionLoading[svcId]}
						{@const currentAct = actionLoading[svcId]}
						{@const isInactive = svc.state.toLowerCase() === "inactive" || svc.state.toLowerCase() === "offline"}

						<div class="flex flex-col gap-2.5 px-5 py-3.5 transition-colors hover:bg-muted/30">
							<div class="flex flex-wrap items-center justify-between gap-3">
								<a
									href={meta.configHref}
									class="flex items-center gap-2.5 group/svc flex-1 min-w-[200px]"
								>
									<div class="bg-muted flex size-8 items-center justify-center rounded-md border group-hover/svc:border-primary/40 transition-colors">
										<SvcIcon class="size-4 text-foreground group-hover/svc:text-primary transition-colors" />
									</div>
									<div class="flex flex-col">
										<div class="flex items-center gap-2">
											<span class="text-foreground text-sm font-semibold capitalize group-hover/svc:text-primary transition-colors">
												{meta.name}
											</span>
											{#if svc.id}
												<span class="bg-muted text-muted-foreground rounded px-1.5 py-0.5 font-mono text-[10px]">
													{svc.id}
												</span>
											{/if}
											<span class="text-muted-foreground text-[10px] hidden sm:inline">
												• {meta.tag}
											</span>
										</div>
										<span class="text-muted-foreground text-xs">
											{#if svc.uptime_secs > 0}
												Uptime: {formatUptime(svc.uptime_secs)}
											{:else}
												Stopped / Standby
											{/if}
										</span>
									</div>
								</a>

								<div class="flex flex-wrap items-center gap-2">
									<Badge variant={stateBadgeVariant(svc.state)} class="capitalize text-xs gap-1.5">
										<StatusIcon class={["size-3.5", stateColor(svc.state), svc.state === "starting" ? "animate-spin" : ""].join(" ")} />
										{svc.state}
									</Badge>

									<Button
										variant="outline"
										size="sm"
										href={meta.configHref}
										class="text-xs gap-1 h-7 px-2.5 font-normal"
									>
										<SlidersIcon class="size-3" />
										<span>Configure</span>
										<ExternalLinkIcon class="size-2.5 text-muted-foreground" />
									</Button>

									{#if meta.canControl}
										{#if isInactive}
											<Button
												variant="default"
												size="sm"
												disabled={isBusy}
												onclick={() => executeServiceAction(svcId, "Start")}
												class="text-xs gap-1 h-7 px-2.5 bg-emerald-600 hover:bg-emerald-700 text-white"
											>
												{#if isBusy && currentAct === "Start"}
													<Loader2Icon class="size-3 animate-spin" />
												{:else}
													<PlayIcon class="size-3 fill-current" />
												{/if}
												Start
											</Button>
										{:else}
											<Button
												variant="secondary"
												size="sm"
												disabled={isBusy}
												onclick={() => executeServiceAction(svcId, "Restart")}
												class="text-xs gap-1 h-7 px-2"
											>
												{#if isBusy && currentAct === "Restart"}
													<Loader2Icon class="size-3 animate-spin" />
												{:else}
													<RotateCwIcon class="size-3" />
												{/if}
												Restart
											</Button>
											<Button
												variant="outline"
												size="sm"
												disabled={isBusy}
												onclick={() => executeServiceAction(svcId, "Stop")}
												class="text-xs gap-1 h-7 px-2 text-destructive hover:bg-destructive/10"
											>
												{#if isBusy && currentAct === "Stop"}
													<Loader2Icon class="size-3 animate-spin" />
												{:else}
													<SquareIcon class="size-3 fill-current" />
												{/if}
												Stop
											</Button>
										{/if}
									{/if}
								</div>
							</div>

							{#if Object.keys(svc.stats).length > 0}
								<div class="flex flex-wrap gap-1.5 pt-1">
									{#each Object.entries(svc.stats) as [k, v] (k)}
										<div class="bg-muted/40 border-border flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs">
											<span class="text-muted-foreground text-[11px]">{formatMetricKey(k)}:</span>
											<span class="font-mono text-[11px] font-medium text-foreground">{v}</span>
										</div>
									{/each}
								</div>
							{/if}
						</div>
					{/each}
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
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
					<Badge variant="outline" class="border-amber-500/40 text-amber-500 font-mono text-xs">
						Dev Override Active
					</Badge>
				{/if}
			</div>
		</Card.Header>
		<Card.Content class="flex flex-col gap-4">
			{#if capabilitiesState.debugMode}
				<div class="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200 flex items-center justify-between gap-3">
					<p>
						<strong class="font-semibold">Vite Dev Capabilities Override:</strong> All navigation menus and sub-features are forced visible. Click the button or use Topbar to restore live filtering.
					</p>
					<Button
						variant="outline"
						size="sm"
						class="h-7 text-xs border-amber-500/40 text-amber-600 dark:text-amber-300 hover:bg-amber-500/20 shrink-0"
						onclick={() => capabilitiesState.setDebugMode(false)}
					>
						Restore Live Filtering
					</Button>
				</div>
			{/if}
			{#if serverCaps}
				<div>
					<p
						class="text-muted-foreground mb-2 text-xs font-medium uppercase tracking-wide"
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
						class="text-muted-foreground mb-2 text-xs font-medium uppercase tracking-wide"
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
