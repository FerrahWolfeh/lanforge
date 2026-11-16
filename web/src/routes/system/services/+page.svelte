<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { serviceBanners, status, controlService, reload } from "$lib/api/client";
	import { normalizeServices, type ServiceBanner } from "$lib/api/types";
	import { degradedReason, getServiceMeta } from "$lib/services";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import { createPolling } from "$lib/utils/polling";
	import { formatBytes } from "$lib/utils";

	import ServerIcon from "@lucide/svelte/icons/server";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import PlayIcon from "@lucide/svelte/icons/play";
	import SquareIcon from "@lucide/svelte/icons/square";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";

	const systemTabs: NavTabItem[] = [
		{ label: "System Status", href: "/system", icon: ServerIcon },
		{ label: "Services & Daemons", href: "/system/services", icon: LayersIcon },
		{ label: "Event Stream", href: "/system/events", icon: ActivityIcon },
	];
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import CpuIcon from "@lucide/svelte/icons/cpu";

	import StopImpactDialog from "$lib/components/StopImpactDialog.svelte";
	let stopDialog = $state<StopImpactDialog>();

	// Reload and service control are admin-only on the server.
	const isAdmin = $derived(auth.can("admin"));

	let banners = $state<ServiceBanner[]>([]);
	let loading = $state(true);
	let isRefreshing = $state(false);
	let reloadingConfig = $state(false);
	let searchQuery = $state("");
	let statusFilter = $state<"all" | "online" | "inactive" | "error">("all");
	let actionLoading = $state<Record<string, string | null>>({});

	async function fetchBanners(showSpinner = true) {
		if (showSpinner) isRefreshing = true;
		try {
			// Prefer dedicated /service_banners endpoint with fallback to normalizeServices(status)
			try {
				const list = await serviceBanners();
				if (Array.isArray(list) && list.length > 0) {
					banners = list.map((b) => ({
						...b,
						id: b.id || b.name.toLowerCase().replace(/\s+/g, "_")
					}));
					return;
				}
			} catch {
				// Fallback to /status
			}
			const st = await status();
			banners = normalizeServices(st);
		} catch {
			if (showSpinner) toast.error("Could not fetch service banners");
		} finally {
			loading = false;
			if (showSpinner) isRefreshing = false;
		}
	}

	async function handleReloadConfig() {
		reloadingConfig = true;
		try {
			await reload();
			toast.success("Daemon configuration reloaded successfully");
			await fetchBanners(false);
		} catch (err) {
			toast.error(`Failed to reload configuration: ${err instanceof Error ? err.message : String(err)}`);
		} finally {
			reloadingConfig = false;
		}
	}

	async function executeAction(id: string, action: "Start" | "Stop" | "Restart") {
		if (action === "Stop") {
			try {
				if (!(await stopDialog?.confirmStop(id))) return;
			} catch (err) {
				toast.error(`Could not check what stopping '${id}' affects: ${err instanceof Error ? err.message : String(err)}`);
				return;
			}
		}
		actionLoading[id] = action;
		try {
			await controlService(id, action);
			toast.success(`Service '${id}' received ${action.toLowerCase()} signal`);
			// Re-fetch service state after brief settling time
			setTimeout(async () => {
				await fetchBanners(false);
				actionLoading[id] = null;
			}, 750);
		} catch (err) {
			actionLoading[id] = null;
			toast.error(`Failed to ${action.toLowerCase()} service: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

	onMount(() => {
		fetchBanners(true);
		const stopPolling = createPolling(() => {
			fetchBanners(false);
		}, 6000);
		return () => {
			stopPolling();
		};
	});

	function isOnline(state: string): boolean {
		const s = (state || "").toLowerCase();
		return s === "online" || s === "active";
	}

	function isStarting(state: string): boolean {
		return (state || "").toLowerCase() === "starting";
	}

	function isInactive(state: string): boolean {
		const s = (state || "").toLowerCase();
		return s === "inactive" || s === "offline";
	}

	function isError(state: string): boolean {
		const s = (state || "").toLowerCase();
		return s === "error" || s === "failed" || s === "degraded";
	}

	function formatUptime(secs: number): string {
		if (!secs || secs <= 0) return "Standby / Stopped";
		const d = Math.floor(secs / 86400);
		const h = Math.floor((secs % 86400) / 3600);
		const m = Math.floor((secs % 3600) / 60);
		if (d > 0) return `Up ${d}d ${h}h ${m}m`;
		if (h > 0) return `Up ${h}h ${m}m`;
		return `Up ${m}m ${secs % 60}s`;
	}

	const totalCount = $derived(banners.length);
	const onlineCount = $derived(banners.filter((b) => isOnline(b.state)).length);
	const inactiveCount = $derived(banners.filter((b) => isInactive(b.state)).length);
	const errorCount = $derived(banners.filter((b) => isError(b.state)).length);

	const filteredBanners = $derived(
		banners.filter((banner) => {
			const meta = getServiceMeta(banner.id, banner.name);
			// Filter by state tab
			if (statusFilter === "online" && !isOnline(banner.state)) return false;
			if (statusFilter === "inactive" && !isInactive(banner.state)) return false;
			if (statusFilter === "error" && !isError(banner.state)) return false;

			// Filter by text search
			if (!searchQuery.trim()) return true;
			const q = searchQuery.toLowerCase().trim();
			return (
				banner.name.toLowerCase().includes(q) ||
				(banner.id && banner.id.toLowerCase().includes(q)) ||
				meta.name.toLowerCase().includes(q) ||
				meta.tag.toLowerCase().includes(q) ||
				meta.proto.toLowerCase().includes(q) ||
				meta.description.toLowerCase().includes(q)
			);
		})
	);
</script>

<svelte:head>
	<title>Services — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Page Header -->
	<PageHeader
		title="Services"
		description="Start, stop and restart the router's services."
		icon={LayersIcon}
	>
		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				onclick={() => fetchBanners(true)}
				disabled={isRefreshing}
				class="text-xs gap-1.5"
			>
				<RefreshCwIcon class={["size-3.5", isRefreshing ? "animate-spin" : ""].join(" ")} />
				Refresh
			</Button>
			{#if isAdmin}
			<Button
				variant="secondary"
				size="sm"
				onclick={handleReloadConfig}
				disabled={reloadingConfig}
				class="text-xs gap-1.5"
			>
				<RotateCwIcon class={["size-3.5", reloadingConfig ? "animate-spin" : ""].join(" ")} />
				Reload Config
			</Button>
			{/if}
		{/snippet}
	</PageHeader>

	<!-- System Diagnostics Sub-Navigation Tabs -->
	<NavTabs tabs={systemTabs} ariaLabel="System diagnostics navigation" />

	<!-- Filter & Search Toolbar -->
	<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div class="relative w-full sm:w-72">
			<SearchIcon class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2 pointer-events-none" />
			<Input
				bind:value={searchQuery}
				placeholder="Search services, protocols, IDs..."
				class="pl-9 text-xs"
			/>
		</div>

		<div class="flex flex-wrap items-center gap-1.5">
			<Button
				variant={statusFilter === "all" ? "default" : "outline"}
				size="sm"
				onclick={() => (statusFilter = "all")}
				class="text-xs h-8"
			>
				All ({totalCount})
			</Button>
			<Button
				variant={statusFilter === "online" ? "default" : "outline"}
				size="sm"
				onclick={() => (statusFilter = "online")}
				class="text-xs h-8"
			>
				Online ({onlineCount})
			</Button>
			<Button
				variant={statusFilter === "inactive" ? "default" : "outline"}
				size="sm"
				onclick={() => (statusFilter = "inactive")}
				class="text-xs h-8"
			>
				Inactive ({inactiveCount})
			</Button>
			{#if errorCount > 0}
				<Button
					variant={statusFilter === "error" ? "destructive" : "outline"}
					size="sm"
					onclick={() => (statusFilter = "error")}
					class="text-xs h-8"
				>
					Errors ({errorCount})
				</Button>
			{/if}
		</div>
	</div>

	<!-- Services List -->
	{#if loading}
		<Card.Root class="gap-0 py-0">
			<div class="flex flex-col divide-y divide-border">
				{#each [1, 2, 3, 4, 5, 6] as _}
					<div class="flex items-center gap-3 px-4 py-3">
						<Skeleton class="size-4" />
						<Skeleton class="h-4 w-40" />
						<Skeleton class="ml-auto h-5 w-24" />
					</div>
				{/each}
			</div>
		</Card.Root>
	{:else if filteredBanners.length === 0}
		<Card.Root class="border-dashed py-12 text-center">
			<Card.Content class="flex flex-col items-center justify-center gap-2">
				<CpuIcon class="text-muted-foreground size-8" />
				<p class="text-foreground text-sm font-semibold">No services match your criteria</p>
				<p class="text-muted-foreground text-xs">
					{#if searchQuery}
						Try adjusting your search query or reset the state filter.
					{:else}
						No background services found on this Lanforge instance.
					{/if}
				</p>
				{#if searchQuery || statusFilter !== "all"}
					<Button
						variant="outline"
						size="sm"
						onclick={() => { searchQuery = ""; statusFilter = "all"; }}
						class="text-xs mt-2"
					>
						Clear Filters
					</Button>
				{/if}
			</Card.Content>
		</Card.Root>
	{:else}
		<!-- One row per service: phones keep it to two lines instead of a 280px card each. -->
		<Card.Root class="gap-0 py-0">
			<div class="flex flex-col divide-y divide-border">
			{#each filteredBanners as banner (banner.id || banner.name)}
				{@const svcId = banner.id || banner.name.toLowerCase().replace(/\s+/g, "_")}
				{@const meta = getServiceMeta(banner.id, banner.name)}
				{@const SvcIcon = meta.icon}
				{@const isBusy = !!actionLoading[svcId]}
				{@const currentAction = actionLoading[svcId]}
				<!-- A degraded service still serves (Rust `is_serving`): it can be restarted or stopped. -->
				{@const active = isOnline(banner.state) || banner.state.toLowerCase() === "degraded"}
				{@const starting = isStarting(banner.state)}
				{@const inactive = isInactive(banner.state)}
				{@const reason = degradedReason(banner.detail)}
				{@const t = banner.transport}

				<div class="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-3 transition-colors hover:bg-accent/30">
					<SvcIcon class="size-4 shrink-0 text-muted-foreground" />
					<a href={meta.configHref} class="flex min-w-0 flex-1 basis-56 flex-col" title={meta.description}>
						<span class="flex items-center gap-2">
							<span class="truncate text-sm font-medium text-foreground hover:text-selected-foreground">{meta.name}</span>
							<span class="hidden font-mono text-xs text-muted-foreground sm:inline">{svcId}</span>
						</span>
						{#if reason}
							<span class="truncate text-xs text-warning">{reason}</span>
						{:else if banner.summary}
							<span class="truncate font-mono text-xs text-muted-foreground">{banner.summary}</span>
						{:else}
							<span class="hidden truncate text-xs text-muted-foreground md:block">{meta.description}</span>
						{/if}
					</a>

					{#if t && (t.errors > 0 || t.dropped > 0 || t.rate_limited > 0)}
						<span class="flex items-center gap-2 font-mono text-xs" title={`↓ ${formatBytes(t.rx_bytes)} ↑ ${formatBytes(t.tx_bytes)}`}>
							{#if t.rate_limited > 0}<span class="text-warning">{t.rate_limited} limited</span>{/if}
							{#if t.dropped > 0}<span class="text-danger">{t.dropped} dropped</span>{/if}
							{#if t.errors > 0}<span class="text-danger">{t.errors} errors</span>{/if}
						</span>
					{/if}

					<span class="w-20 text-right font-mono text-xs tabular-nums text-muted-foreground">
						{active || starting ? formatUptime(banner.uptime_secs) : ""}
					</span>

					<StatusBadge
						text={banner.state}
						variant={isOnline(banner.state) ? "online" : starting || banner.state.toLowerCase() === "degraded" ? "warning" : isError(banner.state) ? "error" : "dormant"}
						showDot
						class="w-24 justify-center capitalize shrink-0"
					/>

					<div class="flex w-full items-center justify-end gap-1.5 sm:w-auto">
						{#if meta.canControl && isAdmin}
							{#if inactive}
								<Button
									variant="outline"
									size="sm"
									disabled={isBusy}
									title="Start {meta.name} now (to keep it on, enable it in Configure)"
									onclick={() => executeAction(svcId, "Start")}
									class="h-7 gap-1.5 text-xs text-success hover:text-success"
								>
									{#if isBusy && currentAction === "Start"}
										<Loader2Icon class="size-3.5 animate-spin" />
									{:else}
										<PlayIcon class="size-3.5 fill-current" />
									{/if}
									Start
								</Button>
							{:else}
								<Button
									variant="outline"
									size="sm"
									disabled={isBusy}
									title="Restart {meta.name}"
									onclick={() => executeAction(svcId, "Restart")}
									class="h-7 gap-1.5 text-xs"
								>
									{#if isBusy && currentAction === "Restart"}
										<Loader2Icon class="size-3.5 animate-spin" />
									{:else}
										<RotateCwIcon class="size-3.5" />
									{/if}
									Restart
								</Button>
								{#if active}
									<Button
										variant="outline"
										size="sm"
										disabled={isBusy}
										title="Stop {meta.name} now (to keep it off, disable it in Configure)"
										onclick={() => executeAction(svcId, "Stop")}
										class="h-7 gap-1.5 text-xs text-destructive hover:bg-destructive/10 hover:text-destructive"
									>
										{#if isBusy && currentAction === "Stop"}
											<Loader2Icon class="size-3.5 animate-spin" />
										{:else}
											<SquareIcon class="size-3.5 fill-current" />
										{/if}
										Stop
									</Button>
								{/if}
							{/if}
						{/if}
						<Button
							variant="ghost"
							size="sm"
							href={meta.configHref}
							title="Configure {meta.name}"
							class="h-7 gap-1.5 text-xs text-muted-foreground"
						>
							<SlidersIcon class="size-3.5" />
							<span class="sr-only sm:not-sr-only">Configure</span>
						</Button>
					</div>
				</div>
			{/each}
			</div>
		</Card.Root>
	{/if}
</div>

<StopImpactDialog bind:this={stopDialog} />
