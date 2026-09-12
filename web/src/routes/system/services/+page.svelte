<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { serviceBanners, status, controlService, reload } from "$lib/api/client";
	import { normalizeServices, type ServiceBanner } from "$lib/api/types";
	import { getServiceMeta } from "$lib/services";
	import { toast } from "svelte-sonner";
	import { goto } from "$app/navigation";
	import { onMount, onDestroy } from "svelte";

	import ServerIcon from "@lucide/svelte/icons/server";
	import CircleCheckIcon from "@lucide/svelte/icons/circle-check";
	import PowerOffIcon from "@lucide/svelte/icons/power-off";
	import TriangleAlertIcon from "@lucide/svelte/icons/triangle-alert";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import PlayIcon from "@lucide/svelte/icons/play";
	import SquareIcon from "@lucide/svelte/icons/square";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ShieldIcon from "@lucide/svelte/icons/shield";

	let banners = $state<ServiceBanner[]>([]);
	let loading = $state(true);
	let isRefreshing = $state(false);
	let reloadingConfig = $state(false);
	let searchQuery = $state("");
	let statusFilter = $state<"all" | "online" | "inactive" | "error">("all");
	let actionLoading = $state<Record<string, string | null>>({});
	let refreshInterval: ReturnType<typeof setInterval> | null = null;

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
		refreshInterval = setInterval(() => {
			fetchBanners(false);
		}, 6000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
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

	function stateBadgeVariant(state: string): "default" | "secondary" | "outline" | "destructive" {
		if (isOnline(state)) return "default";
		if (isStarting(state)) return "secondary";
		if (isInactive(state)) return "outline";
		return "destructive";
	}

	function stateDotClass(state: string): string {
		if (isOnline(state)) return "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]";
		if (isStarting(state)) return "bg-amber-500 animate-pulse";
		if (isInactive(state)) return "bg-zinc-500";
		return "bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]";
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

	function formatMetricKey(key: string): string {
		return key
			.replace(/_/g, " ")
			.replace(/\b\w/g, (c) => c.toUpperCase());
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
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-foreground text-2xl font-bold tracking-tight">Services & Subsystems</h1>
			<p class="text-muted-foreground text-sm">
				View runtime status, telemetry, and control daemon services. Click <strong>Configure</strong> to change boot defaults.
			</p>
		</div>
		<div class="flex flex-wrap items-center gap-2">
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
		</div>
	</div>

	<!-- Top Metric Summary Cards -->
	<div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
		<!-- Total Services -->
		<Card.Root>
			<Card.Content class="p-4 flex items-center justify-between">
				<div class="flex flex-col">
					<span class="text-muted-foreground text-xs font-medium">Total Services</span>
					<span class="text-foreground font-mono text-2xl font-bold">
						{loading ? "—" : totalCount}
					</span>
				</div>
				<div class="bg-muted flex size-9 items-center justify-center rounded-lg border border-border/60">
					<ServerIcon class="size-4 text-foreground" />
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Online Services -->
		<Card.Root>
			<Card.Content class="p-4 flex items-center justify-between">
				<div class="flex flex-col">
					<span class="text-muted-foreground text-xs font-medium">Online / Active</span>
					<span class="text-emerald-500 font-mono text-2xl font-bold">
						{loading ? "—" : onlineCount}
					</span>
				</div>
				<div class="bg-emerald-500/10 flex size-9 items-center justify-center rounded-lg border border-emerald-500/20">
					<CircleCheckIcon class="size-4 text-emerald-500" />
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Inactive Services -->
		<Card.Root>
			<Card.Content class="p-4 flex items-center justify-between">
				<div class="flex flex-col">
					<span class="text-muted-foreground text-xs font-medium">Inactive / Standby</span>
					<span class="text-muted-foreground font-mono text-2xl font-bold">
						{loading ? "—" : inactiveCount}
					</span>
				</div>
				<div class="bg-muted flex size-9 items-center justify-center rounded-lg border border-border/60">
					<PowerOffIcon class="size-4 text-muted-foreground" />
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Degraded / Error Services -->
		<Card.Root>
			<Card.Content class="p-4 flex items-center justify-between">
				<div class="flex flex-col">
					<span class="text-muted-foreground text-xs font-medium">Degraded / Error</span>
					<span class={["font-mono text-2xl font-bold", errorCount > 0 ? "text-rose-500" : "text-muted-foreground"].join(" ")}>
						{loading ? "—" : errorCount}
					</span>
				</div>
				<div class={["flex size-9 items-center justify-center rounded-lg border", errorCount > 0 ? "bg-rose-500/10 border-rose-500/20" : "bg-muted border-border/60"].join(" ")}>
					<TriangleAlertIcon class={["size-4", errorCount > 0 ? "text-rose-500" : "text-muted-foreground"].join(" ")} />
				</div>
			</Card.Content>
		</Card.Root>
	</div>

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

	<!-- Services Grid -->
	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each [1, 2, 3, 4, 5, 6] as _}
				<Card.Root class="p-5 flex flex-col gap-4">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-3">
							<Skeleton class="size-10 rounded-lg" />
							<div class="flex flex-col gap-1.5">
								<Skeleton class="h-4 w-32" />
								<Skeleton class="h-3 w-20" />
							</div>
						</div>
						<Skeleton class="h-6 w-16 rounded-full" />
					</div>
					<Skeleton class="h-10 w-full" />
					<Skeleton class="h-8 w-full rounded-md" />
				</Card.Root>
			{/each}
		</div>
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
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each filteredBanners as banner (banner.id || banner.name)}
				{@const svcId = banner.id || banner.name.toLowerCase().replace(/\s+/g, "_")}
				{@const meta = getServiceMeta(banner.id, banner.name)}
				{@const SvcIcon = meta.icon}
				{@const isBusy = !!actionLoading[svcId]}
				{@const currentAction = actionLoading[svcId]}
				{@const active = isOnline(banner.state)}
				{@const starting = isStarting(banner.state)}
				{@const inactive = isInactive(banner.state)}

				<Card.Root class="flex flex-col justify-between transition-all hover:border-zinc-600/70 hover:shadow-sm group">
					<!-- Clickable Body: Direct Navigation to Configuration -->
					<div
						role="button"
						tabindex="0"
						onclick={() => goto(meta.configHref)}
						onkeydown={(e) => { if (e.key === "Enter" || e.key === " ") goto(meta.configHref); }}
						class="flex-1 p-5 flex flex-col gap-3.5 cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-primary/50 rounded-t-xl"
					>
						<!-- Card Top Row: Icon, Titles & Status Badge -->
						<div class="flex items-start justify-between gap-2">
							<div class="flex items-center gap-3">
								<div class="bg-muted flex size-10 items-center justify-center rounded-lg border border-border/70 shrink-0 group-hover:border-primary/40 transition-colors">
									<SvcIcon class="size-5 text-foreground group-hover:text-primary transition-colors" />
								</div>
								<div class="flex flex-col min-w-0">
									<div class="flex items-center gap-1.5 flex-wrap">
										<span class="text-foreground text-sm font-semibold truncate group-hover:text-primary transition-colors">
											{meta.name}
										</span>
									</div>
									<div class="flex items-center gap-1.5 pt-0.5">
										<span class="bg-muted text-muted-foreground rounded px-1.5 py-0.2 font-mono text-[10px]">
											{svcId}
										</span>
										<span class="text-muted-foreground text-[10px] truncate">
											• {meta.tag}
										</span>
									</div>
								</div>
							</div>

							<!-- Status Badge with Dot -->
							<Badge variant={stateBadgeVariant(banner.state)} class="capitalize text-[11px] gap-1.5 shrink-0">
								{#if starting}
									<Loader2Icon class="size-3 animate-spin text-amber-500" />
								{:else}
									<span class={["size-2 rounded-full shrink-0", stateDotClass(banner.state)].join(" ")}></span>
								{/if}
								{banner.state}
							</Badge>
						</div>

						<!-- Service Description -->
						<p class="text-muted-foreground text-xs line-clamp-2 leading-relaxed">
							{meta.description}
						</p>

						<!-- Transport & Uptime Info -->
						<div class="flex items-center justify-between text-[11px] font-mono border-t border-border/50 pt-2.5">
							<Badge variant="outline" class="font-mono text-[10px] px-1.5 py-0">
								{meta.proto}
							</Badge>
							<span class="text-muted-foreground">
								{formatUptime(banner.uptime_secs)}
							</span>
						</div>

						<!-- Telemetry Stats Chips -->
						{#if banner.stats && Object.keys(banner.stats).length > 0}
							<div class="flex flex-wrap gap-1.5 pt-0.5">
								{#each Object.entries(banner.stats) as [k, v] (k)}
									<div class="bg-muted/40 border-border/70 flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px]">
										<span class="text-muted-foreground text-[10px]">{formatMetricKey(k)}:</span>
										<span class="font-mono text-[10px] font-medium text-foreground">{v}</span>
									</div>
								{/each}
							</div>
						{/if}
					</div>

					<!-- Card Footer: Navigation Link & Lifecycle Action Controls -->
					<Card.Footer class="px-5 py-3 border-t border-border/50 flex flex-wrap items-center justify-between gap-2 bg-muted/10">
						<!-- Configure Button -->
						<Button
							variant="outline"
							size="sm"
							href={meta.configHref}
							title="Configure {meta.name} (persistent boot enable/disable and parameters)"
							class="text-xs gap-1.5 h-8 font-medium hover:text-primary"
						>
							<SlidersIcon class="size-3.5" />
							<span>Configure</span>
							<ExternalLinkIcon class="size-3 text-muted-foreground" />
						</Button>

						<!-- Service Lifecycle Actions -->
						<div class="flex items-center gap-1.5">
							{#if meta.canControl}
								{#if inactive}
									<!-- Start Action -->
									<Button
										variant="default"
										size="sm"
										disabled={isBusy}
										title="Start {meta.name} in runtime"
										onclick={(e) => {
											e.stopPropagation();
											executeAction(svcId, "Start");
										}}
										class="text-xs gap-1.5 h-8 bg-emerald-600 hover:bg-emerald-700 text-white"
									>
										{#if isBusy && currentAction === "Start"}
											<Loader2Icon class="size-3.5 animate-spin" />
										{:else}
											<PlayIcon class="size-3.5 fill-current" />
										{/if}
										Start
									</Button>
								{:else if active}
									<!-- Restart Action -->
									<Button
										variant="secondary"
										size="sm"
										disabled={isBusy}
										title="Restart {meta.name} process"
										onclick={(e) => {
											e.stopPropagation();
											executeAction(svcId, "Restart");
										}}
										class="text-xs gap-1.5 h-8"
									>
										{#if isBusy && currentAction === "Restart"}
											<Loader2Icon class="size-3.5 animate-spin" />
										{:else}
											<RotateCwIcon class="size-3.5" />
										{/if}
										Restart
									</Button>

									<!-- Stop Action -->
									<Button
										variant="outline"
										size="sm"
										disabled={isBusy}
										title="Stop {meta.name} in runtime (to permanently disable, use Configure)"
										onclick={(e) => {
											e.stopPropagation();
											executeAction(svcId, "Stop");
										}}
										class="text-xs gap-1.5 h-8 text-destructive hover:bg-destructive/10 hover:text-destructive"
									>
										{#if isBusy && currentAction === "Stop"}
											<Loader2Icon class="size-3.5 animate-spin" />
										{:else}
											<SquareIcon class="size-3.5 fill-current" />
										{/if}
										Stop
									</Button>
								{:else}
									<!-- Error/Starting State: Restart Option -->
									<Button
										variant="secondary"
										size="sm"
										disabled={isBusy}
										onclick={(e) => {
											e.stopPropagation();
											executeAction(svcId, "Restart");
										}}
										class="text-xs gap-1.5 h-8"
									>
										{#if isBusy && currentAction === "Restart"}
											<Loader2Icon class="size-3.5 animate-spin" />
										{:else}
											<RotateCwIcon class="size-3.5" />
										{/if}
										Restart
									</Button>
								{/if}
							{:else}
								<!-- Core Subsystem Badge -->
								<Badge variant="secondary" class="text-[10px] font-mono gap-1 text-muted-foreground">
									<ShieldIcon class="size-3 text-muted-foreground" />
									Core Task
								</Badge>
							{/if}
						</div>
					</Card.Footer>
				</Card.Root>
			{/each}
		</div>
	{/if}
</div>
