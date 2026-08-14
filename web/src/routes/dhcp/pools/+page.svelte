<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import { dhcpPools, status } from "$lib/api/client";
	import type {
		DhcpPoolEntry,
		DhcpPoolsResponse,
		StatusResponse,
	} from "$lib/api/types";

	// Icons
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import ServerIcon from "@lucide/svelte/icons/server";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";

	let poolData = $state<DhcpPoolsResponse>({ v4_pools: [], v6_pools: [] });
	let daemonStatus = $state<StatusResponse | null>(null);
	let loading = $state(true);
	let isRefreshing = $state(false);

	async function loadPoolsData(showSpinner = true) {
		if (showSpinner) loading = true;
		else isRefreshing = true;

		try {
			const [pRes, sRes] = await Promise.allSettled([
				dhcpPools(),
				status(),
			]);

			if (pRes.status === "fulfilled") {
				poolData = pRes.value;
			}
			if (sRes.status === "fulfilled") {
				daemonStatus = sRes.value;
			}
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to load DHCP pool metrics");
		} finally {
			loading = false;
			isRefreshing = false;
		}
	}

	onMount(() => {
		loadPoolsData();
	});

	// Derived metrics
	const allPools = $derived([...poolData.v4_pools, ...poolData.v6_pools]);
	const totalPoolsCount = $derived(allPools.length);
	const totalAddresses = $derived(
		allPools.reduce((acc, p) => acc + (p.total || 0), 0),
	);
	const totalUsedAddresses = $derived(
		allPools.reduce((acc, p) => acc + (p.used || 0), 0),
	);
	const totalAvailableAddresses = $derived(
		allPools.reduce((acc, p) => acc + (p.available || 0), 0),
	);
	const aggregateUtilization = $derived(
		totalAddresses > 0
			? Math.round((totalUsedAddresses / totalAddresses) * 1000) / 10
			: 0,
	);

	function getUtilizationColor(pct: number): {
		barClass: string;
		badgeClass: string;
		label: string;
	} {
		if (pct >= 90) {
			return {
				barClass: "bg-destructive",
				badgeClass:
					"text-destructive border-destructive/30 bg-destructive/10",
				label: "High",
			};
		}
		if (pct >= 75) {
			return {
				barClass: "bg-amber-500",
				badgeClass:
					"text-amber-500 border-amber-500/30 bg-amber-500/10",
				label: "Elevated",
			};
		}
		return {
			barClass: "bg-emerald-500",
			badgeClass:
				"text-emerald-500 border-emerald-500/30 bg-emerald-500/10",
			label: "Normal",
		};
	}
</script>

<div class="flex flex-col gap-6">
	<!-- Top KPI Stats Cards -->
	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Total Configured Pools -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					Configured Pools
				</Card.Title>
				<LayersIcon class="h-4 w-4 text-muted-foreground" />
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="text-2xl font-bold">{totalPoolsCount}</div>
					<p class="text-xs text-muted-foreground mt-1">
						{poolData.v4_pools.length} IPv4 subnet / {poolData
							.v6_pools.length} IPv6 prefix pools
					</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Total Capacity -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					Total Managed IPs
				</Card.Title>
				<NetworkIcon class="h-4 w-4 text-muted-foreground" />
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="text-2xl font-bold">{totalAddresses}</div>
					<p class="text-xs text-muted-foreground mt-1">
						Across all active dynamic ranges
					</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Active Allocations -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					Allocated Addresses
				</Card.Title>
				<ActivityIcon class="h-4 w-4 text-muted-foreground" />
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="text-2xl font-bold">{totalUsedAddresses}</div>
					<p class="text-xs text-muted-foreground mt-1">
						{totalAvailableAddresses} available for allocation
					</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Overall Utilization -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					Global Utilization
				</Card.Title>
				{#if aggregateUtilization >= 90}
					<AlertTriangleIcon class="h-4 w-4 text-destructive" />
				{:else}
					<CheckCircle2Icon class="h-4 w-4 text-emerald-500" />
				{/if}
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="flex items-center gap-2">
						<span class="text-2xl font-bold"
							>{aggregateUtilization}%</span
						>
						<Badge
							variant="outline"
							class={[
								"text-xs",
								getUtilizationColor(aggregateUtilization)
									.badgeClass,
							].join(" ")}
						>
							{getUtilizationColor(aggregateUtilization).label}
						</Badge>
					</div>
					<div
						class="h-1.5 w-full overflow-hidden rounded-full bg-muted mt-2"
					>
						<div
							class={[
								"h-full transition-all duration-300",
								getUtilizationColor(aggregateUtilization)
									.barClass,
							].join(" ")}
							style="width: {Math.min(
								aggregateUtilization,
								100,
							)}%"
						></div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>

	<!-- Pool Detail Cards Section -->
	<div class="flex flex-col gap-6">
		<div class="flex items-center justify-between">
			<div>
				<h2 class="text-lg font-semibold tracking-tight">
					Active Address Pools
				</h2>
				<p class="text-xs text-muted-foreground">
					Dynamic IP scopes and prefix delegation ranges currently
					serviced.
				</p>
			</div>
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadPoolsData(false)}
				disabled={loading || isRefreshing}
			>
				<RefreshCwIcon
					class={[
						"mr-2 h-3.5 w-3.5",
						isRefreshing ? "animate-spin" : "",
					].join(" ")}
				/>
				Refresh Metrics
			</Button>
		</div>

		{#if loading}
			<div class="grid gap-4 md:grid-cols-2">
				<Skeleton class="h-48 w-full" />
				<Skeleton class="h-48 w-full" />
			</div>
		{:else if allPools.length === 0}
			<Card.Root>
				<Card.Content class="py-12">
					<Empty.Root>
						<Empty.Media>
							<LayersIcon
								class="h-10 w-10 text-muted-foreground/60"
							/>
						</Empty.Media>
						<Empty.Title>No DHCP pools active</Empty.Title>
						<Empty.Description>
							No DHCP address pools are currently configured or
							reporting metrics in Lanforge.
						</Empty.Description>
					</Empty.Root>
				</Card.Content>
			</Card.Root>
		{:else}
			<div class="grid gap-4 md:grid-cols-2">
				<!-- IPv4 Pools -->
				{#each poolData.v4_pools as pool, i (pool.range_start || i)}
					{@const colors = getUtilizationColor(
						pool.utilization_percent,
					)}
					<Card.Root class="overflow-hidden border-border/80">
						<Card.Header class="pb-3 border-b bg-muted/20">
							<div class="flex items-center justify-between">
								<div class="flex items-center gap-2">
									<Badge
										variant="outline"
										class="font-mono text-xs text-blue-500 border-blue-500/30"
									>
										IPv4 Pool #{i + 1}
									</Badge>
									<span
										class="text-xs text-muted-foreground font-medium"
									>
										Interface: {daemonStatus?.network
											?.lan_iface || "LAN"}
									</span>
								</div>
								<Badge
									variant="outline"
									class={[
										"font-mono text-xs",
										colors.badgeClass,
									].join(" ")}
								>
									{pool.utilization_percent.toFixed(1)}% Used
								</Badge>
							</div>
							<Card.Title class="text-base font-mono mt-2">
								{pool.range_start || "—"} &rarr; {pool.range_end ||
									"—"}
							</Card.Title>
						</Card.Header>

						<Card.Content class="pt-4 space-y-4">
							<!-- Utilization Bar -->
							<div class="space-y-1.5">
								<div
									class="flex items-center justify-between text-xs text-muted-foreground font-medium"
								>
									<span>Used: {pool.used}</span>
									<span>Available: {pool.available}</span>
									<span>Total: {pool.total}</span>
								</div>
								<div
									class="h-2 w-full overflow-hidden rounded-full bg-muted"
								>
									<div
										class={[
											"h-full transition-all duration-300",
											colors.barClass,
										].join(" ")}
										style="width: {Math.min(
											pool.utilization_percent,
											100,
										)}%"
									></div>
								</div>
							</div>

							<!-- Scope Options Badge Row -->
							<div
								class="grid grid-cols-2 gap-2 pt-2 border-t text-xs"
							>
								<div>
									<span class="text-muted-foreground"
										>Gateway:</span
									>
									<span
										class="font-mono font-medium ml-1 text-foreground"
									>
										{daemonStatus?.network?.lan_ipv4 ||
											"192.168.0.1"}
									</span>
								</div>
								<div>
									<span class="text-muted-foreground"
										>Default Lease:</span
									>
									<span
										class="font-mono font-medium ml-1 text-foreground"
										>24 hours</span
									>
								</div>
							</div>
						</Card.Content>
					</Card.Root>
				{/each}

				<!-- IPv6 Pools -->
				{#each poolData.v6_pools as pool, i (pool.prefix || i)}
					{@const colors = getUtilizationColor(
						pool.utilization_percent,
					)}
					<Card.Root class="overflow-hidden border-border/80">
						<Card.Header class="pb-3 border-b bg-muted/20">
							<div class="flex items-center justify-between">
								<div class="flex items-center gap-2">
									<Badge
										variant="outline"
										class="font-mono text-xs text-purple-500 border-purple-500/30"
									>
										IPv6 Pool #{i + 1}
									</Badge>
									<span
										class="text-xs text-muted-foreground font-medium"
									>
										Interface: {daemonStatus?.network
											?.lan_iface || "LAN"}
									</span>
								</div>
								<Badge
									variant="outline"
									class={[
										"font-mono text-xs",
										colors.badgeClass,
									].join(" ")}
								>
									{pool.utilization_percent.toFixed(1)}% Used
								</Badge>
							</div>
							<Card.Title class="text-base font-mono mt-2">
								{pool.prefix || "::"}/{pool.prefix_len ?? 64}
							</Card.Title>
						</Card.Header>

						<Card.Content class="pt-4 space-y-4">
							<!-- Utilization Bar -->
							<div class="space-y-1.5">
								<div
									class="flex items-center justify-between text-xs text-muted-foreground font-medium"
								>
									<span>Used: {pool.used}</span>
									<span>Available: {pool.available}</span>
									<span>Total: {pool.total}</span>
								</div>
								<div
									class="h-2 w-full overflow-hidden rounded-full bg-muted"
								>
									<div
										class={[
											"h-full transition-all duration-300",
											colors.barClass,
										].join(" ")}
										style="width: {Math.min(
											pool.utilization_percent,
											100,
										)}%"
									></div>
								</div>
							</div>

							<!-- Scope Options Badge Row -->
							<div
								class="grid grid-cols-2 gap-2 pt-2 border-t text-xs"
							>
								<div>
									<span class="text-muted-foreground"
										>Type:</span
									>
									<span
										class="font-mono font-medium ml-1 text-foreground"
									>
										{pool.prefix?.startsWith("fd")
											? "ULA (Local)"
											: "GUA (Global)"}
									</span>
								</div>
								<div>
									<span class="text-muted-foreground"
										>Prefix Length:</span
									>
									<span
										class="font-mono font-medium ml-1 text-foreground"
										>/{pool.prefix_len ?? 64}</span
									>
								</div>
							</div>
						</Card.Content>
					</Card.Root>
				{/each}
			</div>
		{/if}
	</div>
</div>
