<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import type { Dhcpv6PoolConfig, DhcpPoolsResponse, DhcpPoolEntry } from "$lib/api/types";

	let {
		v6Pools = [],
		poolStats = { v4_pools: [], v6_pools: [] },
		loading = false,
		globalV6LeaseTime = 86400,
		activeUlaPrefix = null,
		onAdd = () => {},
		onEdit = (_idx: number) => {},
		onDelete = (_idx: number) => {},
	}: {
		v6Pools?: Dhcpv6PoolConfig[];
		poolStats?: DhcpPoolsResponse;
		loading?: boolean;
		globalV6LeaseTime?: number;
		activeUlaPrefix?: string | null;
		onAdd?: () => void;
		onEdit?: (idx: number) => void;
		onDelete?: (idx: number) => void;
	} = $props();

	function getUtilizationStyles(pct: number) {
		if (pct >= 90) {
			return {
				bar: "bg-rose-500",
				badge: "text-rose-400 border-rose-500/30 bg-rose-500/10",
				text: "text-rose-400",
				label: "Critical",
			};
		}
		if (pct >= 75) {
			return {
				bar: "bg-amber-500",
				badge: "text-amber-400 border-amber-500/30 bg-amber-500/10",
				text: "text-amber-400",
				label: "Elevated",
			};
		}
		return {
			bar: "bg-purple-500",
			badge: "text-purple-400 border-purple-500/30 bg-purple-500/10",
			text: "text-purple-400",
			label: "Healthy",
		};
	}

	function findV6LiveStats(pool: Dhcpv6PoolConfig): DhcpPoolEntry | undefined {
		return poolStats.v6_pools.find((live) => {
			if (pool.address && live.prefix && (live.prefix === pool.address || live.prefix.startsWith(pool.address)))
				return true;
			if (
				pool.range_start &&
				pool.range_end &&
				live.range_start === pool.range_start &&
				live.range_end === pool.range_end
			)
				return true;
			return false;
		});
	}
</script>

<Card.Root>
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div>
				<div class="flex items-center gap-2">
					<GlobeIcon class="size-4 text-purple-400" />
					<Card.Title class="text-base">IPv6 Stateful Address Scopes</Card.Title>
					<Badge variant="outline" class="font-mono text-[10px]">
						{v6Pools.length} {v6Pools.length === 1 ? "Pool" : "Pools"}
					</Badge>
				</div>
				<Card.Description class="text-xs">
					Stateful DHCPv6 address delegation ranges announced over ICMPv6/UDP 547
				</Card.Description>
			</div>

			<Button size="sm" variant="outline" onclick={onAdd} class="h-8 text-xs">
				<PlusIcon data-icon="inline-start" class="size-3.5" />
				Add IPv6 Scope
			</Button>
		</div>
	</Card.Header>

	<Card.Content class="p-0">
		{#if loading}
			<div class="p-6 flex flex-col gap-3">
				<Skeleton class="h-10 w-full" />
				<Skeleton class="h-10 w-full" />
			</div>
		{:else if v6Pools.length === 0}
			<Empty.Root class="py-10">
				<Empty.Header>
					<Empty.Media variant="icon">
						<GlobeIcon class="size-6 text-muted-foreground" />
					</Empty.Media>
					<Empty.Title>No IPv6 Stateful Scopes Configured</Empty.Title>
					<Empty.Description>
						IPv6 clients may be relying purely on SLAAC (via Router Advertisements). Add an IPv6 scope if you wish to assign stateful addresses.
					</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					<Button size="sm" variant="outline" onclick={onAdd} class="h-8 text-xs">
						<PlusIcon data-icon="inline-start" class="size-3.5" />
						Add IPv6 Scope
					</Button>
				</Empty.Content>
			</Empty.Root>
		{:else}
			<!-- Mobile View: Touch Cards -->
			<div class="flex flex-col divide-y sm:hidden">
				{#each v6Pools as pool, idx (idx)}
					{@const live = findV6LiveStats(pool)}
					{@const used = live?.used ?? 0}
					{@const total = live?.total ?? 0}
					{@const pct = live?.utilization_percent ?? (total > 0 ? Math.round((used / total) * 100) : 0)}
					{@const style = getUtilizationStyles(pct)}
					<div class="p-4 flex flex-col gap-3">
						<div class="flex items-start justify-between gap-2">
							<div class="flex flex-col gap-0.5">
								<span class="font-bold text-foreground text-sm">
									{pool.name || `IPv6 Scope #${idx + 1}`}
								</span>
								<div class="flex items-center gap-1.5 font-mono text-xs">
									<span class="text-purple-400 font-medium">{pool.range_start || "::1"}</span>
									<span class="text-muted-foreground">–</span>
									<span class="text-purple-400 font-medium">{pool.range_end || "::ffff"}</span>
								</div>
							</div>
							<div class="flex items-center gap-1 shrink-0">
								<Button
									variant="ghost"
									size="icon-sm"
									onclick={() => onEdit(idx)}
									title="Edit Scope"
								>
									<PencilIcon class="size-3.5" />
								</Button>
								<Button
									variant="ghost"
									size="icon-sm"
									class="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10"
									onclick={() => onDelete(idx)}
									title="Delete Scope"
								>
									<Trash2Icon class="size-3.5" />
								</Button>
							</div>
						</div>

						<!-- Live Usage Bar if total > 0 -->
						<div class="flex flex-col gap-1.5 bg-muted/20 p-2.5 rounded-lg border">
							<div class="flex items-center justify-between text-xs font-mono">
								<span class="text-muted-foreground">
									{used} used {total > 0 ? `/ ${total}` : ""}
								</span>
								{#if total > 0}
									<span class={style.text}>{pct}%</span>
								{/if}
							</div>
							{#if total > 0}
								<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted">
									<div
										class={`h-full ${style.bar} transition-all duration-500`}
										style={`width: ${Math.min(100, Math.max(0, pct))}%`}
									></div>
								</div>
							{/if}
						</div>

						<!-- Details Pills -->
						<div class="flex flex-wrap items-center gap-2 text-[11px] font-mono text-muted-foreground">
							<span class="bg-muted/40 px-2 py-0.5 rounded border">
								Addr: {pool.address || activeUlaPrefix || "Auto (SLAAC / ULA)"}
							</span>
							<span class="bg-muted/40 px-2 py-0.5 rounded border">
								Lease: {pool.lease_time ? `${Math.round(pool.lease_time / 3600)}h` : `${Math.round(globalV6LeaseTime / 3600)}h`}
							</span>
						</div>
					</div>
				{/each}
			</div>

			<!-- Desktop View: Table -->
			<div class="hidden sm:block overflow-x-auto">
				<Table.Root>
					<Table.Header>
						<Table.Row class="hover:bg-transparent">
							<Table.Head class="w-[180px]">Scope Name</Table.Head>
							<Table.Head>Prefix / Suffix Range</Table.Head>
							<Table.Head>Static CIDR Address</Table.Head>
							<Table.Head class="w-[200px]">Live Utilization</Table.Head>
							<Table.Head>Lease Time</Table.Head>
							<Table.Head class="text-right w-[110px]">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each v6Pools as pool, idx (idx)}
							{@const live = findV6LiveStats(pool)}
							{@const used = live?.used ?? 0}
							{@const total = live?.total ?? 0}
							{@const pct = live?.utilization_percent ?? (total > 0 ? Math.round((used / total) * 100) : 0)}
							{@const style = getUtilizationStyles(pct)}
							<Table.Row class="hover:bg-muted/30 transition-colors">
								<Table.Cell class="font-medium">
									<span class="font-bold text-foreground text-xs">
										{pool.name || `IPv6 Scope #${idx + 1}`}
									</span>
								</Table.Cell>

								<Table.Cell>
									<div class="flex items-center gap-1.5 font-mono text-xs">
										<span class="text-purple-400 font-semibold">{pool.range_start || "::1"}</span>
										<span class="text-muted-foreground">–</span>
										<span class="text-purple-400 font-semibold">{pool.range_end || "::ffff"}</span>
									</div>
								</Table.Cell>

								<Table.Cell class="font-mono text-xs text-muted-foreground">
									{pool.address || activeUlaPrefix || "Auto (SLAAC / ULA)"}
								</Table.Cell>

								<Table.Cell>
									<div class="flex flex-col gap-1.5">
										<div class="flex items-center justify-between text-[11px] font-mono">
											<span class="font-medium text-foreground">
												{used} used
											</span>
											{#if total > 0}
												<span class={style.text}>{pct}%</span>
											{/if}
										</div>
										{#if total > 0}
											<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted">
												<div
													class={`h-full ${style.bar} transition-all duration-500`}
													style={`width: ${Math.min(100, Math.max(0, pct))}%`}
												></div>
											</div>
										{/if}
									</div>
								</Table.Cell>

								<Table.Cell class="text-xs font-mono text-muted-foreground">
									{pool.lease_time ? `${Math.round(pool.lease_time / 3600)}h` : `${Math.round(globalV6LeaseTime / 3600)}h`}
								</Table.Cell>

								<Table.Cell class="text-right">
									<div class="flex items-center justify-end gap-1">
										<Button
											variant="ghost"
											size="icon-sm"
											onclick={() => onEdit(idx)}
											title="Edit Scope"
										>
											<PencilIcon class="size-3.5" />
										</Button>
										<Button
											variant="ghost"
											size="icon-sm"
											class="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10"
											onclick={() => onDelete(idx)}
											title="Delete Scope"
										>
											<Trash2Icon class="size-3.5" />
										</Button>
									</div>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
