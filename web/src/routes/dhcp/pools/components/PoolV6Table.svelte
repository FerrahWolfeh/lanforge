<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import type { Dhcpv6PoolConfig, DhcpPoolsResponse, DhcpPoolEntry } from "$lib/api/types";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

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

<DataTableCard
	title="IPv6 Stateful Address Scopes"
	icon={GlobeIcon}
	description="Stateful DHCPv6 address delegation ranges announced over ICMPv6/UDP 547"
	total={v6Pools.length}
	itemName="scopes"
	showSearch={false}
	showPagination={false}
	containerHeight="h-auto"
	minTableWidth="min-w-[700px]"
	columns={5}
	{loading}
	isEmpty={v6Pools.length === 0}
	emptyMessage="IPv6 clients may be relying purely on SLAAC (via Router Advertisements). Add an IPv6 scope if you wish to assign stateful addresses."
>
	{#snippet titleExtra()}
		<Badge variant="outline" class="font-mono text-[10px]">
			{v6Pools.length} {v6Pools.length === 1 ? "Pool" : "Pools"}
		</Badge>
	{/snippet}

	{#snippet actions()}
		<Button size="sm" variant="outline" onclick={onAdd} class="h-8 text-xs gap-1.5 cursor-pointer">
			<PlusIcon class="size-3.5" />
			<span>Add IPv6 Scope</span>
		</Button>
	{/snippet}

	{#snippet emptyAction()}
		<Button size="sm" variant="outline" onclick={onAdd} class="h-8 text-xs gap-1.5 cursor-pointer">
			<PlusIcon class="size-3.5" />
			<span>Add Stateful IPv6 Scope</span>
		</Button>
	{/snippet}

	{#snippet header()}
		<Table.Head class="w-[180px]">Scope Name</Table.Head>
		<Table.Head>Delegated Range / Prefix</Table.Head>
		<Table.Head class="w-[220px]">Live Capacity &amp; Utilization</Table.Head>
		<Table.Head>Lease Time</Table.Head>
		<Table.Head class="text-right w-[110px]">Actions</Table.Head>
	{/snippet}

	{#each v6Pools as pool, idx (idx)}
		{@const live = findV6LiveStats(pool)}
		{@const used = live?.used ?? 0}
		{@const total = live?.total ?? 0}
		{@const pct = live?.utilization_percent ?? (total > 0 ? Math.round((used / total) * 100) : 0)}
		{@const style = getUtilizationStyles(pct)}
		<Table.Row class="hover:bg-muted/30 transition-colors font-mono text-xs">
			<Table.Cell class="font-medium">
				<div class="flex flex-col gap-0.5">
					<span class="font-bold text-foreground text-xs">
						{pool.name || `Scope #${idx + 1}`}
					</span>
					<span class="text-[10px] text-muted-foreground uppercase">
						Type: {pool.address ? "Prefix Delegated" : "Direct Range"}
					</span>
				</div>
			</Table.Cell>

			<Table.Cell>
				{#if pool.range_start && pool.range_end}
					<div class="flex flex-col gap-0.5 font-mono text-xs">
						<span class="text-purple-400 font-semibold truncate max-w-[280px]" title={pool.range_start}>
							{pool.range_start}
						</span>
						<span class="text-muted-foreground text-[10px]">to</span>
						<span class="text-purple-400 font-semibold truncate max-w-[280px]" title={pool.range_end}>
							{pool.range_end}
						</span>
					</div>
				{:else if pool.address}
					<div class="flex items-center gap-1.5 font-mono text-xs text-purple-400 font-semibold">
						<span>{pool.address}</span>
						{#if activeUlaPrefix && pool.address.startsWith(activeUlaPrefix)}
							<Badge variant="outline" class="text-[9px] text-purple-400 border-purple-500/30">ULA</Badge>
						{/if}
					</div>
				{:else}
					<span class="text-muted-foreground italic">Dynamic Subnet</span>
				{/if}
			</Table.Cell>

			<Table.Cell>
				<div class="flex flex-col gap-1.5">
					<div class="flex items-center justify-between text-[11px] font-mono">
						<span class="font-medium text-foreground">
							{used} / {total > 0 ? total : "—"} active
						</span>
						<span class={style.text}>{pct}%</span>
					</div>
					<div class="h-1.5 w-full overflow-hidden rounded-full bg-muted">
						<div
							class={`h-full ${style.bar} transition-all duration-500`}
							style={`width: ${Math.min(100, Math.max(0, pct))}%`}
						></div>
					</div>
				</div>
			</Table.Cell>

			<Table.Cell class="text-xs font-mono text-muted-foreground">
				{pool.lease_time ? `${Math.round(pool.lease_time / 3600)}h` : `${Math.round(globalV6LeaseTime / 3600)}h (Default)`}
			</Table.Cell>

			<Table.Cell class="text-right">
				<div class="flex items-center justify-end gap-1">
					<Button
						variant="ghost"
						size="icon-sm"
						onclick={() => onEdit(idx)}
						title="Edit Scope"
						class="cursor-pointer"
					>
						<PencilIcon class="size-3.5" />
					</Button>
					<Button
						variant="ghost"
						size="icon-sm"
						class="text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 cursor-pointer"
						onclick={() => onDelete(idx)}
						title="Delete Scope"
					>
						<Trash2Icon class="size-3.5" />
					</Button>
				</div>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>
