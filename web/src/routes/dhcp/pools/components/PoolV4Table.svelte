<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import ServerIcon from "@lucide/svelte/icons/server";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import type { Dhcpv4PoolConfig, DhcpPoolsResponse, DhcpPoolEntry } from "$lib/api/types";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	let {
		v4Pools = [],
		poolStats = { v4_pools: [], v6_pools: [] },
		loading = false,
		globalV4Router = "",
		globalV4SubnetMask = "255.255.255.0",
		globalV4LeaseTime = 86400,
		onAdd = () => {},
		onEdit = (_idx: number) => {},
		onDelete = (_idx: number) => {},
	}: {
		v4Pools?: Dhcpv4PoolConfig[];
		poolStats?: DhcpPoolsResponse;
		loading?: boolean;
		globalV4Router?: string;
		globalV4SubnetMask?: string;
		globalV4LeaseTime?: number;
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
			bar: "bg-emerald-500",
			badge: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
			text: "text-emerald-400",
			label: "Healthy",
		};
	}

	function findV4LiveStats(pool: Dhcpv4PoolConfig): DhcpPoolEntry | undefined {
		return poolStats.v4_pools.find(
			(p) => p.range_start === pool.range_start && p.range_end === pool.range_end,
		);
	}
</script>

<DataTableCard
	title="IPv4 Dynamic Address Scopes"
	icon={ServerIcon}
	description="Dynamic allocation ranges for IPv4 clients with per-pool gateway, netmask, and capacity telemetry"
	total={v4Pools.length}
	itemName="scopes"
	showSearch={false}
	showPagination={false}
	containerHeight="h-auto"
	minTableWidth="min-w-[700px]"
	columns={6}
	{loading}
	isEmpty={v4Pools.length === 0}
	emptyMessage="Lanforge is currently not serving dynamic IPv4 leases. Add an address scope to begin allocating IP ranges."
>
	{#snippet titleExtra()}
		<Badge variant="outline" class="font-mono text-[10px]">
			{v4Pools.length} {v4Pools.length === 1 ? "Pool" : "Pools"}
		</Badge>
	{/snippet}

	{#snippet actions()}
		<Button size="sm" onclick={onAdd} class="h-8 text-xs gap-1.5 cursor-pointer">
			<PlusIcon class="size-3.5" />
			<span>Add IPv4 Scope</span>
		</Button>
	{/snippet}

	{#snippet emptyAction()}
		<Button size="sm" onclick={onAdd} class="h-8 text-xs gap-1.5 cursor-pointer">
			<PlusIcon class="size-3.5" />
			<span>Add Primary IPv4 Scope</span>
		</Button>
	{/snippet}

	{#snippet header()}
		<Table.Head class="w-[180px]">Scope Name</Table.Head>
		<Table.Head>Dynamic IP Range</Table.Head>
		<Table.Head>Gateway / Mask</Table.Head>
		<Table.Head class="w-[220px]">Live Capacity &amp; Utilization</Table.Head>
		<Table.Head>Lease Time</Table.Head>
		<Table.Head class="text-right w-[110px]">Actions</Table.Head>
	{/snippet}

	{#each v4Pools as pool, idx (idx)}
		{@const live = findV4LiveStats(pool)}
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
					{#if pool.boot_file}
						<div class="flex items-center gap-1 text-[10px] text-muted-foreground">
							<HardDriveDownloadIcon class="size-3 text-emerald-400" />
							<span class="font-mono">{pool.boot_file}</span>
						</div>
					{/if}
				</div>
			</Table.Cell>

			<Table.Cell>
				<div class="flex items-center gap-1.5 font-mono text-xs">
					<span class="text-emerald-400 font-semibold">{pool.range_start}</span>
					<span class="text-muted-foreground">–</span>
					<span class="text-emerald-400 font-semibold">{pool.range_end}</span>
				</div>
			</Table.Cell>

			<Table.Cell>
				<div class="flex flex-col gap-0.5 font-mono text-xs">
					<span class="text-foreground">
						GW: {pool.router || globalV4Router || "Default"}
					</span>
					<span class="text-muted-foreground text-[11px]">
						Mask: {pool.subnet_mask || globalV4SubnetMask}
					</span>
				</div>
			</Table.Cell>

			<Table.Cell>
				<div class="flex flex-col gap-1.5">
					<div class="flex items-center justify-between text-[11px] font-mono">
						<span class="font-medium text-foreground">
							{used} / {total > 0 ? total : "—"} used
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
				{pool.lease_time ? `${Math.round(pool.lease_time / 3600)}h` : `${Math.round(globalV4LeaseTime / 3600)}h (Default)`}
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
