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
	import ServerIcon from "@lucide/svelte/icons/server";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import type { Dhcpv4PoolConfig, DhcpPoolsResponse, DhcpPoolEntry } from "$lib/api/types";

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

<Card.Root>
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div>
				<div class="flex items-center gap-2">
					<ServerIcon class="size-4 text-blue-400" />
					<Card.Title class="text-base">IPv4 Dynamic Address Scopes</Card.Title>
					<Badge variant="outline" class="font-mono text-[10px]">
						{v4Pools.length} {v4Pools.length === 1 ? "Pool" : "Pools"}
					</Badge>
				</div>
				<Card.Description class="text-xs">
					Dynamic allocation ranges for IPv4 clients with per-pool gateway, netmask, and capacity telemetry
				</Card.Description>
			</div>

			<Button size="sm" onclick={onAdd} class="h-8 text-xs">
				<PlusIcon data-icon="inline-start" class="size-3.5" />
				Add IPv4 Scope
			</Button>
		</div>
	</Card.Header>

	<Card.Content class="p-0">
		{#if loading}
			<div class="p-6 flex flex-col gap-3">
				<Skeleton class="h-10 w-full" />
				<Skeleton class="h-10 w-full" />
				<Skeleton class="h-10 w-full" />
			</div>
		{:else if v4Pools.length === 0}
			<Empty.Root class="py-12">
				<Empty.Header>
					<Empty.Media variant="icon">
						<NetworkIcon class="size-6 text-muted-foreground" />
					</Empty.Media>
					<Empty.Title>No IPv4 Scopes Configured</Empty.Title>
					<Empty.Description>
						Lanforge is currently not serving dynamic IPv4 leases. Add an address scope to begin allocating IP ranges.
					</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					<Button size="sm" onclick={onAdd} class="h-8 text-xs">
						<PlusIcon data-icon="inline-start" class="size-3.5" />
						Add Primary IPv4 Scope
					</Button>
				</Empty.Content>
			</Empty.Root>
		{:else}
			<!-- Mobile View: Touch Cards -->
			<div class="flex flex-col divide-y sm:hidden">
				{#each v4Pools as pool, idx (idx)}
					{@const live = findV4LiveStats(pool)}
					{@const used = live?.used ?? 0}
					{@const total = live?.total ?? 0}
					{@const pct = live?.utilization_percent ?? (total > 0 ? Math.round((used / total) * 100) : 0)}
					{@const style = getUtilizationStyles(pct)}
					<div class="p-4 flex flex-col gap-3">
						<div class="flex items-start justify-between gap-2">
							<div class="flex flex-col gap-0.5">
								<span class="font-bold text-foreground text-sm">
									{pool.name || `Scope #${idx + 1}`}
								</span>
								<div class="flex items-center gap-1.5 font-mono text-xs">
									<span class="text-emerald-500 font-medium">{pool.range_start}</span>
									<span class="text-muted-foreground">–</span>
									<span class="text-emerald-500 font-medium">{pool.range_end}</span>
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

						<!-- Capacity Bar -->
						<div class="flex flex-col gap-1.5 bg-muted/20 p-2.5 rounded-lg border">
							<div class="flex items-center justify-between text-xs font-mono">
								<span class="text-muted-foreground">
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

						<!-- Details Pills -->
						<div class="flex flex-wrap items-center gap-2 text-[11px] font-mono text-muted-foreground">
							<span class="bg-muted/40 px-2 py-0.5 rounded border">
								GW: {pool.router || globalV4Router || "Default"}
							</span>
							<span class="bg-muted/40 px-2 py-0.5 rounded border">
								Mask: {pool.subnet_mask || globalV4SubnetMask}
							</span>
							<span class="bg-muted/40 px-2 py-0.5 rounded border">
								Lease: {pool.lease_time ? `${Math.round(pool.lease_time / 3600)}h` : `${Math.round(globalV4LeaseTime / 3600)}h`}
							</span>
							{#if pool.boot_file}
								<span class="bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 px-2 py-0.5 rounded flex items-center gap-1">
									<HardDriveDownloadIcon class="size-3" />
									{pool.boot_file}
								</span>
							{/if}
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
							<Table.Head>Dynamic IP Range</Table.Head>
							<Table.Head>Gateway / Mask</Table.Head>
							<Table.Head class="w-[220px]">Live Capacity &amp; Utilization</Table.Head>
							<Table.Head>Lease Time</Table.Head>
							<Table.Head class="text-right w-[110px]">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each v4Pools as pool, idx (idx)}
							{@const live = findV4LiveStats(pool)}
							{@const used = live?.used ?? 0}
							{@const total = live?.total ?? 0}
							{@const pct = live?.utilization_percent ?? (total > 0 ? Math.round((used / total) * 100) : 0)}
							{@const style = getUtilizationStyles(pct)}
							<Table.Row class="hover:bg-muted/30 transition-colors">
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
