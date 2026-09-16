<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Alert from "$lib/components/ui/alert";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import type { FirewallStatus } from "$lib/api/types";

	interface Props {
		status: FirewallStatus | null;
		loading: boolean;
		activeTxId: string | null;
		rollbackSecsLeft: number | null;
		onAbort: () => void;
		onConfirmNow: () => void;
	}

	let { status, loading, activeTxId, rollbackSecsLeft, onAbort, onConfirmNow }: Props = $props();

	function formatSecsAgo(secs: number | null): string {
		if (secs === null) return "Never";
		if (secs < 60) return `${secs}s ago`;
		if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
		return `${Math.floor(secs / 3600)}h ago`;
	}
</script>

<div class="flex flex-col gap-4 w-full">
	<!-- Rollback & Transaction Alert Banners -->
	{#if rollbackSecsLeft !== null}
		<div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 p-3.5 text-xs font-medium text-amber-700 dark:text-amber-400">
			<div class="flex items-center gap-2">
				<AlertTriangleIcon class="size-4 shrink-0 text-amber-500" />
				<span>
					Auto-rollback in <strong class="font-mono text-foreground font-bold">{rollbackSecsLeft}s</strong> — confirm your connection to keep new nftables rules.
				</span>
			</div>
			<div class="flex items-center gap-2">
				<Button
					size="sm"
					class="h-7 px-3 text-xs bg-amber-600 hover:bg-amber-500 text-white font-medium shadow-xs"
					onclick={onConfirmNow}
				>
					Confirm Connection
				</Button>
				<Button
					variant="outline"
					size="sm"
					class="h-7 px-3 text-xs border-amber-500/40 text-amber-700 dark:text-amber-300 hover:bg-amber-500/10"
					onclick={onAbort}
				>
					Rollback Now
				</Button>
			</div>
		</div>
	{:else if activeTxId !== null}
		<div class="flex items-center justify-between gap-3 rounded-xl border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
			<div class="flex items-center gap-2">
				<span class="relative flex size-2">
					<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
					<span class="relative inline-flex rounded-full size-2 bg-primary"></span>
				</span>
				<span>Transaction pending: <code class="font-mono text-[11px] text-foreground">{activeTxId}</code></span>
			</div>
			<Button
				variant="outline"
				size="sm"
				class="h-7 text-xs text-destructive border-destructive/30 hover:bg-destructive/10"
				onclick={onAbort}
			>
				Abort Transaction
			</Button>
		</div>
	{/if}

	<!-- 4-Card Stats Grid -->
	<div class="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Card 1: Operation Mode -->
		<Card.Root class="p-4">
			{#if loading && !status}
				<div class="flex flex-col gap-2">
					<Skeleton class="h-4 w-24" />
					<Skeleton class="h-6 w-32" />
					<Skeleton class="h-3 w-20" />
				</div>
			{:else if status}
				<div class="flex items-center justify-between">
					<span class="text-xs font-medium text-muted-foreground">Operation Mode</span>
					{#if status.mode === "full"}
						<Badge variant="outline" class="border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-[10px]">
							Standalone
						</Badge>
					{:else if status.mode === "minimal"}
						<Badge variant="outline" class="border-primary/30 bg-primary/10 text-primary text-[10px]">
							Coexistence
						</Badge>
					{:else}
						<Badge variant="secondary" class="text-[10px]">
							Disabled
						</Badge>
					{/if}
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-xl font-bold tracking-tight text-foreground capitalize">
						{status.mode || (status.enabled ? "full" : "disabled")}
					</span>
				</div>
				<p class="mt-1 text-[11px] text-muted-foreground">
					{#if status.mode === "full"}
						Authoritative standalone gateway
					{:else if status.mode === "minimal"}
						Helper table with system firewall
					{:else}
						Kernel nftables unmanaged
					{/if}
				</p>
			{:else}
				<div class="flex items-center gap-2 text-xs text-muted-foreground">
					<AlertTriangleIcon class="size-4 text-destructive" />
					<span>Firewall status unavailable</span>
				</div>
			{/if}
		</Card.Root>

		<!-- Card 2: Active Rules & Ports -->
		<Card.Root class="p-4">
			{#if loading && !status}
				<div class="flex flex-col gap-2">
					<Skeleton class="h-4 w-24" />
					<Skeleton class="h-6 w-32" />
					<Skeleton class="h-3 w-20" />
				</div>
			{:else if status}
				<div class="flex items-center justify-between">
					<span class="text-xs font-medium text-muted-foreground">Filtering Rules</span>
					<ActivityIcon class="size-4 text-muted-foreground" />
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-xl font-bold tracking-tight text-foreground font-mono">
						{status.rules_count}
					</span>
					<span class="text-xs text-muted-foreground font-mono">
						/ {status.open_ports_count} open ports
					</span>
				</div>
				<p class="mt-1 text-[11px] text-muted-foreground">
					{status.default_drop_active ? "Default Drop policy active" : "Default Accept policy"}
				</p>
			{:else}
				<div class="flex items-center gap-2 text-xs text-muted-foreground">
					<AlertTriangleIcon class="size-4 text-destructive" />
					<span>Rules unavailable</span>
				</div>
			{/if}
		</Card.Root>

		<!-- Card 3: Flowtable Offload -->
		<Card.Root class="p-4">
			{#if loading && !status}
				<div class="flex flex-col gap-2">
					<Skeleton class="h-4 w-24" />
					<Skeleton class="h-6 w-32" />
					<Skeleton class="h-3 w-20" />
				</div>
			{:else if status}
				<div class="flex items-center justify-between">
					<span class="text-xs font-medium text-muted-foreground">Flowtable Offload</span>
					<ZapIcon class="size-4 {status.flow_offload_active ? 'text-amber-500' : 'text-muted-foreground'}" />
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-xl font-bold tracking-tight text-foreground">
						{status.flow_offload_active ? "Accelerated" : "Disabled"}
					</span>
				</div>
				<p class="mt-1 text-[11px] text-muted-foreground">
					{status.flow_offload_active ? "Line-rate kernel fast-path bypass" : "Standard routing stack traversal"}
				</p>
			{:else}
				<div class="flex items-center gap-2 text-xs text-muted-foreground">
					<AlertTriangleIcon class="size-4 text-destructive" />
					<span>Offload status unavailable</span>
				</div>
			{/if}
		</Card.Root>

		<!-- Card 4: Dataplane & Runtime -->
		<Card.Root class="p-4">
			{#if loading && !status}
				<div class="flex flex-col gap-2">
					<Skeleton class="h-4 w-24" />
					<Skeleton class="h-6 w-32" />
					<Skeleton class="h-3 w-20" />
				</div>
			{:else if status}
				<div class="flex items-center justify-between">
					<span class="text-xs font-medium text-muted-foreground">Dataplane Status</span>
					<CpuIcon class="size-4 text-muted-foreground" />
				</div>
				<div class="mt-2 flex items-baseline gap-2">
					<span class="text-xl font-bold tracking-tight text-foreground">
						{status.enabled ? "Active" : "Inactive"}
					</span>
					<span class="text-[10px] text-muted-foreground font-mono">nftables</span>
				</div>
				<p class="mt-1 text-[11px] text-muted-foreground">
					Last applied: {formatSecsAgo(status.last_applied_secs_ago)}
				</p>
			{:else}
				<div class="flex items-center gap-2 text-xs text-muted-foreground">
					<AlertTriangleIcon class="size-4 text-destructive" />
					<span>Dataplane unavailable</span>
				</div>
			{/if}
		</Card.Root>
	</div>
</div>
