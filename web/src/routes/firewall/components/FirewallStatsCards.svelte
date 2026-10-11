<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
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
	<StatCardGrid cols={4}>
		<!-- Card 1: Operation Mode -->
		<StatCard
			label="Operation Mode"
			value={status ? (status.mode === "full" ? "Standalone" : status.mode === "minimal" ? "Coexistence" : "Disabled") : "—"}
			icon={status?.mode === "full" ? ShieldCheckIcon : ShieldOffIcon}
			color={status?.mode === "full" ? "emerald" : status?.mode === "minimal" ? "primary" : "zinc"}
			badge={status ? {
				text: status.mode === "full" ? "Authoritative" : status.mode === "minimal" ? "Coexistence" : "Disabled",
				variant: status.mode === "full" ? "online" : status.mode === "minimal" ? "warning" : "dormant",
				showDot: true
			} : undefined}
			subtext={status ? (status.mode === "full" ? "Authoritative standalone gateway" : status.mode === "minimal" ? "Helper table with system firewall" : "Kernel nftables unmanaged") : "Firewall status unavailable"}
			loading={loading && !status}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Backend" value="nftables" />
				<StatCardFooterItem
					label="Engine"
					value={status?.enabled ? "Active" : "Inactive"}
					color={status?.enabled ? "text-emerald-500" : "text-muted-foreground"}
				/>
			{/snippet}
		</StatCard>

		<!-- Card 2: Active Rules & Ports -->
		<StatCard
			label="Filtering Rules"
			value={status ? status.rules_count : "—"}
			icon={LayersIcon}
			color="sky"
			subtext={status ? (status.default_drop_active ? "Default Drop policy active" : "Default Accept policy") : "Rules unavailable"}
			loading={loading && !status}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Open Ports" value={status ? status.open_ports_count : "—"} />
				<StatCardFooterItem
					label="Default Policy"
					value={status ? (status.default_drop_active ? "DROP" : "ACCEPT") : "—"}
					color={status?.default_drop_active ? "text-emerald-500" : "text-amber-500"}
				/>
			{/snippet}
		</StatCard>

		<!-- Card 3: Flowtable Offload -->
		<StatCard
			label="Flowtable Offload"
			value={status ? (status.flow_offload_active ? "Accelerated" : "Disabled") : "—"}
			icon={ZapIcon}
			color={status?.flow_offload_active ? "amber" : "zinc"}
			badge={status ? {
				text: status.flow_offload_active ? "Hardware / Fast-Path" : "Disabled",
				variant: status.flow_offload_active ? "online" : "dormant",
				showDot: true
			} : undefined}
			subtext={status ? (status.flow_offload_active ? "Line-rate fast-path bypass" : "Standard routing stack traversal") : "Offload status unavailable"}
			loading={loading && !status}
		>
			{#snippet footer()}
				<StatCardFooterItem
					label="Fast-Path"
					value={status?.flow_offload_active ? "Enabled" : "Disabled"}
					color={status?.flow_offload_active ? "text-amber-500" : "text-muted-foreground"}
				/>
				<StatCardFooterItem label="Bypass" value="L3 / L4 Netlink" />
			{/snippet}
		</StatCard>

		<!-- Card 4: Dataplane & Runtime -->
		<StatCard
			label="Dataplane Status"
			value={status ? (status.enabled ? "Active" : "Inactive") : "—"}
			icon={CpuIcon}
			color={status?.enabled ? "emerald" : "zinc"}
			subtext={status ? `Last applied: ${formatSecsAgo(status.last_applied_secs_ago)}` : "Dataplane unavailable"}
			loading={loading && !status}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Last Sync" value={status ? formatSecsAgo(status.last_applied_secs_ago) : "—"} />
				<StatCardFooterItem
					label="Transaction"
					value={activeTxId ? "In Flight" : "Committed"}
					color={activeTxId ? "text-amber-500" : "text-emerald-500"}
				/>
			{/snippet}
		</StatCard>
	</StatCardGrid>
</div>
