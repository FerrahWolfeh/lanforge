<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
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

	<StatCardGrid cols={2}>
		<StatCard
			label="Rules"
			value={status ? status.rules_count : "—"}
			icon={LayersIcon}
			color="sky"
			subtext={status ? `${status.open_ports_count} open ports · anything else is ${status.default_drop_active ? "dropped" : "accepted"}` : "Rules unavailable"}
			loading={loading && !status}
		/>

		<StatCard
			label="Flow Offload"
			value={status ? (status.flow_offload_suspended ? "Paused" : status.flow_offload_active ? "On" : "Off") : "—"}
			icon={ZapIcon}
			color={status?.flow_offload_suspended ? "amber" : status?.flow_offload_active ? "emerald" : "zinc"}
			subtext={status ? (status.flow_offload_suspended ? "Paused so CAKE can shape the traffic" : status.flow_offload_active ? "Established connections skip the full routing path" : "Every packet takes the full routing path") : "Offload status unavailable"}
			loading={loading && !status}
		/>
	</StatCardGrid>
</div>
