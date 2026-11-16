<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import StatStrip from "$lib/components/StatStrip.svelte";
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
		<div class="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-warning/40 bg-warning/10 p-3.5 text-xs font-medium text-warning">
			<div class="flex items-center gap-2">
				<AlertTriangleIcon class="size-4 shrink-0 text-warning" />
				<span>
					Auto-rollback in <strong class="font-mono text-foreground font-bold">{rollbackSecsLeft}s</strong> — confirm your connection to keep new nftables rules.
				</span>
			</div>
			<div class="flex items-center gap-2">
				<Button
					size="sm"
					class="h-7 px-3 text-xs bg-warning hover:bg-warning/90 text-white font-medium"
					onclick={onConfirmNow}
				>
					Confirm Connection
				</Button>
				<Button
					variant="outline"
					size="sm"
					class="h-7 px-3 text-xs border-warning/40 text-warning hover:bg-warning/10"
					onclick={onAbort}
				>
					Rollback Now
				</Button>
			</div>
		</div>
	{:else if activeTxId !== null}
		<div class="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/40 p-3 text-xs text-muted-foreground">
			<div class="flex items-center gap-2">
				<span class="relative flex size-2">
					<span class="relative inline-flex rounded-full size-2 bg-primary"></span>
				</span>
				<span>Transaction pending: <code class="font-mono text-xs text-foreground">{activeTxId}</code></span>
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

	<StatStrip
		items={[
			{ label: "rules", value: status ? status.rules_count : null, icon: LayersIcon },
			{ label: "open ports", value: status ? status.open_ports_count : null },
			{ label: "default policy", value: status ? (status.default_drop_active ? "Drop" : "Accept") : null },
			{
				label: "flow offload",
				value: status ? (status.flow_offload_suspended ? "Paused" : status.flow_offload_active ? "On" : "Off") : null,
				icon: ZapIcon,
				tone: status?.flow_offload_suspended ? "warning" : undefined
			}
		]}
	/>
</div>
