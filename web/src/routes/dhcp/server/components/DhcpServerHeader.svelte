<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import SaveIcon from "@lucide/svelte/icons/save";

	let {
		isDirty = false,
		loading = false,
		saving = false,
		reconciling = false,
		onReconcile = () => {},
		onRefresh = () => {},
		onDiscard = () => {},
		onSave = () => {},
	}: {
		isDirty?: boolean;
		loading?: boolean;
		saving?: boolean;
		reconciling?: boolean;
		onReconcile?: () => void;
		onRefresh?: () => void;
		onDiscard?: () => void;
		onSave?: () => void;
	} = $props();
</script>

<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-muted/30 border rounded-xl p-4 shadow-sm">
	<div class="flex items-center gap-3">
		<div class="p-2.5 rounded-lg bg-primary/10 text-primary shrink-0">
			<SlidersIcon class="size-6" />
		</div>
		<div>
			<div class="flex items-center gap-2">
				<h2 class="text-lg font-bold tracking-tight">DHCP Server Options</h2>
				{#if isDirty}
					<Badge
						variant="outline"
						class="text-amber-500 border-amber-500/30 bg-amber-500/10 text-xs font-semibold animate-pulse"
					>
						Unsaved Changes
					</Badge>
				{/if}
			</div>
			<p class="text-xs text-muted-foreground mt-0.5">
				Global parameters broadcasted to all DHCP clients on your network link.
			</p>
		</div>
	</div>

	<div class="flex flex-wrap items-center gap-2">
		<Button
			variant="outline"
			size="sm"
			onclick={onReconcile}
			disabled={reconciling || loading || saving}
			title="Audit active dynamic leases against current subnet & pools (RFC 3203 ForceRenew)"
			class="h-8 text-xs"
		>
			<ShieldCheckIcon
				class={`size-3.5 mr-1.5 ${reconciling ? "animate-spin text-primary" : "text-emerald-500"}`}
			/>
			{reconciling ? "Auditing..." : "Reconcile Leases"}
		</Button>

		<Button
			variant="outline"
			size="sm"
			onclick={onRefresh}
			disabled={loading || saving || reconciling}
			class="h-8 text-xs"
		>
			<RefreshCwIcon class={`size-3.5 mr-1.5 ${loading ? "animate-spin" : ""}`} />
			Refresh
		</Button>

		{#if isDirty}
			<Button
				variant="ghost"
				size="sm"
				onclick={onDiscard}
				disabled={saving}
				class="h-8 text-xs"
			>
				<RotateCcwIcon class="size-3.5 mr-1.5" />
				Discard
			</Button>
		{/if}

		<Button
			size="sm"
			onclick={onSave}
			disabled={!isDirty || saving || loading}
			class="h-8 text-xs shadow-sm"
		>
			<SaveIcon class={`size-3.5 mr-1.5 ${saving ? "animate-spin" : ""}`} />
			{saving ? "Saving..." : "Save Server Options"}
		</Button>
	</div>
</div>
