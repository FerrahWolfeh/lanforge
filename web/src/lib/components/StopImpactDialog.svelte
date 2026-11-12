<script lang="ts">
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { serviceStopImpact } from "$lib/api/client";
	import type { ServiceStopImpact, StopOutcome } from "$lib/api/types";

	let open = $state(false);
	let impact = $state<ServiceStopImpact | null>(null);
	let resolve: ((ok: boolean) => void) | null = null;

	const outcomeLabel: Record<StopOutcome, string> = {
		keeps_running: "keeps running",
		degraded: "degraded",
		paused: "paused",
	};

	/**
	 * Resolves true when the stop may go ahead: nothing running requires the service and it
	 * declares no warning, or the admin confirmed after seeing what happens (D-20).
	 */
	export async function confirmStop(id: string): Promise<boolean> {
		const result = await serviceStopImpact(id);
		if (result.affected.length === 0 && !result.warning) return true;
		impact = result;
		open = true;
		return new Promise((r) => (resolve = r));
	}

	function settle(ok: boolean) {
		open = false;
		resolve?.(ok);
		resolve = null;
	}
</script>

<AlertDialog.Root bind:open onOpenChange={(o) => { if (!o) settle(false); }}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Stop '{impact?.id}'?</AlertDialog.Title>
			{#if impact?.warning}
				<AlertDialog.Description class="font-medium text-amber-600 dark:text-amber-400">
					{impact.warning}
				</AlertDialog.Description>
			{/if}
			{#if impact?.affected.length}
				<AlertDialog.Description>
					These running services require it. None of them is stopped or restarted; while it is
					down they continue as listed.
				</AlertDialog.Description>
			{/if}
		</AlertDialog.Header>
		{#if impact?.affected.length}
		<ul class="flex flex-col gap-1 text-xs">
			{#each impact?.affected ?? [] as entry (entry.id)}
				<li class="flex items-center justify-between gap-3 rounded-md border px-3 py-1.5">
					<span class="font-medium">{entry.name} <span class="font-mono text-muted-foreground">[{entry.id}]</span></span>
					<span class={entry.outcome === "keeps_running" ? "text-muted-foreground" : "text-amber-500"}>
						{outcomeLabel[entry.outcome]}
					</span>
				</li>
			{/each}
		</ul>
		{/if}
		<AlertDialog.Footer>
			<AlertDialog.Cancel onclick={() => settle(false)}>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action onclick={() => settle(true)}>Stop</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
