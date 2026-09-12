<script lang="ts">
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Badge } from "$lib/components/ui/badge";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import CheckIcon from "@lucide/svelte/icons/check";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import type { SystemConfigImportResponse } from "$lib/api/types";

	let {
		open = $bindable(false),
		result = null,
	}: {
		open?: boolean;
		result?: SystemConfigImportResponse | null;
	} = $props();
</script>

<AlertDialog.Root bind:open>
	<AlertDialog.Content class="max-w-lg">
		<AlertDialog.Header>
			<AlertDialog.Title class="flex items-center gap-2">
				{#if result?.total_success}
					<CheckCircleIcon class="size-5 text-emerald-500" />
					<span>Configuration Restored</span>
				{:else}
					<AlertTriangleIcon class="size-5 text-amber-500" />
					<span>Restore Completed with Warnings</span>
				{/if}
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Detailed report of the imported subsystem configuration entries:
			</AlertDialog.Description>
		</AlertDialog.Header>

		{#if result}
			<div class="max-h-64 overflow-y-auto space-y-2 py-2">
				{#each result.results as res}
					<div class="flex items-center justify-between rounded-md border p-2 text-xs">
						<span class="font-mono font-medium">{res.section}</span>
						{#if res.success}
							<Badge variant="outline" class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
								<CheckIcon class="size-3 mr-1" />
								{res.count} imported
							</Badge>
						{:else}
							<Badge
								variant="outline"
								class="border-destructive/25 bg-destructive/10 text-destructive truncate max-w-[200px]"
								title={res.error || "failed"}
							>
								<XCircleIcon class="size-3 mr-1" />
								{res.error || "failed"}
							</Badge>
						{/if}
					</div>
				{/each}
			</div>
		{/if}

		<AlertDialog.Footer>
			<AlertDialog.Action onclick={() => (open = false)}>
				Close
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
