<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import FileTextIcon from "@lucide/svelte/icons/file-text";
	import CheckIcon from "@lucide/svelte/icons/check";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";

	let {
		pruning = false,
		logCleaning = false,
		lastPruneTime = null,
		lastLogCleanTime = null,
		formatTimeAgo = () => "Never",
		onPrune = () => {},
		onLogClean = () => {},
		onOpenWipeDialog = () => {},
	}: {
		pruning?: boolean;
		logCleaning?: boolean;
		lastPruneTime?: number | null;
		lastLogCleanTime?: number | null;
		formatTimeAgo?: (secs: number | null | undefined) => string;
		onPrune?: () => void;
		onLogClean?: () => void;
		onOpenWipeDialog?: () => void;
	} = $props();
</script>

<div class="flex flex-col gap-6">
	<div class="grid grid-cols-1 gap-4 md:grid-cols-2">

		<!-- Prune -->
		<Card.Root class="flex flex-col justify-between">
			<Card.Header>
				<Card.Title class="flex items-center gap-2 text-base font-semibold">
					<Trash2Icon class="size-4 text-primary" />
					Prune Zombie Devices
				</Card.Title>
				<Card.Description class="text-xs leading-relaxed mt-1">
					Scans and purges dynamic devices that do not have hostnames, active leases, nor recent network activity.
				</Card.Description>
			</Card.Header>
			<Card.Content class="pt-0 space-y-3">
				{#if lastPruneTime}
					<p class="text-[11px] text-emerald-500 flex items-center gap-1 font-medium">
						<CheckIcon class="size-3" />
						Executed {formatTimeAgo(Math.floor(Date.now() / 1000) - lastPruneTime)}
					</p>
				{/if}
				<Button
					variant="outline"
					size="sm"
					class="w-full gap-2 text-xs"
					onclick={onPrune}
					disabled={pruning}
				>
					<Trash2Icon class={pruning ? "animate-spin size-4" : "size-4"} />
					{pruning ? "Pruning..." : "Prune Inactive"}
				</Button>
			</Card.Content>
		</Card.Root>

		<!-- Log Clean -->
		<Card.Root class="flex flex-col justify-between">
			<Card.Header>
				<Card.Title class="flex items-center gap-2 text-base font-semibold">
					<FileTextIcon class="size-4 text-primary" />
					Clear Log Buffers
				</Card.Title>
				<Card.Description class="text-xs leading-relaxed mt-1">
					Truncates temporary DNS query records and system lifecycle event log buffers.
				</Card.Description>
			</Card.Header>
			<Card.Content class="pt-0 space-y-3">
				{#if lastLogCleanTime}
					<p class="text-[11px] text-emerald-500 flex items-center gap-1 font-medium">
						<CheckIcon class="size-3" />
						Executed {formatTimeAgo(Math.floor(Date.now() / 1000) - lastLogCleanTime)}
					</p>
				{/if}
				<Button
					variant="outline"
					size="sm"
					class="w-full gap-2 text-xs"
					onclick={onLogClean}
					disabled={logCleaning}
				>
					<FileTextIcon class={logCleaning ? "animate-spin size-4" : "size-4"} />
					{logCleaning ? "Clearing..." : "Clear Log Buffers"}
				</Button>
			</Card.Content>
		</Card.Root>
	</div>

	<!-- Danger Zone -->
	<Card.Root class="border-destructive/30 bg-destructive/5">
		<Card.Header>
			<Card.Title class="flex items-center gap-2 text-destructive text-base font-semibold">
				<AlertTriangleIcon class="size-5" />
				Danger Zone: Storage Reset
			</Card.Title>
			<Card.Description class="text-xs text-muted-foreground leading-relaxed mt-1">
				Permanently clear all persistent data cascades (hosts, leases, custom rewrites, DHCP pools, and token tables). This action is irreversible.
			</Card.Description>
		</Card.Header>
		<Card.Content class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-0">
			<div class="text-xs text-muted-foreground">
				Requires explicit manual confirmation with confirmation word.
			</div>
			<Button
				variant="destructive"
				size="sm"
				onclick={onOpenWipeDialog}
			>
				Reset Database
			</Button>
		</Card.Content>
	</Card.Root>
</div>
