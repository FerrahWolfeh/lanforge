<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import { toast } from "svelte-sonner";
	import { leaseRelease } from "$lib/api/client";
	import type { LeaseEntry, LeaseTarget } from "$lib/api/types";

	let {
		open = $bindable(false),
		lease = null,
		onReleased = async () => {},
	}: {
		open?: boolean;
		lease?: LeaseEntry | null;
		onReleased?: () => Promise<void>;
	} = $props();

	let releasing = $state(false);

	async function handleConfirm() {
		if (!lease) return;
		releasing = true;
		try {
			const target: LeaseTarget = lease.kind === "v4" ? "V4" : { V6: { iaid: 0 } };
			await leaseRelease(lease.mac, target);
			toast.success(`Released DHCP lease for ${lease.address}`);
			open = false;
			await onReleased();
		} catch (err: any) {
			toast.error(err?.message || "Failed to release lease");
		} finally {
			releasing = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2 text-rose-500">
				<Trash2Icon class="size-5" />
				<span>Confirm Lease Release</span>
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Are you sure you want to forcibly release and purge this DHCP lease from memory?
			</Dialog.Description>
		</Dialog.Header>

		{#if lease}
			<div class="rounded-lg border border-border/60 bg-muted/30 p-3 flex flex-col gap-1.5 text-xs font-mono">
				<div class="flex justify-between">
					<span class="text-muted-foreground font-sans">Hostname:</span>
					<span class="font-sans font-semibold text-foreground">{lease.hostname || "—"}</span>
				</div>
				<div class="flex justify-between">
					<span class="text-muted-foreground font-sans">IP Address:</span>
					<span class="text-emerald-400 font-medium">{lease.address}</span>
				</div>
				<div class="flex justify-between">
					<span class="text-muted-foreground font-sans">MAC Address:</span>
					<span class="text-foreground">{lease.mac}</span>
				</div>
			</div>
		{/if}

		<Dialog.Footer class="flex flex-row justify-end gap-2 mt-2">
			<Button
				variant="outline"
				size="sm"
				onclick={() => (open = false)}
			>
				Cancel
			</Button>
			<Button
				variant="destructive"
				size="sm"
				onclick={handleConfirm}
				disabled={releasing}
			>
				{#if releasing}
					<span class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"></span>
				{/if}
				Release Lease
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
