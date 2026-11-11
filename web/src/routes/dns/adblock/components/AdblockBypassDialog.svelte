<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import { toast } from "svelte-sonner";
	import { dnsAdblockBypassSet } from "$lib/api/client";
	import type { AdblockClientEntry } from "$lib/api/types";
	import AdblockClientsEditor from "./AdblockClientsEditor.svelte";

	/** Edits the clients adblock never filters. */
	let {
		open = $bindable(false),
		bypass = [],
		onSaved = () => {},
	}: {
		open?: boolean;
		bypass?: AdblockClientEntry[];
		onSaved?: () => void;
	} = $props();

	let clients = $state<string[]>([]);
	let submitting = $state(false);

	$effect(() => {
		if (open) clients = bypass.map((c) => c.selector);
	});

	async function handleSubmit(e: Event) {
		e.preventDefault();
		submitting = true;
		try {
			await dnsAdblockBypassSet(clients);
			toast.success("Bypass saved");
			open = false;
			onSaved();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save the bypass");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-lg">
		<Dialog.Header>
			<div class="flex items-center gap-2">
				<div class="p-2 rounded-lg bg-amber-500/10 text-amber-500">
					<ShieldOffIcon class="size-4" />
				</div>
				<Dialog.Title>Bypass</Dialog.Title>
			</div>
			<Dialog.Description class="text-xs">
				These clients are never filtered, whatever the global layer and their groups say.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleSubmit} class="flex flex-col gap-5 py-2">
			<AdblockClientsEditor bind:clients known={bypass} />
			<div class="flex items-center justify-end gap-2">
				<Button type="button" variant="outline" size="sm" onclick={() => (open = false)}>
					Cancel
				</Button>
				<Button type="submit" size="sm" disabled={submitting}>Save</Button>
			</div>
		</form>
	</Dialog.Content>
</Dialog.Root>
