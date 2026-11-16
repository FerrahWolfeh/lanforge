<script lang="ts">
	import { untrack } from "svelte";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import LinkIcon from "@lucide/svelte/icons/link";
	import XIcon from "@lucide/svelte/icons/x";
	import { toast } from "svelte-sonner";
	import { deviceLinkedSet } from "$lib/api/client";
	import type { DeviceEntry } from "$lib/api/types";

	/** The addresses linked to one device (its tailnet / VPN addresses). */
	let {
		open = $bindable(false),
		device = null,
		onSaved = () => {},
	}: {
		open?: boolean;
		device?: DeviceEntry | null;
		onSaved?: () => void;
	} = $props();

	let addresses = $state<string[]>([]);
	let draft = $state("");
	let submitting = $state(false);

	$effect(() => {
		// `device` is replaced on every page reload: read it untracked so an open dialog keeps its edits.
		if (open) {
			untrack(() => {
				addresses = [...(device?.linked_addresses ?? [])];
				draft = "";
			});
		}
	});

	function add() {
		const value = draft.trim();
		if (!value) return;
		if (!addresses.includes(value)) addresses = [...addresses, value];
		draft = "";
	}

	function remove(address: string) {
		addresses = addresses.filter((a) => a !== address);
	}

	async function save() {
		if (!device) return;
		// An address typed but not added yet still counts.
		add();
		submitting = true;
		try {
			await deviceLinkedSet(device.mac, addresses);
			toast.success(`Linked addresses of ${device.hostname || device.mac} saved`);
			open = false;
			onSaved();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save the linked addresses");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<LinkIcon class="size-5 text-primary" />
				<span>Linked addresses: {device?.hostname || device?.mac}</span>
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Addresses this device uses outside the LAN, such as its Tailscale IPv4 and IPv6. DNS
				statistics and adblock groups count them as this device. They are never used in DNS
				answers, rewrites, port forwards or the firewall.
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex flex-col gap-3 py-2 text-xs">
			{#if addresses.length === 0}
				<p class="text-muted-foreground">No linked addresses.</p>
			{/if}
			{#each addresses as address (address)}
				<div class="flex items-center justify-between gap-3 rounded-md border px-3 py-1.5">
					<span class="font-mono">{address}</span>
					<Button
						variant="ghost"
						size="icon"
						class="size-6"
						aria-label={`Remove ${address}`}
						onclick={() => remove(address)}
					>
						<XIcon class="size-3.5" />
					</Button>
				</div>
			{/each}
			<form
				class="flex items-center gap-2"
				onsubmit={(e) => {
					e.preventDefault();
					add();
				}}
			>
				<Input
					bind:value={draft}
					placeholder="100.64.0.6 or fd7a:115c:a1e0::1"
					class="h-8 font-mono text-xs"
				/>
				<Button type="submit" variant="outline" size="sm" disabled={!draft.trim()}>Add</Button>
			</form>
		</div>

		<div class="flex items-center justify-end gap-2">
			<Button type="button" variant="outline" size="sm" onclick={() => (open = false)}>
				Cancel
			</Button>
			<Button size="sm" disabled={submitting || !device} onclick={save}>Save</Button>
		</div>
	</Dialog.Content>
</Dialog.Root>
