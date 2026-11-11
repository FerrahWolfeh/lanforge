<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import UsersIcon from "@lucide/svelte/icons/users";
	import CheckIcon from "@lucide/svelte/icons/check";
	import { toast } from "svelte-sonner";
	import { dnsAdblockGroupCreate, dnsAdblockGroupUpdate } from "$lib/api/client";
	import type { AdblockGroupEntry } from "$lib/api/types";
	import AdblockClientsEditor from "./AdblockClientsEditor.svelte";

	/** Creates a group (`group` null) or edits one: its clients and the lists it adds. */
	let {
		open = $bindable(false),
		group = null,
		lists = [],
		onSaved = () => {},
	}: {
		open?: boolean;
		group?: AdblockGroupEntry | null;
		/** Source names a group can add: every list that is not in the global layer. */
		lists?: string[];
		onSaved?: () => void;
	} = $props();

	let name = $state("");
	let clients = $state<string[]>([]);
	let chosen = $state<string[]>([]);
	let submitting = $state(false);

	const NAME = /^[A-Za-z0-9_-]{1,64}$/;

	$effect(() => {
		if (open) {
			name = group?.name ?? "";
			clients = group ? group.clients.map((c) => c.selector) : [];
			chosen = group ? [...group.lists] : [];
		}
	});

	const offered = $derived([...new Set([...lists, ...chosen])]);

	function toggle(list: string) {
		chosen = chosen.includes(list) ? chosen.filter((l) => l !== list) : [...chosen, list];
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!group && !NAME.test(name.trim())) {
			toast.error("Use letters, digits, '-' and '_' for the group name");
			return;
		}
		submitting = true;
		try {
			if (group) {
				await dnsAdblockGroupUpdate(group.name, chosen, clients);
				toast.success(`Group "${group.name}" saved`);
			} else {
				await dnsAdblockGroupCreate(name.trim(), chosen, clients);
				toast.success(`Group "${name.trim()}" created`);
			}
			open = false;
			onSaved();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save the group");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-lg">
		<Dialog.Header>
			<div class="flex items-center gap-2">
				<div class="p-2 rounded-lg bg-primary/10 text-primary">
					<UsersIcon class="size-4" />
				</div>
				<Dialog.Title>{group ? `Edit group "${group.name}"` : "New adblock group"}</Dialog.Title>
			</div>
			<Dialog.Description class="text-xs">
				A group overrides the global layer for its clients: its allow rules let through what
				the global lists block, its block rules and lists block more.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleSubmit} class="flex flex-col gap-5 py-2">
			{#if !group}
				<div class="flex flex-col gap-1.5">
					<Label for="group-name" class="text-xs font-semibold">Name</Label>
					<Input
						id="group-name"
						placeholder="e.g. banking or kids"
						class="font-mono text-xs"
						bind:value={name}
						required
					/>
					<p class="text-[11px] text-muted-foreground">
						Letters, digits, '-' and '_'. Its rules live in <span class="font-mono"
							>adblock/&lt;name&gt;.rules</span
						>.
					</p>
				</div>
			{/if}

			<div class="flex flex-col gap-1.5">
				<Label class="text-xs font-semibold">Clients</Label>
				<AdblockClientsEditor bind:clients known={group?.clients ?? []} />
			</div>

			<div class="flex flex-col gap-1.5">
				<Label class="text-xs font-semibold">Extra lists</Label>
				{#if offered.length === 0}
					<p class="text-[11px] text-muted-foreground">
						No list outside the global layer. Add one from the Blocklists tab, for this group.
					</p>
				{:else}
					<div class="flex flex-wrap gap-1.5">
						{#each offered as list (list)}
							<Button
								type="button"
								variant={chosen.includes(list) ? "default" : "outline"}
								size="sm"
								class="h-7 gap-1 font-mono text-[11px]"
								onclick={() => toggle(list)}
							>
								{#if chosen.includes(list)}
									<CheckIcon class="size-3" />
								{/if}
								{list}
							</Button>
						{/each}
					</div>
				{/if}
			</div>

			<div class="flex items-center justify-end gap-2">
				<Button type="button" variant="outline" size="sm" onclick={() => (open = false)}>
					Cancel
				</Button>
				<Button type="submit" size="sm" disabled={submitting}>
					{group ? "Save" : "Create group"}
				</Button>
			</div>
		</form>
	</Dialog.Content>
</Dialog.Root>
