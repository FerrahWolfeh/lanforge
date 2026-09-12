<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import BookmarkPlusIcon from "@lucide/svelte/icons/bookmark-plus";
	import { toast } from "svelte-sonner";
	import { hostAdd } from "$lib/api/client";
	import type { LeaseEntry, HostConfigEntry } from "$lib/api/types";

	let {
		open = $bindable(false),
		lease = null,
		onPromoted = async () => {},
	}: {
		open?: boolean;
		lease?: LeaseEntry | null;
		onPromoted?: () => Promise<void>;
	} = $props();

	let formMac = $state("");
	let formHostname = $state("");
	let formV4 = $state("");
	let formV6Suffix = $state("");
	let submitting = $state(false);

	$effect(() => {
		if (open && lease) {
			formMac = lease.mac;
			formHostname = lease.hostname || "";
			if (lease.kind === "v4") {
				formV4 = lease.address;
				formV6Suffix = "";
			} else {
				formV4 = "";
				formV6Suffix = lease.address;
			}
		}
	});

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!formMac.trim()) {
			toast.error("MAC address is required");
			return;
		}

		submitting = true;
		try {
			const entry: HostConfigEntry = {
				mac: formMac.trim(),
				hostname: formHostname.trim(),
				v4_fixed: formV4.trim() || undefined,
				v6_suffix: formV6Suffix.trim() || undefined,
				origin: "Static",
			};
			await hostAdd(entry);
			toast.success(`Converted ${formMac} into a static reservation!`);
			open = false;
			await onPromoted();
		} catch (err: any) {
			toast.error(err?.message || "Failed to create static reservation");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<BookmarkPlusIcon class="size-5 text-amber-400" />
				<span>Convert Lease to Static Reservation</span>
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Pin this client's IP so it permanently receives the same address and DNS hostname.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleSubmit} class="py-2">
			<Field.FieldGroup class="gap-4">
				<Field.Field>
					<Field.FieldLabel for="lpmac">MAC Address</Field.FieldLabel>
					<Input
						id="lpmac"
						class="font-mono text-xs bg-muted/30"
						bind:value={formMac}
						readonly
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="lphostname">Hostname</Field.FieldLabel>
					<Input
						id="lphostname"
						placeholder="e.g. printer-office"
						class="text-xs"
						bind:value={formHostname}
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="lpv4">Reserved IPv4 Address</Field.FieldLabel>
					<Input
						id="lpv4"
						placeholder="e.g. 192.168.1.50"
						class="font-mono text-xs"
						bind:value={formV4}
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="lpv6">IPv6 Suffix / Address (Optional)</Field.FieldLabel>
					<Input
						id="lpv6"
						placeholder="e.g. ::50"
						class="font-mono text-xs"
						bind:value={formV6Suffix}
					/>
				</Field.Field>

				<div class="flex items-center justify-end gap-2 mt-2">
					<Button
						type="button"
						variant="outline"
						size="sm"
						onclick={() => (open = false)}
					>
						Cancel
					</Button>
					<Button
						type="submit"
						size="sm"
						disabled={submitting}
					>
						{#if submitting}
							<span class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"></span>
						{/if}
						Save Reservation
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>
