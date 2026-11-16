<script lang="ts">
	import * as Sheet from "$lib/components/ui/sheet";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import { toast } from "svelte-sonner";
	import { untrack } from "svelte";
	import { hostAdd, hostRemove } from "$lib/api/client";
	import type { HostConfigEntry } from "$lib/api/types";
	import { z } from "zod";
	import { validateForm, macSchema, hostnameSchema, type FieldErrors } from "$lib/utils/validation";

	/** Name and fixed addresses of one device, kept in lanforge.toml as a static host. */
	let {
		open = $bindable(false),
		mac,
		name,
		reserved = false,
		initial,
		onSaved = async () => {},
	}: {
		open?: boolean;
		mac: string;
		/** The name the page shows for the device, used in messages. */
		name: string;
		/** The device already has a static host rule; enables "Remove reservation". */
		reserved?: boolean;
		/** Where the form starts: the existing rule, or the device as it is now. */
		initial: HostConfigEntry;
		onSaved?: () => Promise<void>;
	} = $props();

	const hostFormSchema = z.object({
		mac: macSchema,
		hostname: hostnameSchema.optional().or(z.literal("")),
		v4: z.string().trim().ipv4("Invalid IPv4 address format (e.g. 192.168.1.10)").optional().or(z.literal("")),
		v6Suffix: z
			.string()
			.trim()
			.regex(/^[0-9a-fA-F:]*$/, "Use hex digits and colons only (e.g. ::10)"),
	});

	let formName = $state("");
	let formV4 = $state("");
	let formV6 = $state("");
	let submitting = $state(false);
	let fieldErrors = $state<FieldErrors<{ mac: string; hostname: string; v4: string; v6Suffix: string }>>({});

	// Start from the given values each time the sheet opens. A device reload while it is open
	// must not overwrite what the user is typing, so `initial` is read untracked.
	$effect(() => {
		if (open) {
			untrack(() => {
				formName = initial.hostname ?? "";
				formV4 = initial.v4_fixed ?? initial.v4 ?? "";
				formV6 = initial.v6_suffix ?? "";
				fieldErrors = {};
			});
		}
	});

	async function handleSubmit(e: SubmitEvent) {
		e.preventDefault();
		if (submitting) return;
		fieldErrors = {};

		const validation = validateForm(hostFormSchema, {
			mac,
			hostname: formName,
			v4: formV4,
			v6Suffix: formV6,
		});
		if (!validation.success) {
			fieldErrors = validation.errors;
			toast.error("Please correct the invalid fields");
			return;
		}

		submitting = true;
		try {
			// hostAdd upserts. The DNS log settings belong to the device, not to the reservation.
			const entry: HostConfigEntry = {
				mac,
				hostname: formName.trim(),
				v4_fixed: formV4.trim() || undefined,
				v6_suffix: formV6.trim() || undefined,
				origin: "Static",
				ignore_dns_log: initial.ignore_dns_log ?? false,
				ignored_log_domains: initial.ignored_log_domains ?? [],
			};
			await hostAdd(entry);
			toast.success(reserved ? `Updated the reservation of ${name}` : `Reserved ${name} in lanforge.toml`);
			open = false;
			await onSaved();
		} catch (err: any) {
			toast.error(err?.message || "Failed to save the reservation");
		} finally {
			submitting = false;
		}
	}

	async function removeReservation() {
		if (!confirm(`Remove ${name} from lanforge.toml? The device keeps working with a dynamic lease.`)) return;
		submitting = true;
		try {
			await hostRemove(mac);
			toast.success(`Removed the reservation of ${name}`);
			open = false;
			await onSaved();
		} catch (err: any) {
			toast.error(err?.message || "Failed to remove the reservation");
		} finally {
			submitting = false;
		}
	}
</script>

<Sheet.Root bind:open>
	<Sheet.Content side="right" class="w-full p-0">
		<Sheet.Header class="gap-1 border-b border-border pr-14">
			<Sheet.Title>{reserved ? "Edit name and address" : "Reserve this device"}</Sheet.Title>
			<Sheet.Description>
				{reserved ? "The name and address are pinned in lanforge.toml." : "Pins the name and address of this device in lanforge.toml."}
			</Sheet.Description>
		</Sheet.Header>

		<form onsubmit={handleSubmit} class="flex min-h-0 flex-1 flex-col">
			<div class="flex flex-1 flex-col gap-4 overflow-y-auto p-6">
				<Field.FieldGroup class="gap-4">
					<Field.Field>
						<Field.FieldLabel for="device-host-name">Name</Field.FieldLabel>
						<Input
							id="device-host-name"
							placeholder="e.g. living-room-tv"
							bind:value={formName}
							aria-invalid={Boolean(fieldErrors.hostname)}
							oninput={() => {
								if (fieldErrors.hostname) fieldErrors.hostname = undefined;
							}}
						/>
						{#if fieldErrors.hostname}
							<p class="mt-1 flex items-center gap-1 text-xs font-medium text-danger">
								<AlertCircleIcon class="size-3.5 shrink-0" />
								{fieldErrors.hostname}
							</p>
						{/if}
						<Field.FieldDescription class="text-xs">
							Pinned in lanforge.toml; DNS and dev: rules use it.
						</Field.FieldDescription>
					</Field.Field>

					<Field.Field>
						<Field.FieldLabel for="device-host-v4">Fixed IPv4</Field.FieldLabel>
						<Input
							id="device-host-v4"
							placeholder="e.g. 192.168.3.10"
							class="font-mono text-xs"
							bind:value={formV4}
							aria-invalid={Boolean(fieldErrors.v4)}
							oninput={() => {
								if (fieldErrors.v4) fieldErrors.v4 = undefined;
							}}
						/>
						{#if fieldErrors.v4}
							<p class="mt-1 flex items-center gap-1 text-xs font-medium text-danger">
								<AlertCircleIcon class="size-3.5 shrink-0" />
								{fieldErrors.v4}
							</p>
						{/if}
						<Field.FieldDescription class="text-xs">
							DHCP always gives this device this address.
						</Field.FieldDescription>
					</Field.Field>

					<Field.Field>
						<Field.FieldLabel for="device-host-v6">IPv6 suffix</Field.FieldLabel>
						<Input
							id="device-host-v6"
							placeholder="e.g. ::10"
							class="font-mono text-xs"
							bind:value={formV6}
							aria-invalid={Boolean(fieldErrors.v6Suffix)}
							oninput={() => {
								if (fieldErrors.v6Suffix) fieldErrors.v6Suffix = undefined;
							}}
						/>
						{#if fieldErrors.v6Suffix}
							<p class="mt-1 flex items-center gap-1 text-xs font-medium text-danger">
								<AlertCircleIcon class="size-3.5 shrink-0" />
								{fieldErrors.v6Suffix}
							</p>
						{/if}
						<Field.FieldDescription class="text-xs">
							Joined to the LAN prefix; makes the device reachable by IPv6 pinholes.
						</Field.FieldDescription>
					</Field.Field>
				</Field.FieldGroup>

				{#if reserved}
					<div class="mt-auto border-t border-border pt-4">
						<Button
							type="button"
							variant="outline"
							size="sm"
							class="w-full border-danger/40 text-danger hover:bg-danger/10"
							disabled={submitting}
							onclick={removeReservation}
						>
							<Trash2Icon />Remove reservation
						</Button>
					</div>
				{/if}
			</div>

			<div class="flex items-center justify-end gap-2 border-t border-border p-4">
				<Button type="button" variant="outline" size="sm" onclick={() => (open = false)}>Cancel</Button>
				<Button type="submit" size="sm" disabled={submitting}>
					{#if submitting}
						<span class="mr-1 size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
					{/if}
					{reserved ? "Save changes" : "Reserve"}
				</Button>
			</div>
		</form>
	</Sheet.Content>
</Sheet.Root>
