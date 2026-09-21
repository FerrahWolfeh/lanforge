<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import PlusCircleIcon from "@lucide/svelte/icons/plus-circle";
	import { toast } from "svelte-sonner";
	import { hostAdd } from "$lib/api/client";
	import type { HostConfigEntry } from "$lib/api/types";

	let {
		open = $bindable(false),
		mac = "",
		hostname = "",
		v4 = "",
		v6Suffix = "",
		onPromoted = async () => {},
	}: {
		open?: boolean;
		mac?: string;
		hostname?: string;
		v4?: string;
		v6Suffix?: string;
		onPromoted?: () => Promise<void>;
	} = $props();

	let formMac = $state("");
	let formHostname = $state("");
	let formV4 = $state("");
	let formV6Suffix = $state("");
	let submitting = $state(false);

	$effect(() => {
		if (open) {
			formMac = mac;
			formHostname = hostname;
			formV4 = v4;
			formV6Suffix = v6Suffix;
		}
	});

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!formMac.trim()) {
			toast.error("MAC address is required to promote device");
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
			toast.success(`Promoted ${formMac} to static host rule!`);
			open = false;
			await onPromoted();
		} catch (err: any) {
			toast.error(err?.message || "Failed to promote device to static host");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<PlusCircleIcon class="size-5 text-amber-400" />
				<span>Promote to Static Host</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleSubmit} class="py-2">
			<Field.FieldGroup class="gap-4">
				<Field.Field>
					<Field.FieldLabel for="pmac">Target MAC Address</Field.FieldLabel>
					<Input
						id="pmac"
						class="font-mono text-xs {mac ? 'bg-muted/30' : ''}"
						placeholder="e.g. aa:bb:cc:dd:ee:ff"
						bind:value={formMac}
						readonly={Boolean(mac)}
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="phostname">Custom Hostname</Field.FieldLabel>
					<Input
						id="phostname"
						placeholder="e.g. main-workstation"
						class="text-xs"
						bind:value={formHostname}
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="pv4">Fixed IPv4 Address</Field.FieldLabel>
					<Input
						id="pv4"
						placeholder="e.g. 192.168.1.100"
						class="font-mono text-xs"
						bind:value={formV4}
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="pv6">IPv6 Suffix / Address</Field.FieldLabel>
					<Input
						id="pv6"
						placeholder="e.g. ::100 or ::1a2b:3c4d"
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
							<span
								class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
							></span>
						{/if}
						Create Static Rule
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>
