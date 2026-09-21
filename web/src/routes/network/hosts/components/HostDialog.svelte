<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Switch } from "$lib/components/ui/switch";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import DeviceCombobox from "$lib/components/DeviceCombobox.svelte";
	import { toast } from "svelte-sonner";
	import { hostAdd } from "$lib/api/client";
	import type { HostConfigEntry, DeviceEntry } from "$lib/api/types";
	import { z } from "zod";
	import { validateForm, macSchema, type FieldErrors } from "$lib/utils/validation";

	let {
		open = $bindable(false),
		isEditing = false,
		host = null,
		devices = [],
		onSaved = async () => {},
	}: {
		open?: boolean;
		isEditing?: boolean;
		host?: HostConfigEntry | null;
		devices?: DeviceEntry[];
		onSaved?: () => Promise<void>;
	} = $props();

	const hostFormSchema = z.object({
		mac: macSchema,
		hostname: z.string().trim().max(63, "Hostname cannot exceed 63 characters").optional().or(z.literal("")),
		v4: z.string().trim().ipv4("Invalid IPv4 address format (e.g. 192.168.1.10)").optional().or(z.literal("")),
		v6Suffix: z.string().trim().optional().or(z.literal("")),
	});

	let formMac = $state("");
	let formHostname = $state("");
	let formV4 = $state("");
	let formV6Suffix = $state("");
	let formIgnoreDnsLog = $state(false);
	let formIgnoredLogDomains = $state("");
	let submitting = $state(false);
	let fieldErrors = $state<FieldErrors<{ mac: string; hostname: string; v4: string; v6Suffix: string }>>({});

	$effect(() => {
		if (open) {
			fieldErrors = {};
			if (isEditing && host) {
				formMac = host.mac;
				formHostname = host.hostname || "";
				formV4 = host.v4_fixed || host.v4 || "";
				formV6Suffix = host.v6_suffix || "";
				formIgnoreDnsLog = host.ignore_dns_log ?? false;
				formIgnoredLogDomains = (host.ignored_log_domains || []).join(", ");
			} else {
				formMac = "";
				formHostname = "";
				formV4 = "";
				formV6Suffix = "";
				formIgnoreDnsLog = false;
				formIgnoredLogDomains = "";
			}
		}
	});

	function handleDeviceSelect(dev: DeviceEntry) {
		formMac = dev.mac;
		if (fieldErrors.mac) fieldErrors.mac = undefined;
		if (dev.hostname && dev.hostname !== "—" && !dev.hostname.startsWith("<")) {
			formHostname = dev.hostname;
		}
		const rawV4 = dev.v4?.ip || (dev.display_v4 && dev.display_v4 !== "—" ? dev.display_v4.replace(/\s*\?$/, "") : "");
		if (rawV4.trim()) {
			formV4 = rawV4.trim();
			if (fieldErrors.v4) fieldErrors.v4 = undefined;
		}
		const rawV6 = dev.v6?.ip || (dev.display_v6 && dev.display_v6 !== "—" ? dev.display_v6 : "");
		if (rawV6.trim()) formV6Suffix = rawV6.trim();
		if (dev.ignore_dns_log !== undefined) {
			formIgnoreDnsLog = dev.ignore_dns_log;
		}
		if (dev.ignored_log_domains && dev.ignored_log_domains.length > 0) {
			formIgnoredLogDomains = dev.ignored_log_domains.join(", ");
		}
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		fieldErrors = {};

		const validation = validateForm(hostFormSchema, {
			mac: formMac,
			hostname: formHostname,
			v4: formV4,
			v6Suffix: formV6Suffix,
		});

		if (!validation.success) {
			fieldErrors = validation.errors;
			toast.error("Please correct the invalid fields highlighted below");
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
				ignore_dns_log: formIgnoreDnsLog,
				ignored_log_domains: formIgnoredLogDomains
					.split(",")
					.map((s) => s.trim().toLowerCase())
					.filter(Boolean),
			};
			await hostAdd(entry);
			toast.success(
				isEditing
					? `Updated static host rule for ${entry.mac}`
					: `Added static host rule for ${entry.mac}`,
			);
			open = false;
			await onSaved();
		} catch (err: any) {
			toast.error(err?.message || "Failed to save static host rule");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				{#if isEditing}
					<PencilIcon class="size-5 text-amber-400" />
					<span>Edit Static Host Rule</span>
				{:else}
					<PlusIcon class="size-5 text-emerald-400" />
					<span>Add Static Host Rule</span>
				{/if}
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleSubmit} class="py-2">
			<Field.FieldGroup class="gap-4">
				<!-- Target MAC Address with Discovered LAN Autocomplete -->
				<Field.Field>
					<Field.FieldLabel for="mac">MAC Address *</Field.FieldLabel>
					<DeviceCombobox
						id="mac"
						bind:value={formMac}
						{devices}
						readonly={isEditing}
						placeholder="Search device or enter MAC (e.g. AA:BB:CC:DD:EE:FF)..."
						onselect={handleDeviceSelect}
					/>
					{#if fieldErrors.mac}
						<p class="text-[11px] text-destructive font-medium mt-1 flex items-center gap-1">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							{fieldErrors.mac}
						</p>
					{/if}
				</Field.Field>

				<!-- Hostname -->
				<Field.Field>
					<Field.FieldLabel for="hostname">Custom Hostname</Field.FieldLabel>
					<Input
						id="hostname"
						placeholder="e.g. raspberry-pi-4"
						class="text-xs"
						bind:value={formHostname}
						aria-invalid={Boolean(fieldErrors.hostname)}
						oninput={() => { if (fieldErrors.hostname) fieldErrors.hostname = undefined; }}
					/>
					{#if fieldErrors.hostname}
						<p class="text-[11px] text-destructive font-medium mt-1 flex items-center gap-1">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							{fieldErrors.hostname}
						</p>
					{/if}
					<Field.FieldDescription class="text-[11px]">
						Overrides reverse DNS and DHCP Option 12 host name for this device.
					</Field.FieldDescription>
				</Field.Field>

				<!-- Fixed IPv4 -->
				<Field.Field>
					<Field.FieldLabel for="v4">Fixed IPv4 Address</Field.FieldLabel>
					<Input
						id="v4"
						placeholder="e.g. 192.168.1.10"
						class="font-mono text-xs"
						bind:value={formV4}
						aria-invalid={Boolean(fieldErrors.v4)}
						oninput={() => { if (fieldErrors.v4) fieldErrors.v4 = undefined; }}
					/>
					{#if fieldErrors.v4}
						<p class="text-[11px] text-destructive font-medium mt-1 flex items-center gap-1">
							<AlertCircleIcon class="size-3.5 shrink-0" />
							{fieldErrors.v4}
						</p>
					{/if}
					<Field.FieldDescription class="text-[11px]">
						Reserved IPv4 address granted exclusively to this MAC via DHCP.
					</Field.FieldDescription>
				</Field.Field>

				<!-- IPv6 Suffix -->
				<Field.Field>
					<Field.FieldLabel for="v6">IPv6 Suffix / Address</Field.FieldLabel>
					<Input
						id="v6"
						placeholder="e.g. ::10 or ::cafe:babe"
						class="font-mono text-xs"
						bind:value={formV6Suffix}
					/>
					<Field.FieldDescription class="text-[11px]">
						Static IPv6 interface identifier appended to active router prefixes.
					</Field.FieldDescription>
				</Field.Field>

				<!-- DNS Log Suppression -->
				<div class="rounded-lg border p-3 bg-muted/20 space-y-3">
					<div class="flex items-center justify-between gap-2">
						<div class="space-y-0.5">
							<span class="text-xs font-medium text-foreground">Silence in DNS Query Logs</span>
							<p class="text-[11px] text-muted-foreground">
								Omit all DNS telemetry and log entries generated by this device.
							</p>
						</div>
						<Switch bind:checked={formIgnoreDnsLog} />
					</div>

					{#if !formIgnoreDnsLog}
						<Field.Field>
							<Field.FieldLabel for="ignored-domains">Muted Domains for this Device</Field.FieldLabel>
							<Input
								id="ignored-domains"
								placeholder="e.g. *.sonarr.tv, authelia.internal"
								class="font-mono text-xs"
								bind:value={formIgnoredLogDomains}
							/>
							<Field.FieldDescription class="text-[11px]">
								Comma-separated domains or wildcards (*.domain) to omit from logs exclusively when requested by this device.
							</Field.FieldDescription>
						</Field.Field>
					{/if}
				</div>

				<!-- Actions -->
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
						{isEditing ? "Save Changes" : "Create Host Rule"}
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>
