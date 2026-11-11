<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Switch } from "$lib/components/ui/switch";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import { toast } from "svelte-sonner";
	import { dnsAdblockGroups, dnsAdblockDeviceSet } from "$lib/api/client";
	import type { AdblockClientEntry, DeviceEntry } from "$lib/api/types";

	/** The adblock groups and bypass of one device. */
	let {
		open = $bindable(false),
		device = null,
	}: {
		open?: boolean;
		device?: DeviceEntry | null;
	} = $props();

	let names = $state<string[]>([]);
	let member = $state<string[]>([]);
	/** Groups the device is in through a subnet: shown, not editable here. */
	let viaSubnet = $state<string[]>([]);
	let bypass = $state(false);
	let loading = $state(false);
	let submitting = $state(false);

	const deviceIn = (clients: AdblockClientEntry[], mac: string) =>
		clients.some((c) => c.devices.some((d) => d.mac.toLowerCase() === mac));

	async function load(dev: DeviceEntry) {
		loading = true;
		try {
			const res = await dnsAdblockGroups();
			const mac = dev.mac.toLowerCase();
			names = res.groups.map((g) => g.name);
			member = res.groups.filter((g) => deviceIn(g.clients, mac)).map((g) => g.name);
			viaSubnet = res.groups
				.filter((g) => !member.includes(g.name))
				.filter((g) => g.clients.some((c) => c.devices.length === 0 && !c.selector.startsWith("dev:")))
				.map((g) => g.name);
			bypass = deviceIn(res.bypass, mac);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to load adblock groups");
		} finally {
			loading = false;
		}
	}

	$effect(() => {
		if (open && device) load(device);
	});

	function toggle(name: string, on: boolean) {
		member = on ? [...member, name] : member.filter((m) => m !== name);
	}

	async function save() {
		if (!device) return;
		submitting = true;
		try {
			await dnsAdblockDeviceSet(device.mac, member, bypass);
			toast.success(`Adblock groups of ${device.hostname || device.mac} saved`);
			open = false;
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save the adblock groups");
		} finally {
			submitting = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<ShieldIcon class="size-5 text-primary" />
				<span>Adblock: {device?.hostname || device?.mac}</span>
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				The device gets the global layer plus its groups. It is added by name, so it stays in
				its groups when its MAC address changes.
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex flex-col gap-3 py-2 text-xs">
			{#if loading}
				<p class="text-muted-foreground">Loading...</p>
			{:else}
				{#if names.length === 0}
					<p class="text-muted-foreground">
						No adblock groups yet. Create one in DNS → Adblock → Groups.
					</p>
				{/if}
				{#each names as name (name)}
					<label class="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
						<span class="font-mono">{name}</span>
						<span class="flex items-center gap-2">
							{#if viaSubnet.includes(name)}
								<span class="text-[10px] text-muted-foreground">may also match by subnet</span>
							{/if}
							<Switch
								checked={member.includes(name)}
								disabled={bypass}
								onCheckedChange={(on) => toggle(name, on)}
							/>
						</span>
					</label>
				{/each}
				<label
					class="flex items-center justify-between gap-3 rounded-md border border-amber-500/30 bg-amber-500/5 px-3 py-2"
				>
					<span>
						<span class="font-medium">Bypass</span>
						<span class="block text-[11px] text-muted-foreground">Never filtered.</span>
					</span>
					<Switch bind:checked={bypass} />
				</label>
			{/if}
		</div>

		<div class="flex items-center justify-end gap-2">
			<Button type="button" variant="outline" size="sm" onclick={() => (open = false)}>
				Cancel
			</Button>
			<Button size="sm" disabled={submitting || loading || !device} onclick={save}>Save</Button>
		</div>
	</Dialog.Content>
</Dialog.Root>
