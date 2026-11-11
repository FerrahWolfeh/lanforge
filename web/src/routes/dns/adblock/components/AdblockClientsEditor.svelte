<script lang="ts">
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import DeviceCombobox from "$lib/components/DeviceCombobox.svelte";
	import XIcon from "@lucide/svelte/icons/x";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import type { AdblockClientEntry, DeviceEntry } from "$lib/api/types";
	import { adblockClientMacs, adblockClientNames } from "$lib/utils";

	/**
	 * Edits a list of adblock client selectors: a device (`dev:<name>`, or `dev:<mac>` when it
	 * has no name, so it keeps matching when an Android re-randomizes its MAC), an address or a
	 * subnet.
	 */
	let {
		clients = $bindable([]),
		known = [],
	}: {
		clients?: string[];
		/** What the daemon resolved for the saved selectors (device names to show). */
		known?: AdblockClientEntry[];
	} = $props();

	let deviceQuery = $state("");
	let address = $state("");

	function add(selector: string) {
		const s = selector.trim();
		if (s && !clients.includes(s)) clients = [...clients, s];
	}

	function addDevice(dev: DeviceEntry) {
		add(dev.hostname ? `dev:${dev.hostname.toLowerCase()}` : `dev:${dev.mac.toLowerCase()}`);
		deviceQuery = "";
	}

	function addAddress() {
		add(address);
		address = "";
	}

	function devicesOf(selector: string) {
		return known.find((k) => k.selector === selector)?.devices ?? [];
	}
</script>

<div class="flex flex-col gap-3">
	{#if clients.length === 0}
		<p class="text-xs text-muted-foreground">No clients yet.</p>
	{:else}
		<div class="flex flex-wrap gap-1.5">
			{#each clients as selector (selector)}
				<Badge
					variant="secondary"
					class="h-auto max-w-full gap-1 pr-1 font-mono text-[11px] whitespace-normal break-all"
					title={adblockClientMacs(devicesOf(selector))}
				>
					<span>{selector}</span>
					{#if devicesOf(selector).length > 0}
						<span class="font-sans text-muted-foreground">({adblockClientNames(devicesOf(selector))})</span>
					{/if}
					<button
						type="button"
						class="rounded p-0.5 hover:bg-muted-foreground/20"
						title="Remove {selector}"
						onclick={() => (clients = clients.filter((c) => c !== selector))}
					>
						<XIcon class="size-3" />
					</button>
				</Badge>
			{/each}
		</div>
	{/if}

	<DeviceCombobox
		bind:value={deviceQuery}
		placeholder="Add a device..."
		onselect={addDevice}
	/>

	<!-- Not a <form>: this editor sits inside the dialogs' forms. -->
	<div class="flex items-center gap-2">
		<Input
			class="h-8 font-mono text-xs"
			placeholder="or an address / subnet (e.g. 192.168.1.64/28)"
			bind:value={address}
			onkeydown={(e) => {
				if (e.key === "Enter") {
					e.preventDefault();
					addAddress();
				}
			}}
		/>
		<Button
			type="button"
			variant="outline"
			size="sm"
			class="h-8 gap-1 text-xs shrink-0"
			onclick={addAddress}
		>
			<PlusIcon class="size-3.5" />
			Add
		</Button>
	</div>
</div>
