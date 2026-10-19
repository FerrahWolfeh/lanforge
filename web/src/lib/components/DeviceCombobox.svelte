<script lang="ts">
	import { Input } from "$lib/components/ui/input";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import CheckIcon from "@lucide/svelte/icons/check";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import { listDevices } from "$lib/api/client";
	import type { DeviceEntry } from "$lib/api/types";
	import { onMount, onDestroy } from "svelte";

	let {
		value = $bindable(""),
		placeholder = "Search or select a LAN device...",
		id = "",
		class: className = "",
		readonly = false,
		disabled = false,
		devices: providedDevices = null,
		onselect = null,
	}: {
		value: string;
		placeholder?: string;
		id?: string;
		class?: string;
		readonly?: boolean;
		disabled?: boolean;
		devices?: DeviceEntry[] | null;
		onselect?: ((dev: DeviceEntry) => void) | null;
	} = $props();

	let loadedDevices = $state<DeviceEntry[]>([]);
	let open = $state(false);
	let popoverContainer = $state<HTMLDivElement | null>(null);

	const activeDevices = $derived(providedDevices ?? loadedDevices);

	async function fetchDevicesIfNeeded() {
		if (providedDevices !== null) return;
		try {
			const res = await listDevices();
			if (res && res.devices) {
				loadedDevices = res.devices;
			}
		} catch {
			// silent fallback
		}
	}

	const matchingDevices = $derived.by(() => {
		if (!activeDevices || activeDevices.length === 0) return [];
		const q = value.trim().toLowerCase();
		if (!q) return activeDevices.slice(0, 8);

		return activeDevices
			.filter(
				(d) =>
					(d.hostname && d.hostname.toLowerCase().includes(q)) ||
					(d.mac && d.mac.toLowerCase().includes(q)) ||
					(d.primary_v4 && d.primary_v4.toLowerCase().includes(q)) ||
					(d.v4?.ip && d.v4.ip.toLowerCase().includes(q)) ||
					(d.primary_v6 && d.primary_v6.toLowerCase().includes(q)),
			)
			.slice(0, 8);
	});

	function handleSelect(dev: DeviceEntry) {
		const targetId = dev.hostname || dev.mac;
		value = targetId;
		open = false;
		if (onselect) {
			onselect(dev);
		}
	}

	function handleWindowClick(e: MouseEvent) {
		if (!open) return;
		if (popoverContainer && !popoverContainer.contains(e.target as Node)) {
			open = false;
		}
	}

	function handleKeyDown(e: KeyboardEvent) {
		if (e.key === "Escape") {
			open = false;
		}
	}

	onMount(() => {
		fetchDevicesIfNeeded();
		if (typeof window !== "undefined") {
			window.addEventListener("click", handleWindowClick);
			window.addEventListener("keydown", handleKeyDown);
		}
	});

	onDestroy(() => {
		if (typeof window !== "undefined") {
			window.removeEventListener("click", handleWindowClick);
			window.removeEventListener("keydown", handleKeyDown);
		}
	});
</script>

<div class="relative w-full" bind:this={popoverContainer}>
	<div class="relative">
		<Input
			{id}
			type="text"
			{placeholder}
			{readonly}
			{disabled}
			class={["h-9 text-xs font-mono pr-8", className].join(" ")}
			bind:value
			onfocus={() => {
				fetchDevicesIfNeeded();
				if (!readonly && !disabled) open = true;
			}}
			oninput={() => {
				if (!readonly && !disabled) open = true;
			}}
		/>
		<div
			class="absolute right-2.5 top-2.5 text-muted-foreground pointer-events-none"
		>
			<LaptopIcon class="h-4 w-4" />
		</div>
	</div>

	<!-- Autocomplete Suggestions Popover -->
	{#if open && !readonly && !disabled && matchingDevices.length > 0}
		<div
			class="absolute top-full left-0 right-0 z-50 mt-1 flex flex-col rounded-lg border border-border bg-card p-1 shadow-xl max-h-52 overflow-y-auto text-xs"
		>
			<div
				class="flex items-center justify-between px-2.5 py-1 text-[10px] uppercase tracking-wider text-muted-foreground font-semibold border-b border-border/40"
			>
				<span>Discovered LAN Devices</span>
				<span class="flex items-center gap-1 font-mono text-[10px]">
					<WifiIcon class="h-3 w-3 text-emerald-400" />
					{activeDevices.length} available
				</span>
			</div>

			{#each matchingDevices as dev (dev.mac)}
				{@const targetId = dev.hostname || dev.mac}
				{@const isSelected =
					value.toLowerCase() === targetId.toLowerCase() ||
					value.toLowerCase() === dev.mac.toLowerCase()}
				<button
					type="button"
					class="flex items-center justify-between gap-2 px-2.5 py-1.5 text-left rounded-md hover:bg-muted/70 transition-colors font-mono"
					onclick={() => handleSelect(dev)}
				>
					<div class="flex flex-col min-w-0">
						<span
							class="font-sans font-semibold text-foreground truncate"
						>
							{dev.hostname || "Unassigned Device"}
						</span>
						<span class="text-muted-foreground text-[10px]">
							{dev.mac}
						</span>
					</div>
					<div class="flex items-center gap-2 shrink-0">
						{#if dev.primary_v4 || dev.v4?.ip}
							<span
								class="text-emerald-500 font-mono text-[11px]"
							>
								{dev.primary_v4 || dev.v4?.ip}
							</span>
						{/if}
						{#if dev.primary_v6}
							<span
								class="text-purple-400 font-mono text-[10px] hidden sm:inline max-w-[130px] truncate"
								title={dev.primary_v6}
							>
								{dev.primary_v6}
							</span>
						{/if}
						{#if isSelected}
							<CheckIcon class="h-3.5 w-3.5 text-emerald-500" />
						{/if}
					</div>
				</button>
			{/each}
		</div>
	{/if}
</div>
