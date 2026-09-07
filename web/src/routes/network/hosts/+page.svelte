<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import * as Field from "$lib/components/ui/field";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import {
		hostList,
		hostAdd,
		hostRemove,
		hostExport,
		hostImport,
		listDevices,
	} from "$lib/api/client";
	import type { HostConfigEntry, DeviceEntry } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import SearchIcon from "@lucide/svelte/icons/search";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import ServerIcon from "@lucide/svelte/icons/server";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import CheckIcon from "@lucide/svelte/icons/check";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import DeviceCombobox from "$lib/components/DeviceCombobox.svelte";

	let hosts = $state<HostConfigEntry[]>([]);
	let discoveredDevices = $state<DeviceEntry[]>([]);
	let loading = $state(true);
	let searchQuery = $state("");

	// Add/Edit Host Modal state
	let dialogOpen = $state(false);
	let isEditing = $state(false);
	let submitting = $state(false);

	let formMac = $state("");
	let formHostname = $state("");
	let formV4 = $state("");
	let formV6Suffix = $state("");

	onMount(loadHostsAndDevices);

	async function loadHostsAndDevices() {
		loading = true;
		try {
			const [hRes, dRes] = await Promise.allSettled([
				hostList(),
				listDevices(),
			]);
			if (hRes.status === "fulfilled") {
				hosts = hRes.value;
			}
			if (dRes.status === "fulfilled") {
				discoveredDevices = dRes.value.devices;
			}
		} catch {
			toast.error("Failed to load static host configurations");
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		formMac = "";
		formHostname = "";
		formV4 = "";
		formV6Suffix = "";
		isEditing = false;
	}

	function openAddModal() {
		resetForm();
		dialogOpen = true;
	}

	function openEditModal(host: HostConfigEntry) {
		resetForm();
		isEditing = true;
		formMac = host.mac;
		formHostname = host.hostname || "";
		formV4 = host.v4_fixed || host.v4 || "";
		formV6Suffix = host.v6_suffix || "";
		dialogOpen = true;
	}

	function selectDiscoveredDevice(dev: DeviceEntry) {
		formMac = dev.mac;
		if (dev.hostname && dev.hostname !== "—" && !dev.hostname.startsWith("<")) {
			formHostname = dev.hostname;
		}
		const rawV4 = dev.v4?.ip || (dev.display_v4 && dev.display_v4 !== "—" ? dev.display_v4.replace(/\s*\?$/, "") : "");
		if (rawV4.trim()) formV4 = rawV4.trim();
		const rawV6 = dev.v6?.ip || (dev.display_v6 && dev.display_v6 !== "—" ? dev.display_v6 : "");
		if (rawV6.trim()) formV6Suffix = rawV6.trim();
		toast.info(`Selected ${dev.hostname || dev.mac}`);
	}

	async function handleSaveHost(e: Event) {
		e.preventDefault();
		if (!formMac.trim()) {
			toast.error("MAC Address is required");
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
			toast.success(
				isEditing
					? `Updated static host rule for ${entry.mac}`
					: `Added static host rule for ${entry.mac}`,
			);
			dialogOpen = false;
			await loadHostsAndDevices();
		} catch (err: any) {
			toast.error(err?.message || "Failed to save static host rule");
		} finally {
			submitting = false;
		}
	}

	async function handleRemoveHost(mac: string) {
		try {
			await hostRemove(mac);
			toast.success(`Removed static host rule for ${mac}`);
			await loadHostsAndDevices();
		} catch {
			toast.error(`Failed to remove static host rule for ${mac}`);
		}
	}

	const filteredHosts = $derived.by(() => {
		if (!searchQuery.trim()) return hosts;
		const q = searchQuery.toLowerCase().trim();
		return hosts.filter((h) => {
			const macMatch = h.mac?.toLowerCase().includes(q);
			const hostMatch = h.hostname?.toLowerCase().includes(q);
			const v4Match = (h.v4_fixed || h.v4 || "")
				.toLowerCase()
				.includes(q);
			const v6Match = (h.v6_suffix || "").toLowerCase().includes(q);
			return macMatch || hostMatch || v4Match || v6Match;
		});
	});

	const matchingDiscoveredDevices = $derived.by(() => {
		if (!formMac.trim()) return discoveredDevices.slice(0, 5);
		const q = formMac.toLowerCase().trim();
		return discoveredDevices
			.filter(
				(d) =>
					d.mac.toLowerCase().includes(q) ||
					(d.hostname && d.hostname.toLowerCase().includes(q)) ||
					(d.display_v4 && d.display_v4.includes(q)),
			)
			.slice(0, 5);
	});
</script>

<svelte:head>
	<title>Static Hosts — Lanforge</title>
</svelte:head>

<Tooltip.Provider>
	<div class="flex flex-col gap-6">
		<!-- Page Header -->
		<div
			class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
		>
			<div>
				<h1 class="text-foreground text-2xl font-bold tracking-tight">
					Static Hosts
				</h1>
				<p class="text-muted-foreground text-sm">
					Fixed IP address assignments and custom DNS hostname
					overrides
				</p>
			</div>
			<div class="flex items-center gap-2">
				<Button
					variant="outline"
					size="sm"
					onclick={loadHostsAndDevices}
					disabled={loading}
				>
					<RefreshCwIcon
						data-icon="inline-start"
						class={loading ? "animate-spin" : ""}
					/>
					Refresh
				</Button>
				<Button size="sm" onclick={openAddModal}>
					<PlusIcon data-icon="inline-start" />
					Add Static Host
				</Button>
			</div>
		</div>

		<!-- Controls & Search Bar -->
		<Card.Root>
			<Card.Content
				class="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between"
			>
				<div class="relative flex-1 max-w-sm">
					<SearchIcon
						class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2"
					/>
					<Input
						type="search"
						placeholder="Search static hosts by MAC, name, or IP..."
						class="pl-9"
						bind:value={searchQuery}
					/>
				</div>

				<Badge
					variant="outline"
					class="font-mono text-xs self-start sm:self-auto"
				>
					{hosts.length} Configured Rule{hosts.length === 1
						? ""
						: "s"}
				</Badge>
			</Card.Content>
		</Card.Root>

		<!-- Static Hosts Table Card with Scroll Container & Sticky Header -->
		<Card.Root class="overflow-hidden">
			<Card.Content class="p-0">
				{#if loading}
					<div class="flex flex-col gap-3 p-6">
						{#each { length: 4 } as _, i (i)}
							<div
								class="flex items-center justify-between gap-4"
							>
								<Skeleton class="h-5 w-32" />
								<Skeleton class="h-5 w-40" />
								<Skeleton class="h-5 w-24" />
								<Skeleton class="h-8 w-16 rounded-md" />
							</div>
						{/each}
					</div>
				{:else if filteredHosts.length === 0}
					<Empty.Root class="py-16">
						<Empty.Header>
							<Empty.Media>
								<ServerIcon
									class="size-8 text-muted-foreground/40"
								/>
							</Empty.Media>
							<Empty.Title>No Static Hosts Configured</Empty.Title
							>
							<Empty.Description>
								Add a fixed IP binding or custom hostname
								override to get started.
							</Empty.Description>
						</Empty.Header>
					</Empty.Root>
				{:else}
					<!-- Scrollable Table Container -->
					<div class="max-h-[600px] overflow-auto">
						<Table.Root>
							<Table.Header
								class="sticky top-0 z-10 bg-muted/90 backdrop-blur"
							>
								<Table.Row class="hover:bg-transparent">
									<Table.Head>Hostname</Table.Head>
									<Table.Head>Target MAC</Table.Head>
									<Table.Head>Fixed IPv4</Table.Head>
									<Table.Head>IPv6 Suffix / Addr</Table.Head>
									<Table.Head>Origin</Table.Head>
									<Table.Head class="text-right"
										>Actions</Table.Head
									>
								</Table.Row>
							</Table.Header>
							<Table.Body class="font-mono text-xs">
								{#each filteredHosts as host (host.mac)}
									<Table.Row>
										<!-- Hostname -->
										<Table.Cell
											class="font-sans font-semibold text-foreground"
										>
											{host.hostname || "—"}
										</Table.Cell>

										<!-- MAC -->
										<Table.Cell
											class="text-muted-foreground"
										>
											{host.mac}
										</Table.Cell>

										<!-- Fixed IPv4 -->
										<Table.Cell
											class="text-emerald-400 font-medium"
										>
											{host.v4_fixed || host.v4 || "—"}
										</Table.Cell>

										<!-- IPv6 Suffix -->
										<Table.Cell class="text-sky-400">
											{host.v6_suffix || "—"}
										</Table.Cell>

										<!-- Origin -->
										<Table.Cell class="font-sans">
											<Badge
												variant="outline"
												class="text-[10px] uppercase font-mono"
											>
												{host.origin || "Config"}
											</Badge>
										</Table.Cell>

										<!-- Actions Dropdown Menu -->
										<Table.Cell
											class="text-right font-sans"
										>
											<DropdownMenu.Root>
												<DropdownMenu.Trigger
													class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
												>
													<MoreHorizontalIcon
														class="h-4 w-4"
													/>
												</DropdownMenu.Trigger>
												<DropdownMenu.Content
													align="end"
													class="w-48 text-xs"
												>
													<DropdownMenu.Item
														onclick={() =>
															openEditModal(host)}
														class="gap-2"
													>
														<PencilIcon
															class="h-3.5 w-3.5 text-amber-400"
														/>
														Edit Host Assignment
													</DropdownMenu.Item>
													<DropdownMenu.Separator />
													<DropdownMenu.Item
														onclick={() => {
															navigator.clipboard.writeText(
																host.mac,
															);
															toast.success(
																`Copied MAC ${host.mac}`,
															);
														}}
														class="gap-2"
													>
														<CopyIcon
															class="h-3.5 w-3.5 text-muted-foreground"
														/>
														Copy MAC Address
													</DropdownMenu.Item>
													{#if host.v4_fixed || host.v4}
														<DropdownMenu.Item
															onclick={() => {
																const ip =
																	host.v4_fixed ||
																	host.v4 ||
																	"";
																navigator.clipboard.writeText(
																	ip,
																);
																toast.success(
																	`Copied Fixed IPv4 ${ip}`,
																);
															}}
															class="gap-2"
														>
															<CopyIcon
																class="h-3.5 w-3.5 text-muted-foreground"
															/>
															Copy Fixed IPv4
														</DropdownMenu.Item>
													{/if}
													<DropdownMenu.Separator />
													<DropdownMenu.Item
														onclick={() =>
															handleRemoveHost(
																host.mac,
															)}
														class="gap-2 text-rose-500"
													>
														<Trash2Icon
															class="h-3.5 w-3.5"
														/>
														Delete Static Host
													</DropdownMenu.Item>
												</DropdownMenu.Content>
											</DropdownMenu.Root>
										</Table.Cell>
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
</Tooltip.Provider>

<!-- Add / Edit Static Host Modal -->
<Dialog.Root bind:open={dialogOpen}>
	<Dialog.Content class="sm:max-w-md">
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

		<form onsubmit={handleSaveHost} class="py-2">
			<Field.FieldGroup class="gap-4">
				<!-- Target MAC Address with Discovered LAN Autocomplete -->
				<Field.Field>
					<Field.FieldLabel for="mac">MAC Address *</Field.FieldLabel>
					<DeviceCombobox
						id="mac"
						bind:value={formMac}
						devices={discoveredDevices}
						readonly={isEditing}
						placeholder="Search device or enter MAC address (e.g. AA:BB:CC:DD:EE:FF)..."
						onselect={(dev) => selectDiscoveredDevice(dev)}
					/>
				</Field.Field>

				<!-- Hostname -->
				<Field.Field>
					<Field.FieldLabel for="hostname">Hostname</Field.FieldLabel>
					<Input
						id="hostname"
						placeholder="e.g. desktop-workstation"
						class="text-xs"
						bind:value={formHostname}
					/>
				</Field.Field>

				<!-- Fixed IPv4 -->
				<Field.Field>
					<Field.FieldLabel for="v4"
						>Fixed IPv4 Address</Field.FieldLabel
					>
					<Input
						id="v4"
						placeholder="e.g. 192.168.1.100"
						class="font-mono text-xs"
						bind:value={formV4}
					/>
				</Field.Field>

				<!-- IPv6 Suffix -->
				<Field.Field>
					<Field.FieldLabel for="v6"
						>IPv6 Suffix or Address</Field.FieldLabel
					>
					<Input
						id="v6"
						placeholder="e.g. ::100 or ::1a2b:3c4d"
						class="font-mono text-xs"
						bind:value={formV6Suffix}
					/>
				</Field.Field>

				<!-- Actions -->
				<div class="flex items-center justify-end gap-2 mt-2">
					<Button
						type="button"
						variant="outline"
						size="sm"
						onclick={() => (dialogOpen = false)}
					>
						Cancel
					</Button>
					<Button type="submit" size="sm" disabled={submitting}>
						{#if submitting}
							<span
								class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
							></span>
						{/if}
						{isEditing ? "Save Changes" : "Save Rule"}
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>
