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
		listDevices,
		whois,
		purge,
		wol,
		scan,
		hostAdd,
	} from "$lib/api/client";
	import type { DeviceEntry, HostConfigEntry } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import SearchIcon from "@lucide/svelte/icons/search";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SendIcon from "@lucide/svelte/icons/send";
	import InfoIcon from "@lucide/svelte/icons/info";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import PlusCircleIcon from "@lucide/svelte/icons/plus-circle";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import CheckIcon from "@lucide/svelte/icons/check";

	let devices = $state<DeviceEntry[]>([]);
	let meta = $state<{ total: number; online: number } | null>(null);
	let loading = $state(true);
	let scanning = $state(false);

	let searchQuery = $state("");
	let statusFilter = $state<"all" | "online" | "offline">("all");

	// Details Modal State
	let selectedDevice = $state<DeviceEntry | null>(null);
	let whoisHistory = $state<any[]>([]);
	let detailsOpen = $state(false);
	let loadingDetails = $state(false);

	// Promote Modal State
	let promoteOpen = $state(false);
	let promoteSubmitting = $state(false);
	let promoteMac = $state("");
	let promoteHostname = $state("");
	let promoteV4 = $state("");
	let promoteV6Suffix = $state("");

	async function loadDevices() {
		loading = true;
		try {
			const res = await listDevices();
			devices = res.devices;
			meta = res.meta;
		} catch {
			toast.error("Failed to load network devices");
		} finally {
			loading = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await loadDevices();
			toast.success("Network devices refreshed");
		} catch {
			toast.error("Failed to refresh devices");
		} finally {
			scanning = false;
		}
	}

	async function handleWol(mac: string) {
		try {
			await wol(mac);
			toast.success(`Wake-on-LAN magic packet sent to ${mac}`);
		} catch {
			toast.error(`Failed to send Wake-on-LAN to ${mac}`);
		}
	}

	async function handlePurge(mac: string) {
		try {
			await purge(mac);
			toast.success(`Purged device record for ${mac}`);
			await loadDevices();
		} catch {
			toast.error(`Failed to purge device record for ${mac}`);
		}
	}

	async function openDetails(device: DeviceEntry) {
		selectedDevice = device;
		whoisHistory = [];
		detailsOpen = true;
		loadingDetails = true;
		try {
			const res = await whois(device.mac);
			if (res) {
				if (res.entry) {
					selectedDevice = res.entry;
				}
				if (Array.isArray(res.history)) {
					whoisHistory = res.history;
				}
			}
		} catch {
			// Fallback
		} finally {
			loadingDetails = false;
		}
	}

	function openPromoteModal(device: DeviceEntry) {
		promoteMac = device.mac;
		promoteHostname =
			device.hostname && device.hostname !== "—" && !device.hostname.startsWith("<")
				? device.hostname
				: "";
		const rawV4 =
			device.v4?.ip ||
			(device.display_v4 && device.display_v4 !== "—"
				? device.display_v4.replace(/\s*\?$/, "")
				: "");
		promoteV4 = rawV4.trim();
		const rawV6 =
			device.v6?.ip ||
			(device.display_v6 && device.display_v6 !== "—" ? device.display_v6 : "");
		promoteV6Suffix = rawV6.trim();
		promoteOpen = true;
	}

	async function handlePromoteSubmit(e: Event) {
		e.preventDefault();
		if (!promoteMac.trim()) {
			toast.error("MAC address is required");
			return;
		}

		promoteSubmitting = true;
		try {
			const entry: HostConfigEntry = {
				mac: promoteMac.trim(),
				hostname: promoteHostname.trim(),
				v4_fixed: promoteV4.trim() || undefined,
				v6_suffix: promoteV6Suffix.trim() || undefined,
				origin: "Static",
			};
			await hostAdd(entry);
			toast.success(`Promoted ${promoteMac} to static host rule!`);
			promoteOpen = false;
			await loadDevices();
		} catch (err: any) {
			toast.error(err?.message || "Failed to promote device to static host");
		} finally {
			promoteSubmitting = false;
		}
	}

	onMount(loadDevices);

	const filteredDevices = $derived.by(() => {
		let list = devices;
		if (statusFilter === "online") {
			list = list.filter((d) => d.online);
		} else if (statusFilter === "offline") {
			list = list.filter((d) => !d.online);
		}

		if (searchQuery.trim()) {
			const q = searchQuery.toLowerCase().trim();
			list = list.filter((d) => {
				const macMatch = d.mac?.toLowerCase().includes(q);
				const hostMatch = d.hostname?.toLowerCase().includes(q);
				const v4Match = (d.display_v4 || d.v4?.ip || "")
					.toLowerCase()
					.includes(q);
				const v6Match = (d.display_v6 || d.v6?.ip || "")
					.toLowerCase()
					.includes(q);
				return macMatch || hostMatch || v4Match || v6Match;
			});
		}

		return list;
	});

	function formatLastSeen(ts: string | number): string {
		if (!ts) return "—";
		let ms = typeof ts === "string" ? Date.parse(ts) : ts;
		if (isNaN(ms) || ms === 0) return "Never";
		if (ms < 10000000000) ms *= 1000;
		const secsAgo = Math.floor((Date.now() - ms) / 1000);
		if (secsAgo < 0 || secsAgo < 10) return "Just now";
		if (secsAgo < 60) return `${secsAgo}s ago`;
		const minsAgo = Math.floor(secsAgo / 60);
		if (minsAgo < 60) return `${minsAgo}m ago`;
		const hoursAgo = Math.floor(minsAgo / 60);
		if (hoursAgo < 24) return `${hoursAgo}h ago`;
		return `${Math.floor(hoursAgo / 24)}d ago`;
	}
</script>

<svelte:head>
	<title>Devices — Lanforge</title>
</svelte:head>

<Tooltip.Provider>
	<div class="flex flex-col gap-6">
		<!-- Page Header -->
		<div
			class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
		>
			<div>
				<h1 class="text-foreground text-2xl font-bold tracking-tight">
					Network Devices
				</h1>
				<p class="text-muted-foreground text-sm">
					Discovered LAN endpoints tracked via ARP, NDP, and DHCP
				</p>
			</div>
			<div class="flex items-center gap-2">
				<Button
					variant="outline"
					size="sm"
					onclick={loadDevices}
					disabled={loading}
				>
					<RefreshCwIcon
						data-icon="inline-start"
						class={loading ? "animate-spin" : ""}
					/>
					Refresh
				</Button>
				<Button size="sm" onclick={triggerScan} disabled={scanning}>
					{#if scanning}
						<span
							class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
							data-icon="inline-start"
						></span>
					{:else}
						<ZapIcon data-icon="inline-start" />
					{/if}
					Scan Network
				</Button>
			</div>
		</div>

		<!-- Controls & Filter Bar -->
		<Card.Root>
			<Card.Content
				class="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between"
			>
				<!-- Search input -->
				<div class="relative flex-1 max-w-sm">
					<SearchIcon
						class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2"
					/>
					<Input
						type="search"
						placeholder="Search hostname, MAC, or IP..."
						class="pl-9"
						bind:value={searchQuery}
					/>
				</div>

				<!-- Status Filter Pills -->
				<div class="flex items-center gap-3">
					<div
						class="flex items-center gap-1 rounded-lg border border-border/80 bg-muted/40 p-1"
					>
						<button
							class={[
								"rounded-md px-3 py-1 text-xs font-medium transition-colors",
								statusFilter === "all"
									? "bg-background text-foreground shadow-sm"
									: "text-muted-foreground hover:text-foreground",
							].join(" ")}
							onclick={() => (statusFilter = "all")}
						>
							All ({meta?.total ?? devices.length})
						</button>
						<button
							class={[
								"rounded-md px-3 py-1 text-xs font-medium transition-colors",
								statusFilter === "online"
									? "bg-background text-emerald-400 shadow-sm"
									: "text-muted-foreground hover:text-foreground",
							].join(" ")}
							onclick={() => (statusFilter = "online")}
						>
							Online ({meta?.online ??
								devices.filter((d) => d.online).length})
						</button>
						<button
							class={[
								"rounded-md px-3 py-1 text-xs font-medium transition-colors",
								statusFilter === "offline"
									? "bg-background text-rose-400 shadow-sm"
									: "text-muted-foreground hover:text-foreground",
							].join(" ")}
							onclick={() => (statusFilter = "offline")}
						>
							Offline
						</button>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Devices Table Card with Scroll Container -->
		<Card.Root class="overflow-hidden">
			<Card.Content class="p-0">
				{#if loading}
					<div class="flex flex-col gap-3 p-6">
						{#each { length: 5 } as _, i (i)}
							<div
								class="flex items-center justify-between gap-4"
							>
								<Skeleton class="h-5 w-32" />
								<Skeleton class="h-5 w-40" />
								<Skeleton class="h-5 w-24" />
								<Skeleton class="h-8 w-20 rounded-md" />
							</div>
						{/each}
					</div>
				{:else if filteredDevices.length === 0}
					<Empty.Root class="py-16">
						<Empty.Header>
							<Empty.Media>
								<WifiIcon
									class="size-8 text-muted-foreground/40"
								/>
							</Empty.Media>
							<Empty.Title>No Devices Found</Empty.Title>
							<Empty.Description>
								No devices matched your search or status filter
								criteria.
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
									<Table.Head class="w-[100px]"
										>Status</Table.Head
									>
									<Table.Head>Host / MAC</Table.Head>
									<Table.Head>IP Address</Table.Head>
									<Table.Head>Discovery Method</Table.Head>
									<Table.Head>Last Seen</Table.Head>
									<Table.Head class="text-right"
										>Actions</Table.Head
									>
								</Table.Row>
							</Table.Header>
							<Table.Body class="font-mono text-xs">
								{#each filteredDevices as dev (dev.mac)}
									<Table.Row>
										<!-- Status Dot -->
										<Table.Cell class="font-sans">
											<div
												class="flex items-center gap-2"
											>
												<span
													class={[
														"size-2 rounded-full shrink-0",
														dev.online
															? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
															: "bg-zinc-600",
													].join(" ")}
												></span>
												<span
													class="text-[11px] font-medium capitalize"
												>
													{dev.online
														? "Online"
														: "Offline"}
												</span>
											</div>
										</Table.Cell>

										<!-- Hostname & MAC -->
										<Table.Cell class="font-sans">
											<div class="flex flex-col">
												<span
													class="text-foreground text-sm font-semibold tracking-tight"
												>
													{dev.hostname ||
														"Unassigned Host"}
												</span>
												<span
													class="text-muted-foreground font-mono text-[11px]"
												>
													{dev.mac}
												</span>
											</div>
										</Table.Cell>

										<!-- IP Addresses -->
										<Table.Cell>
											<div class="flex flex-col gap-0.5">
												{#if dev.display_v4 || dev.v4?.ip}
													<span
														class="text-emerald-400 font-medium"
													>
														{dev.display_v4 ||
															dev.v4?.ip}
													</span>
												{/if}
												{#if dev.display_v6 || dev.v6?.ip}
													<span
														class="text-sky-400 text-[10px] truncate max-w-[220px]"
													>
														{dev.display_v6 ||
															dev.v6?.ip}
													</span>
												{/if}
												{#if !dev.display_v4 && !dev.v4?.ip && !dev.display_v6 && !dev.v6?.ip}
													<span
														class="text-muted-foreground font-sans text-xs"
														>—</span
													>
												{/if}
											</div>
										</Table.Cell>

										<!-- Method & Class -->
										<Table.Cell class="font-sans">
											<div
												class="flex items-center gap-1.5"
											>
												{#if dev.learning_method}
													<Badge
														variant="outline"
														class="text-[10px] uppercase font-mono px-2 py-0.5"
													>
														{dev.learning_method}
													</Badge>
												{/if}
												{#if dev.class}
													<Badge
														variant="secondary"
														class="text-[10px] capitalize px-2 py-0.5"
													>
														{dev.class}
													</Badge>
												{/if}
											</div>
										</Table.Cell>

										<!-- Last Seen -->
										<Table.Cell
											class="font-sans text-muted-foreground"
										>
											{formatLastSeen(dev.last_seen)}
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
															openDetails(dev)}
														class="gap-2"
													>
														<SearchIcon
															class="h-3.5 w-3.5 text-sky-400"
														/>
														Inspect Details (Whois)
													</DropdownMenu.Item>
													<DropdownMenu.Item
														onclick={() =>
															handleWol(dev.mac)}
														class="gap-2"
													>
														<ZapIcon
															class="h-3.5 w-3.5 text-emerald-400"
														/>
														Send Wake-on-LAN
													</DropdownMenu.Item>
													<DropdownMenu.Item
														onclick={() =>
															openPromoteModal(
																dev,
															)}
														class="gap-2"
													>
														<BookmarkIcon
															class="h-3.5 w-3.5 text-amber-400"
														/>
														Promote to Static Host
													</DropdownMenu.Item>
													<DropdownMenu.Separator />
													<DropdownMenu.Item
														onclick={() => {
															navigator.clipboard.writeText(
																dev.mac,
															);
															toast.success(
																`Copied MAC ${dev.mac}`,
															);
														}}
														class="gap-2"
													>
														<CopyIcon
															class="h-3.5 w-3.5 text-muted-foreground"
														/>
														Copy MAC Address
													</DropdownMenu.Item>
													{#if dev.display_v4 || dev.v4?.ip}
														<DropdownMenu.Item
															onclick={() => {
																const ip =
																	dev.display_v4 ||
																	dev.v4
																		?.ip ||
																	"";
																navigator.clipboard.writeText(
																	ip,
																);
																toast.success(
																	`Copied IP ${ip}`,
																);
															}}
															class="gap-2"
														>
															<CopyIcon
																class="h-3.5 w-3.5 text-muted-foreground"
															/>
															Copy IPv4 Address
														</DropdownMenu.Item>
													{/if}
													<DropdownMenu.Separator />
													<DropdownMenu.Item
														onclick={() =>
															handlePurge(
																dev.mac,
															)}
														class="gap-2 text-rose-500"
													>
														<Trash2Icon
															class="h-3.5 w-3.5"
														/>
														Purge Endpoint
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

<!-- Device Details Dialog -->
<Dialog.Root bind:open={detailsOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<MonitorIcon class="size-5 text-emerald-400" />
				<span>Device Details</span>
			</Dialog.Title>
		</Dialog.Header>

		{#if loadingDetails}
			<div class="flex flex-col gap-3 py-4">
				<Skeleton class="h-4 w-full" />
				<Skeleton class="h-4 w-3/4" />
				<Skeleton class="h-4 w-5/6" />
			</div>
		{:else if selectedDevice}
			<div class="flex flex-col gap-3 text-xs py-2">
				<div
					class="flex justify-between border-b border-border/50 pb-2"
				>
					<span class="text-muted-foreground font-medium"
						>Hostname</span
					>
					<span class="font-semibold text-foreground"
						>{selectedDevice.hostname || "Unassigned"}</span
					>
				</div>
				<div
					class="flex justify-between border-b border-border/50 pb-2"
				>
					<span class="text-muted-foreground font-medium"
						>MAC Address</span
					>
					<span class="font-mono text-foreground"
						>{selectedDevice.mac}</span
					>
				</div>
				<div
					class="flex justify-between border-b border-border/50 pb-2"
				>
					<span class="text-muted-foreground font-medium"
						>IPv4 Address</span
					>
					<span class="font-mono text-emerald-400"
						>{selectedDevice.display_v4 ||
							selectedDevice.v4?.ip ||
							"—"}</span
					>
				</div>
				<div
					class="flex justify-between border-b border-border/50 pb-2"
				>
					<span class="text-muted-foreground font-medium"
						>IPv6 Address</span
					>
					<span class="font-mono text-sky-400 truncate max-w-[200px]"
						>{selectedDevice.display_v6 ||
							selectedDevice.v6?.ip ||
							"—"}</span
					>
				</div>
				{#if selectedDevice.duid}
					<div
						class="flex justify-between border-b border-border/50 pb-2"
					>
						<span class="text-muted-foreground font-medium"
							>DHCPv6 DUID</span
						>
						<span
							class="font-mono text-foreground truncate max-w-[200px]"
							>{selectedDevice.duid}</span
						>
					</div>
				{/if}
				<div
					class="flex justify-between border-b border-border/50 pb-2"
				>
					<span class="text-muted-foreground font-medium"
						>Discovery Origin</span
					>
					<Badge variant="outline"
						>{selectedDevice.origin || "Dynamic"}</Badge
					>
				</div>
				<div class="flex justify-between">
					<span class="text-muted-foreground font-medium"
						>Last Reachable</span
					>
					<span>{formatLastSeen(selectedDevice.last_seen)}</span>
				</div>

				{#if whoisHistory.length > 0}
					<div
						class="flex flex-col gap-2 mt-2 pt-2 border-t border-border/60"
					>
						<span
							class="text-muted-foreground font-medium uppercase text-[10px] tracking-wider"
							>Lease History</span
						>
						<div
							class="flex flex-col gap-1 max-h-32 overflow-auto font-mono text-[11px]"
						>
							{#each whoisHistory as h (h.ts || h.ip)}
								<div
									class="flex justify-between text-muted-foreground"
								>
									<span>{h.ip}</span>
									<span
										>{formatLastSeen(
											h.ts || h.expires,
										)}</span
									>
								</div>
							{/each}
						</div>
					</div>
				{/if}
			</div>
		{/if}
	</Dialog.Content>
</Dialog.Root>

<!-- Promote to Static Host Modal -->
<Dialog.Root bind:open={promoteOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<PlusCircleIcon class="size-5 text-amber-400" />
				<span>Promote to Static Host</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handlePromoteSubmit} class="py-2">
			<Field.FieldGroup class="gap-4">
				<Field.Field>
					<Field.FieldLabel for="pmac"
						>Target MAC Address</Field.FieldLabel
					>
					<Input
						id="pmac"
						class="font-mono text-xs bg-muted/30"
						bind:value={promoteMac}
						readonly
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="phostname"
						>Custom Hostname</Field.FieldLabel
					>
					<Input
						id="phostname"
						placeholder="e.g. main-workstation"
						class="text-xs"
						bind:value={promoteHostname}
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="pv4"
						>Fixed IPv4 Address</Field.FieldLabel
					>
					<Input
						id="pv4"
						placeholder="e.g. 192.168.1.100"
						class="font-mono text-xs"
						bind:value={promoteV4}
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="pv6"
						>IPv6 Suffix / Address</Field.FieldLabel
					>
					<Input
						id="pv6"
						placeholder="e.g. ::100 or ::1a2b:3c4d"
						class="font-mono text-xs"
						bind:value={promoteV6Suffix}
					/>
				</Field.Field>

				<div class="flex items-center justify-end gap-2 mt-2">
					<Button
						type="button"
						variant="outline"
						size="sm"
						onclick={() => (promoteOpen = false)}
					>
						Cancel
					</Button>
					<Button
						type="submit"
						size="sm"
						disabled={promoteSubmitting}
					>
						{#if promoteSubmitting}
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
