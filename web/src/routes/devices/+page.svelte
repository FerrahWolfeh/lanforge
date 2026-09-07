<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { listDevices, whois, purge, wol, scan } from "$lib/api/client";
	import type { DeviceEntry, DevicesResponse } from "$lib/api/types";
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

	let devices = $state<DeviceEntry[]>([]);
	let meta = $state<{ total: number; online: number } | null>(null);
	let loading = $state(true);
	let scanning = $state(false);

	let searchQuery = $state("");
	let statusFilter = $state<"all" | "online" | "offline">("all");

	// Details Modal
	let selectedDevice = $state<DeviceEntry | null>(null);
	let detailsOpen = $state(false);
	let loadingDetails = $state(false);

	async function loadDevices() {
		loading = true;
		try {
			const res: DevicesResponse = await listDevices();
			devices = Array.isArray(res.devices) ? res.devices : [];
			meta = res.meta ?? { total: devices.length, online: devices.filter(d => d.online).length };
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
			toast.error("Failed to refresh network devices");
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
			toast.success(`Purged device ${mac}`);
			await loadDevices();
		} catch {
			toast.error(`Failed to purge device ${mac}`);
		}
	}

	async function openDetails(device: DeviceEntry) {
		selectedDevice = device;
		detailsOpen = true;
		loadingDetails = true;
		try {
			const res = await whois(device.mac);
			if (res && res.entry) {
				selectedDevice = res.entry;
			}
		} catch {
			// Fallback to existing record info if whois fails
		} finally {
			loadingDetails = false;
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
				const v4Match = (d.display_v4 || d.v4?.ip || "").toLowerCase().includes(q);
				const v6Match = (d.display_v6 || d.v6?.ip || "").toLowerCase().includes(q);
				return macMatch || hostMatch || v4Match || v6Match;
			});
		}

		return list;
	});

	function formatLastSeen(ts: string | number): string {
		if (!ts) return "—";
		const ms = typeof ts === "string" ? Date.parse(ts) : ts;
		if (isNaN(ms)) return String(ts);
		const secsAgo = Math.floor((Date.now() - ms) / 1000);
		if (secsAgo < 10) return "Just now";
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

<div class="flex flex-col gap-6">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
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
		<Card.Content class="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
			<!-- Search input -->
			<div class="relative flex-1 max-w-sm">
				<SearchIcon class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2" />
				<Input
					type="search"
					placeholder="Search hostname, MAC, or IP..."
					class="pl-9"
					bind:value={searchQuery}
				/>
			</div>

			<!-- Status Filter Pills & Counter -->
			<div class="flex items-center gap-3">
				<div class="flex items-center gap-1 rounded-lg border border-border/80 bg-muted/40 p-1">
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
						Online ({meta?.online ?? devices.filter((d) => d.online).length})
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

	<!-- Devices Table Card -->
	<Card.Root class="overflow-hidden">
		<Card.Content class="p-0">
			{#if loading}
				<div class="flex flex-col gap-3 p-6">
					{#each { length: 5 } as _, i (i)}
						<div class="flex items-center justify-between gap-4">
							<Skeleton class="h-5 w-32" />
							<Skeleton class="h-5 w-40" />
							<Skeleton class="h-5 w-24" />
							<Skeleton class="h-8 w-20 rounded-md" />
						</div>
					{/each}
				</div>
			{:else if filteredDevices.length === 0}
				<div class="text-muted-foreground flex flex-col items-center justify-center gap-2 py-16 text-sm">
					<WifiIcon class="size-8 opacity-30" />
					<span>No devices found matching criteria</span>
				</div>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full text-left text-xs border-collapse">
						<thead>
							<tr class="border-b border-border/60 bg-muted/30 text-muted-foreground font-semibold uppercase tracking-wider text-[10px]">
								<th class="py-3 px-4">Status</th>
								<th class="py-3 px-4">Host / MAC</th>
								<th class="py-3 px-4">IP Address</th>
								<th class="py-3 px-4">Discovery Method</th>
								<th class="py-3 px-4">Last Seen</th>
								<th class="py-3 px-4 text-right">Actions</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-border/40 font-mono">
							{#each filteredDevices as dev (dev.mac)}
								<tr class="transition-colors hover:bg-muted/30">
									<!-- Status Dot -->
									<td class="py-3.5 px-4 font-sans">
										<div class="flex items-center gap-2">
											<span
												class={[
													"size-2 rounded-full shrink-0",
													dev.online
														? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
														: "bg-zinc-600",
												].join(" ")}
											></span>
											<span class="text-[11px] font-medium capitalize">
												{dev.online ? "Online" : "Offline"}
											</span>
										</div>
									</td>

									<!-- Hostname & MAC -->
									<td class="py-3.5 px-4 font-sans">
										<div class="flex flex-col">
											<span class="text-foreground text-sm font-semibold tracking-tight">
												{dev.hostname || "Unassigned Host"}
											</span>
											<span class="text-muted-foreground font-mono text-[11px]">
												{dev.mac}
											</span>
										</div>
									</td>

									<!-- IP Addresses -->
									<td class="py-3.5 px-4">
										<div class="flex flex-col gap-0.5">
											{#if dev.display_v4 || dev.v4?.ip}
												<span class="text-emerald-400 font-medium">
													{dev.display_v4 || dev.v4?.ip}
												</span>
											{/if}
											{#if dev.display_v6 || dev.v6?.ip}
												<span class="text-sky-400 text-[10px] truncate max-w-[220px]">
													{dev.display_v6 || dev.v6?.ip}
												</span>
											{/if}
											{#if !dev.display_v4 && !dev.v4?.ip && !dev.display_v6 && !dev.v6?.ip}
												<span class="text-muted-foreground font-sans text-xs">—</span>
											{/if}
										</div>
									</td>

									<!-- Method & Class -->
									<td class="py-3.5 px-4 font-sans">
										<div class="flex items-center gap-1.5">
											{#if dev.learning_method}
												<Badge variant="outline" class="text-[10px] uppercase font-mono px-2 py-0.5">
													{dev.learning_method}
												</Badge>
											{/if}
											{#if dev.class}
												<Badge variant="secondary" class="text-[10px] capitalize px-2 py-0.5">
													{dev.class}
												</Badge>
											{/if}
										</div>
									</td>

									<!-- Last Seen -->
									<td class="py-3.5 px-4 font-sans text-muted-foreground">
										{formatLastSeen(dev.last_seen)}
									</td>

									<!-- Actions -->
									<td class="py-3.5 px-4 text-right font-sans">
										<div class="flex items-center justify-end gap-1">
											<Button
												variant="ghost"
												size="icon-sm"
												title="View Details (Whois)"
												onclick={() => openDetails(dev)}
											>
												<InfoIcon class="size-4 text-sky-400" />
											</Button>
											<Button
												variant="ghost"
												size="icon-sm"
												title="Send Wake-on-LAN"
												onclick={() => handleWol(dev.mac)}
											>
												<SendIcon class="size-4 text-amber-400" />
											</Button>
											<Button
												variant="ghost"
												size="icon-sm"
												title="Purging device"
												onclick={() => handlePurge(dev.mac)}
											>
												<Trash2Icon class="size-4 text-rose-400" />
											</Button>
										</div>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>

<!-- Device Details Dialog -->
<Dialog.Root bind:open={detailsOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<MonitorIcon class="size-5 text-emerald-400" />
				<span>Device Details</span>
			</Dialog.Title>
		</Dialog.Header>

		{#if selectedDevice}
			<div class="flex flex-col gap-3 text-xs py-2">
				<div class="flex justify-between border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">Hostname</span>
					<span class="font-semibold text-foreground">{selectedDevice.hostname || "Unassigned"}</span>
				</div>
				<div class="flex justify-between border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">MAC Address</span>
					<span class="font-mono text-foreground">{selectedDevice.mac}</span>
				</div>
				<div class="flex justify-between border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">IPv4 Address</span>
					<span class="font-mono text-emerald-400">{selectedDevice.display_v4 || selectedDevice.v4?.ip || "—"}</span>
				</div>
				<div class="flex justify-between border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">IPv6 Address</span>
					<span class="font-mono text-sky-400 truncate max-w-[200px]">{selectedDevice.display_v6 || selectedDevice.v6?.ip || "—"}</span>
				</div>
				{#if selectedDevice.duid}
					<div class="flex justify-between border-b border-border/50 pb-2">
						<span class="text-muted-foreground font-medium">DHCPv6 DUID</span>
						<span class="font-mono text-foreground truncate max-w-[200px]">{selectedDevice.duid}</span>
					</div>
				{/if}
				<div class="flex justify-between border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">Discovery Origin</span>
					<Badge variant="outline">{selectedDevice.origin || "Dynamic"}</Badge>
				</div>
				<div class="flex justify-between">
					<span class="text-muted-foreground font-medium">Last Reachable</span>
					<span>{formatLastSeen(selectedDevice.last_seen)}</span>
				</div>
			</div>
		{/if}
	</Dialog.Content>
</Dialog.Root>
