<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import { Label } from "$lib/components/ui/label";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import {
		leases,
		leaseRenew,
		leaseRelease,
		hostAdd,
		wol,
		eventsUrl,
	} from "$lib/api/client";
	import type { LeaseEntry, LeaseKind, LeaseTarget } from "$lib/api/types";

	// Icons
	import SearchIcon from "@lucide/svelte/icons/search";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import BookmarkPlusIcon from "@lucide/svelte/icons/bookmark-plus";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ActivityIcon from "@lucide/svelte/icons/activity";

	let allLeases = $state<LeaseEntry[]>([]);
	let loading = $state(true);
	let isRefreshing = $state(false);

	// Filters
	let searchQuery = $state("");
	let selectedKind = $state<"all" | "v4" | "v6" | "v6_prefix">("all");

	// Promote / Static Host Dialog
	let promoteOpen = $state(false);
	let promoteSubmitting = $state(false);
	let promoteMac = $state("");
	let promoteHostname = $state("");
	let promoteV4 = $state("");
	let promoteV6Suffix = $state("");

	// Release Confirmation Dialog
	let releaseConfirmOpen = $state(false);
	let targetToRelease = $state<LeaseEntry | null>(null);
	let releasing = $state(false);

	// EventSource
	let eventSource: EventSource | null = null;

	async function loadLeasesData(showSpinner = true) {
		if (showSpinner) loading = true;
		else isRefreshing = true;

		try {
			const res = await leases();
			allLeases = Array.isArray(res) ? res : [];
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to load DHCP leases");
		} finally {
			loading = false;
			isRefreshing = false;
		}
	}

	onMount(() => {
		loadLeasesData();

		// Real-time SSE listener
		try {
			const url = eventsUrl({ filter: "Dhcp" });
			eventSource = new EventSource(url);

			eventSource.onmessage = (e) => {
				try {
					const data = JSON.parse(e.data);
					const kind = data?.kind || data?.event || "";
					if (
						typeof kind === "string" &&
						(kind.includes("DhcpLeaseGranted") ||
							kind.includes("DhcpLeaseReleased") ||
							kind.includes("Device"))
					) {
						loadLeasesData(false);
					}
				} catch {
					// silent parse error
				}
			};

			eventSource.onerror = () => {
				// Reconnection is handled automatically by browser EventSource
			};
		} catch {
			// SSE unsupported or network error
		}
	});

	onDestroy(() => {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
	});

	// Derived statistics
	const totalCount = $derived(allLeases.length);
	const v4Count = $derived(allLeases.filter((l) => l.kind === "v4").length);
	const v6Count = $derived(
		allLeases.filter((l) => l.kind === "v6" || l.kind === "v6_prefix")
			.length,
	);
	const expiringSoonCount = $derived(
		allLeases.filter((l) => l.remaining_secs > 0 && l.remaining_secs < 3600)
			.length,
	);

	// Filtered leases
	const filteredLeases = $derived(
		allLeases.filter((lease) => {
			if (selectedKind !== "all" && lease.kind !== selectedKind) {
				return false;
			}
			if (!searchQuery.trim()) return true;
			const q = searchQuery.toLowerCase().trim();
			return (
				lease.hostname.toLowerCase().includes(q) ||
				lease.mac.toLowerCase().includes(q) ||
				lease.address.toLowerCase().includes(q)
			);
		}),
	);

	// Formatters
	function formatDuration(secs: number): string {
		if (secs <= 0) return "Expired";
		if (secs < 60) return `${secs}s`;
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		if (m < 60) return `${m}m ${s}s`;
		const h = Math.floor(m / 60);
		const remM = m % 60;
		if (h < 24) return `${h}h ${remM}m`;
		const d = Math.floor(h / 24);
		const remH = h % 24;
		return `${d}d ${remH}h`;
	}

	function formatExactDate(epochSecs: number): string {
		if (!epochSecs) return "Never";
		const date = new Date(epochSecs * 1000);
		return date.toLocaleString();
	}

	function copyToClipboard(text: string, label: string) {
		navigator.clipboard.writeText(text);
		toast.success(`Copied ${label} to clipboard`);
	}

	async function handleRenew(lease: LeaseEntry) {
		try {
			const target: LeaseTarget | undefined =
				lease.kind === "v4"
					? "V4"
					: lease.kind === "v6"
						? { V6: { iaid: 0 } }
						: { V6Prefix: { iaid: 0 } };
			await leaseRenew(lease.mac, target);
			toast.success(
				`Requested lease renewal for ${lease.hostname || lease.mac}`,
			);
			await loadLeasesData(false);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to request lease renewal");
		}
	}

	function promptRelease(lease: LeaseEntry) {
		targetToRelease = lease;
		releaseConfirmOpen = true;
	}

	async function confirmRelease() {
		if (!targetToRelease) return;
		releasing = true;
		try {
			const lease = targetToRelease;
			const target: LeaseTarget | undefined =
				lease.kind === "v4"
					? "V4"
					: lease.kind === "v6"
						? { V6: { iaid: 0 } }
						: { V6Prefix: { iaid: 0 } };
			await leaseRelease(lease.mac, target);
			toast.success(
				`Released DHCP lease for ${lease.hostname || lease.mac}`,
			);
			releaseConfirmOpen = false;
			targetToRelease = null;
			await loadLeasesData(false);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to release DHCP lease");
		} finally {
			releasing = false;
		}
	}

	async function handleWol(mac: string) {
		try {
			await wol(mac);
			toast.success(`Wake-on-LAN magic packet sent to ${mac}`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to send Wake-on-LAN");
		}
	}

	function openPromoteDialog(lease: LeaseEntry) {
		promoteMac = lease.mac;
		promoteHostname = lease.hostname !== "—" ? lease.hostname : "";
		promoteV4 = lease.kind === "v4" ? lease.address : "";
		promoteV6Suffix = "";
		promoteOpen = true;
	}

	async function handlePromoteSubmit(e: SubmitEvent) {
		e.preventDefault();
		if (!promoteMac) {
			toast.error("MAC address is required");
			return;
		}
		promoteSubmitting = true;
		try {
			await hostAdd({
				mac: promoteMac,
				hostname: promoteHostname.trim() || null,
				v4_fixed: promoteV4.trim() || null,
				v6_suffix: promoteV6Suffix.trim() || null,
			});
			toast.success(`Reserved static host mapping for ${promoteMac}`);
			promoteOpen = false;
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to create static host mapping");
		} finally {
			promoteSubmitting = false;
		}
	}
</script>

<div class="flex flex-col gap-6">
	<!-- Top KPI Stats Cards -->
	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Total Leases -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					Total Active Leases
				</Card.Title>
				<NetworkIcon class="h-4 w-4 text-muted-foreground" />
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="text-2xl font-bold">{totalCount}</div>
					<p class="text-xs text-muted-foreground mt-1">
						Dynamically assigned address bindings
					</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- IPv4 Leases -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					DHCPv4 Leases
				</Card.Title>
				<Badge
					variant="outline"
					class="font-mono text-xs text-blue-500 border-blue-500/30"
				>
					IPv4
				</Badge>
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="text-2xl font-bold">{v4Count}</div>
					<p class="text-xs text-muted-foreground mt-1">
						Standard RFC 2131 dynamic allocations
					</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- IPv6 Leases -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					DHCPv6 & Prefixes
				</Card.Title>
				<GlobeIcon class="h-4 w-4 text-muted-foreground" />
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="text-2xl font-bold">{v6Count}</div>
					<p class="text-xs text-muted-foreground mt-1">
						IA_NA non-temporary & IA_PD delegations
					</p>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Expiring Soon -->
		<Card.Root>
			<Card.Header
				class="flex flex-row items-center justify-between pb-2"
			>
				<Card.Title class="text-sm font-medium text-muted-foreground">
					Expiring Soon
				</Card.Title>
				<ClockIcon class="h-4 w-4 text-amber-500" />
			</Card.Header>
			<Card.Content>
				{#if loading}
					<Skeleton class="h-8 w-16" />
				{:else}
					<div class="flex items-center gap-2">
						<span class="text-2xl font-bold"
							>{expiringSoonCount}</span
						>
						{#if expiringSoonCount > 0}
							<Badge
								variant="secondary"
								class="bg-amber-500/10 text-amber-500 text-xs"
							>
								&lt; 1 hour
							</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground mt-1">
						Leases eligible for immediate renewal
					</p>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>

	<!-- Main Table Card -->
	<Card.Root>
		<Card.Header
			class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
		>
			<div>
				<Card.Title>Lease Directory</Card.Title>
				<Card.Description>
					Live view of all assigned client addresses, lifetime
					countdowns, and renewal actions.
				</Card.Description>
			</div>

			<!-- Action & Search Toolbar -->
			<div class="flex flex-wrap items-center gap-2">
				<!-- Search -->
				<div class="relative w-full sm:w-64">
					<SearchIcon
						class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground"
					/>
					<Input
						type="search"
						placeholder="Search hostname, IP, MAC..."
						class="pl-8"
						bind:value={searchQuery}
					/>
				</div>

				<!-- Protocol Selector -->
				<div
					class="flex items-center rounded-lg border bg-background p-1 text-xs"
				>
					<button
						class={[
							"rounded px-2.5 py-1 font-medium transition-colors",
							selectedKind === "all"
								? "bg-muted text-foreground"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedKind = "all")}
					>
						All ({totalCount})
					</button>
					<button
						class={[
							"rounded px-2.5 py-1 font-medium transition-colors",
							selectedKind === "v4"
								? "bg-muted text-foreground"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedKind = "v4")}
					>
						IPv4 ({v4Count})
					</button>
					<button
						class={[
							"rounded px-2.5 py-1 font-medium transition-colors",
							selectedKind === "v6"
								? "bg-muted text-foreground"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedKind = "v6")}
					>
						IPv6
					</button>
					<button
						class={[
							"rounded px-2.5 py-1 font-medium transition-colors",
							selectedKind === "v6_prefix"
								? "bg-muted text-foreground"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => (selectedKind = "v6_prefix")}
					>
						Prefixes
					</button>
				</div>

				<!-- Manual Refresh -->
				<Button
					variant="outline"
					size="icon"
					onclick={() => loadLeasesData(false)}
					disabled={loading || isRefreshing}
					title="Refresh leases"
				>
					<RefreshCwIcon
						class={[
							"h-4 w-4",
							isRefreshing ? "animate-spin" : "",
						].join(" ")}
					/>
				</Button>
			</div>
		</Card.Header>

		<Card.Content class="p-0">
			{#if loading}
				<div class="p-6 space-y-4">
					{#each Array(5) as _}
						<Skeleton class="h-12 w-full" />
					{/each}
				</div>
			{:else if filteredLeases.length === 0}
				<div class="py-12">
					<Empty.Root>
						<Empty.Media>
							<NetworkIcon
								class="h-10 w-10 text-muted-foreground/60"
							/>
						</Empty.Media>
						<Empty.Title>No leases found</Empty.Title>
						<Empty.Description>
							{#if searchQuery || selectedKind !== "all"}
								No active DHCP leases match your current search
								criteria or filter.
							{:else}
								No active dynamic DHCP leases have been granted
								by the server yet.
							{/if}
						</Empty.Description>
						{#if searchQuery || selectedKind !== "all"}
							<Empty.Content>
								<Button
									variant="outline"
									size="sm"
									onclick={() => {
										searchQuery = "";
										selectedKind = "all";
									}}
								>
									Clear filters
								</Button>
							</Empty.Content>
						{/if}
					</Empty.Root>
				</div>
			{:else}
				<!-- Scrollable Table Container -->
				<div class="max-h-[600px] overflow-auto">
					<Table.Root>
						<Table.Header
							class="sticky top-0 z-10 bg-muted/90 backdrop-blur"
						>
							<Table.Row class="hover:bg-transparent">
								<Table.Head>Client / Hostname</Table.Head>
								<Table.Head>MAC Address</Table.Head>
								<Table.Head>Assigned Address</Table.Head>
								<Table.Head class="w-[90px]">Type</Table.Head>
								<Table.Head class="w-[200px]"
									>Remaining Lifetime</Table.Head
								>
								<Table.Head class="w-[70px] text-right"
									>Actions</Table.Head
								>
							</Table.Row>
						</Table.Header>
						<Table.Body class="font-mono text-xs">
							{#each filteredLeases as lease (lease.mac + lease.address + lease.kind)}
								{@const isExpiring =
									lease.remaining_secs > 0 &&
									lease.remaining_secs < 3600}
								{@const isExpired = lease.remaining_secs <= 0}
								<Table.Row
									class="hover:bg-muted/50 transition-colors"
								>
									<!-- Hostname -->
									<Table.Cell class="font-sans">
										<div
											class="font-semibold text-foreground text-sm tracking-tight"
										>
											{lease.hostname || "—"}
										</div>
									</Table.Cell>

									<!-- MAC Address -->
									<Table.Cell>
										<div
											class="flex items-center gap-1.5 text-muted-foreground"
										>
											<span>{lease.mac}</span>
											<button
												class="text-muted-foreground hover:text-foreground transition-colors p-1"
												onclick={() =>
													copyToClipboard(
														lease.mac,
														"MAC address",
													)}
												title="Copy MAC"
											>
												<CopyIcon class="h-3 w-3" />
											</button>
										</div>
									</Table.Cell>

									<!-- Assigned IP -->
									<Table.Cell>
										<div class="flex items-center gap-1.5">
											<span
												class={[
													"font-medium",
													lease.kind === "v4"
														? "text-emerald-400"
														: "text-sky-400",
												].join(" ")}
											>
												{#if lease.kind === "v6_prefix"}
													{lease.address}/64
												{:else}
													{lease.address}
												{/if}
											</span>
											<button
												class="text-muted-foreground hover:text-foreground transition-colors p-1"
												onclick={() =>
													copyToClipboard(
														lease.address,
														"IP address",
													)}
												title="Copy IP"
											>
												<CopyIcon class="h-3 w-3" />
											</button>
										</div>
									</Table.Cell>

									<!-- Type Badge -->
									<Table.Cell class="font-sans">
										{#if lease.kind === "v4"}
											<Badge
												variant="outline"
												class="font-mono text-[10px] text-blue-500 border-blue-500/30"
											>
												IPv4
											</Badge>
										{:else if lease.kind === "v6"}
											<Badge
												variant="outline"
												class="font-mono text-[10px] text-purple-500 border-purple-500/30"
											>
												IPv6
											</Badge>
										{:else}
											<Badge
												variant="outline"
												class="font-mono text-[10px] text-emerald-500 border-emerald-500/30"
											>
												IA_PD
											</Badge>
										{/if}
									</Table.Cell>

									<!-- Remaining Lifetime with visual bar -->
									<Table.Cell class="font-sans">
										<Tooltip.Provider>
											<Tooltip.Root>
												<Tooltip.Trigger
													class="w-full text-left"
												>
													<div
														class="flex flex-col gap-1.5"
													>
														<div
															class="flex items-center justify-between text-xs"
														>
															<span
																class={[
																	"font-mono font-medium",
																	isExpired
																		? "text-destructive"
																		: isExpiring
																			? "text-amber-500"
																			: "text-foreground",
																].join(" ")}
															>
																{formatDuration(
																	lease.remaining_secs,
																)}
															</span>
															{#if isExpiring}
																<span
																	class="text-[10px] text-amber-500 font-semibold uppercase tracking-wider"
																>
																	Expiring
																</span>
															{/if}
														</div>

														<!-- Lifetime Bar -->
														<div
															class="h-1.5 w-full overflow-hidden rounded-full bg-muted"
														>
															<div
																class={[
																	"h-full transition-all duration-300",
																	isExpired
																		? "bg-destructive w-full"
																		: isExpiring
																			? "bg-amber-500 w-1/4"
																			: "bg-primary w-3/4",
																].join(" ")}
															></div>
														</div>
													</div>
												</Tooltip.Trigger>
												<Tooltip.Content side="top">
													<p class="text-xs">
														Expires at: <span
															class="font-mono font-medium"
															>{formatExactDate(
																lease.expires,
															)}</span
														>
													</p>
												</Tooltip.Content>
											</Tooltip.Root>
										</Tooltip.Provider>
									</Table.Cell>

									<!-- Actions Dropdown -->
									<Table.Cell class="text-right font-sans">
										<DropdownMenu.Root>
											<DropdownMenu.Trigger>
												{#snippet child({ props })}
													<Button
														{...props}
														variant="ghost"
														size="icon"
														class="h-8 w-8"
													>
														<MoreHorizontalIcon
															class="h-4 w-4"
														/>
													</Button>
												{/snippet}
											</DropdownMenu.Trigger>
											<DropdownMenu.Content align="end">
												<DropdownMenu.Item
													onclick={() =>
														handleRenew(lease)}
												>
													<RotateCcwIcon
														class="mr-2 h-4 w-4"
													/>
													Force Renew
												</DropdownMenu.Item>
												<DropdownMenu.Item
													onclick={() =>
														openPromoteDialog(
															lease,
														)}
												>
													<BookmarkPlusIcon
														class="mr-2 h-4 w-4 text-primary"
													/>
													Reserve Static Host
												</DropdownMenu.Item>
												<DropdownMenu.Item
													onclick={() =>
														handleWol(lease.mac)}
												>
													<ZapIcon
														class="mr-2 h-4 w-4 text-amber-500"
													/>
													Wake-on-LAN
												</DropdownMenu.Item>
												<DropdownMenu.Separator />
												<DropdownMenu.Item
													class="text-destructive focus:text-destructive"
													onclick={() =>
														promptRelease(lease)}
												>
													<Trash2Icon
														class="mr-2 h-4 w-4"
													/>
													Release Lease
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

<!-- Promote / Static Reservation Dialog -->
<Dialog.Root bind:open={promoteOpen}>
	<Dialog.Content class="sm:max-w-[440px]">
		<Dialog.Header>
			<Dialog.Title>Reserve Static Host</Dialog.Title>
			<Dialog.Description>
				Pin this device's MAC address to a fixed IP or hostname in
				Lanforge's static registry.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handlePromoteSubmit} class="space-y-4 py-2">
			<div class="space-y-1.5">
				<Label>MAC Address</Label>
				<Input
					bind:value={promoteMac}
					readonly
					class="font-mono bg-muted"
				/>
			</div>

			<div class="space-y-1.5">
				<Label>Hostname</Label>
				<Input
					placeholder="e.g. raspie, printer, workstation"
					bind:value={promoteHostname}
				/>
			</div>

			<div class="space-y-1.5">
				<Label>Fixed IPv4 Address</Label>
				<Input
					placeholder="e.g. 192.168.0.50"
					bind:value={promoteV4}
					class="font-mono"
				/>
			</div>

			<div class="space-y-1.5">
				<Label>Fixed IPv6 Suffix (optional)</Label>
				<Input
					placeholder="e.g. ::50 or ::cafe"
					bind:value={promoteV6Suffix}
					class="font-mono"
				/>
			</div>

			<Dialog.Footer class="gap-2 sm:gap-0 pt-4">
				<Button
					type="button"
					variant="outline"
					onclick={() => (promoteOpen = false)}
					disabled={promoteSubmitting}
				>
					Cancel
				</Button>
				<Button type="submit" disabled={promoteSubmitting}>
					{#if promoteSubmitting}
						<RefreshCwIcon class="mr-2 h-4 w-4 animate-spin" />
						Saving...
					{:else}
						Create Reservation
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>

<!-- Release Confirmation Dialog -->
<Dialog.Root bind:open={releaseConfirmOpen}>
	<Dialog.Content class="sm:max-w-[400px]">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2 text-destructive">
				<ShieldAlertIcon class="h-5 w-5" />
				Release DHCP Lease
			</Dialog.Title>
			<Dialog.Description>
				Are you sure you want to release the lease for
				<strong class="text-foreground"
					>{targetToRelease?.hostname || targetToRelease?.mac}</strong
				>
				({targetToRelease?.address})? The client will lose this address
				allocation upon expiry or next check.
			</Dialog.Description>
		</Dialog.Header>

		<Dialog.Footer class="gap-2 sm:gap-0 pt-4">
			<Button
				type="button"
				variant="outline"
				onclick={() => {
					releaseConfirmOpen = false;
					targetToRelease = null;
				}}
				disabled={releasing}
			>
				Cancel
			</Button>
			<Button
				variant="destructive"
				onclick={confirmRelease}
				disabled={releasing}
			>
				{#if releasing}
					<RefreshCwIcon class="mr-2 h-4 w-4 animate-spin" />
					Releasing...
				{:else}
					Confirm Release
				{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
