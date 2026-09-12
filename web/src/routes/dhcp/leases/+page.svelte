<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import {
		leases,
		leaseRenew,
		wol,
		eventsUrl,
	} from "$lib/api/client";
	import type { LeaseEntry, LeaseTarget } from "$lib/api/types";

	import SearchIcon from "@lucide/svelte/icons/search";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	import LeaseStatsCards from "./components/LeaseStatsCards.svelte";
	import LeaseTable from "./components/LeaseTable.svelte";
	import LeasePromoteModal from "./components/LeasePromoteModal.svelte";
	import LeaseReleaseModal from "./components/LeaseReleaseModal.svelte";

	let allLeases = $state<LeaseEntry[]>([]);
	let loading = $state(true);
	let isRefreshing = $state(false);

	// Filters
	let searchQuery = $state("");
	let selectedKind = $state<"all" | "v4" | "v6" | "v6_prefix">("all");

	// Modals
	let promoteOpen = $state(false);
	let selectedLeaseForPromote = $state<LeaseEntry | null>(null);

	let releaseOpen = $state(false);
	let selectedLeaseForRelease = $state<LeaseEntry | null>(null);

	// Real-time EventSource
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

	async function handleRenew(lease: LeaseEntry) {
		try {
			const target: LeaseTarget = lease.kind === "v4" ? "V4" : { V6: { iaid: 0 } };
			await leaseRenew(lease.mac, target);
			toast.success(`Sent renewal trigger for ${lease.address}`);
			await loadLeasesData(false);
		} catch (err: any) {
			toast.error(err?.message || "Failed to trigger lease renewal");
		}
	}

	async function handleWol(mac: string) {
		try {
			await wol(mac);
			toast.success(`Wake-on-LAN packet sent to ${mac}`);
		} catch (err: any) {
			toast.error(err?.message || "Failed to send WoL packet");
		}
	}

	function openPromote(lease: LeaseEntry) {
		selectedLeaseForPromote = lease;
		promoteOpen = true;
	}

	function openRelease(lease: LeaseEntry) {
		selectedLeaseForRelease = lease;
		releaseOpen = true;
	}

	onMount(() => {
		loadLeasesData();

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
		} catch {
			// SSE unsupported
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
		allLeases.filter((l) => l.kind === "v6" || l.kind === "v6_prefix").length,
	);
	const expiringSoonCount = $derived(
		allLeases.filter((l) => l.remaining_secs > 0 && l.remaining_secs < 3600).length,
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
</script>

<svelte:head>
	<title>DHCP Leases — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Actions Toolbar -->
	<div class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
		<p class="text-muted-foreground text-xs sm:text-sm">
			Live dynamic IP lease tracking for IPv4 clients, DHCPv6, and prefix delegations.
		</p>
		<div class="flex items-center gap-2 shrink-0">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadLeasesData(false)}
				disabled={loading || isRefreshing}
				class="h-8 text-xs gap-1.5"
			>
				<RefreshCwIcon class="size-3.5 {isRefreshing ? 'animate-spin' : ''}" />
				<span>Refresh</span>
			</Button>
		</div>
	</div>

	<!-- Stats KPI Cards -->
	<LeaseStatsCards
		{loading}
		{totalCount}
		{v4Count}
		{v6Count}
		{expiringSoonCount}
	/>

	<!-- Filter & Search Toolbar -->
	<Card.Root>
		<Card.Content class="flex flex-col gap-3 p-3 sm:flex-row sm:items-center sm:justify-between">
			<!-- Search -->
			<div class="relative flex-1 max-w-sm">
				<SearchIcon class="absolute left-2.5 top-1/2 -translate-y-1/2 size-3.5 text-muted-foreground" />
				<Input
					type="search"
					placeholder="Search hostname, IP, MAC..."
					class="pl-8 text-xs h-8"
					bind:value={searchQuery}
				/>
			</div>

			<!-- Protocol Selector Pills -->
			<div class="flex items-center rounded-lg border border-border/80 bg-muted/40 p-1 text-xs">
				<button
					class={[
						"rounded px-2.5 py-1 font-medium transition-colors",
						selectedKind === "all"
							? "bg-background text-foreground shadow-sm"
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
							? "bg-background text-emerald-400 shadow-sm"
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
							? "bg-background text-sky-400 shadow-sm"
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
							? "bg-background text-purple-400 shadow-sm"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (selectedKind = "v6_prefix")}
				>
					Prefixes
				</button>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Main Leases Table / Mobile Cards -->
	<LeaseTable
		leases={filteredLeases}
		{loading}
		onRenew={handleRenew}
		onRelease={openRelease}
		onPromote={openPromote}
		onWol={handleWol}
	/>
</div>

<!-- Promotion & Release Dialogs -->
<LeasePromoteModal
	bind:open={promoteOpen}
	lease={selectedLeaseForPromote}
	onPromoted={() => loadLeasesData(false)}
/>

<LeaseReleaseModal
	bind:open={releaseOpen}
	lease={selectedLeaseForRelease}
	onReleased={() => loadLeasesData(false)}
/>
