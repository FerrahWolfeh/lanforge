<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import {
		leases,
		leaseRenew,
		wol,
		eventsUrl,
	} from "$lib/api/client";
	import type { LeaseEntry, LeaseTarget } from "$lib/api/types";
	import { createDebounce } from "$lib/utils";

	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	import LeaseStatsCards from "./components/LeaseStatsCards.svelte";
	import LeaseTable from "./components/LeaseTable.svelte";
	import LeasePromoteModal from "./components/LeasePromoteModal.svelte";
	import LeaseReleaseModal from "./components/LeaseReleaseModal.svelte";

	let allLeases = $state<LeaseEntry[]>([]);
	let loading = $state(true);
	let isRefreshing = $state(false);

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
			allLeases = await leases();
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

	const debouncedLoad = createDebounce(() => {
		loadLeasesData(false);
	}, 300);

	onMount(() => {
		loadLeasesData();

		try {
			const url = eventsUrl({ filter: "Dhcp" });
			eventSource = new EventSource(url);

			eventSource.onmessage = (e) => {
				try {
					const data = JSON.parse(e.data);
					const kindStr = typeof data?.kind === "string" ? data.kind : "";
					const eventObj = data?.event;
					const isLeaseOrDevice =
						kindStr.includes("Dhcp") ||
						kindStr.includes("Lease") ||
						kindStr.includes("Device") ||
						Boolean(
							eventObj?.Network?.DhcpLeaseGranted ||
								eventObj?.Network?.DhcpLeaseReleased ||
								eventObj?.Device?.LeaseRelease ||
								eventObj?.Device?.LeaseRenew ||
								eventObj?.Device?.DhcpV4Transaction ||
								eventObj?.Device?.DhcpV6Transaction ||
								eventObj?.Device?.NetworkUpdate ||
								eventObj?.Device?.Discovered
						);
					if (isLeaseOrDevice) {
						debouncedLoad();
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
		debouncedLoad.cancel();
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

	<!-- Main Leases Table -->
	<LeaseTable
		leases={allLeases}
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
