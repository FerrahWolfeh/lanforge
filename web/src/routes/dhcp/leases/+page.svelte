<script lang="ts">
	import { leaseTarget } from "./lease-target";
	import { auth } from "$lib/stores/auth.svelte";
	import { Button } from "$lib/components/ui/button";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";
	import {
		leases,
		leaseRenew,
		wol,
		eventsUrl,
		openEventStream,
		type EventStream,
	} from "$lib/api/client";
	import type { LeaseEntry } from "$lib/api/types";
	import { createDebounce, errorMessage } from "$lib/utils";

	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
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

	// Real-time event stream
	let eventSource: EventStream | null = null;

	async function loadLeasesData(showSpinner = true) {
		if (showSpinner) loading = true;
		else isRefreshing = true;
		try {
			allLeases = await leases();
		} catch (err) {
			toast.error(errorMessage(err, "Failed to load DHCP leases"));
		} finally {
			loading = false;
			isRefreshing = false;
		}
	}

	async function handleRenew(lease: LeaseEntry) {
		try {
			await leaseRenew(lease.mac, leaseTarget(lease));
			toast.success(`Sent renewal trigger for ${lease.address}`);
			await loadLeasesData(false);
		} catch (err) {
			toast.error(errorMessage(err, "Failed to trigger lease renewal"));
		}
	}

	async function handleWol(mac: string) {
		try {
			await wol(mac);
			toast.success(`Wake-on-LAN packet sent to ${mac}`);
		} catch (err) {
			toast.error(errorMessage(err, "Failed to send WoL packet"));
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
			eventSource = openEventStream(url, {
				onmessage: (e) => {
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
				},
			});
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


	<!-- Main Leases Table -->
	<LeaseTable
		leases={allLeases}
		{loading}
		onRenew={handleRenew}
		onRelease={openRelease}
		onPromote={openPromote}
		onWol={handleWol}
		canEdit={auth.can("device_write")}
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
