<script lang="ts">
	import { onMount, onDestroy } from "svelte";
	import { toast } from "svelte-sonner";
	import {
		listDevices,
		whois,
		purge,
		wol,
		scan,
		eventsUrl,
	} from "$lib/api/client";
	import type { DeviceEntry } from "$lib/api/types";

	import DeviceTable from "./components/DeviceTable.svelte";
	import DeviceWhoisModal from "./components/DeviceWhoisModal.svelte";
	import DevicePromoteModal from "./components/DevicePromoteModal.svelte";

	let devices = $state<DeviceEntry[]>([]);
	let meta = $state<{ total: number; online: number } | null>(null);
	let loading = $state(true);
	let scanning = $state(false);

	// Details Modal State
	let selectedDevice = $state<DeviceEntry | null>(null);
	let whoisHistory = $state<any[]>([]);
	let detailsOpen = $state(false);
	let loadingDetails = $state(false);

	// Promote Modal State
	let promoteOpen = $state(false);
	let promoteMac = $state("");
	let promoteHostname = $state("");
	let promoteV4 = $state("");
	let promoteV6Suffix = $state("");
	let eventSource: EventSource | null = null;

	async function loadDevices(showSpinner = true) {
		if (showSpinner) loading = true;
		try {
			const res = await listDevices();
			devices = res.devices;
			meta = res.meta;
		} catch (err: any) {
			if (showSpinner) {
				toast.error(err?.message || "Failed to load devices");
			}
		} finally {
			if (showSpinner) loading = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await scan();
			await loadDevices();
			toast.success("Network devices refreshed");
		} catch (err: any) {
			toast.error(err?.message || "Failed to refresh devices");
		} finally {
			scanning = false;
		}
	}

	async function handleWol(mac: string) {
		try {
			await wol(mac);
			toast.success(`Wake-on-LAN packet transmitted to ${mac}`);
		} catch (err: any) {
			toast.error(err?.message || "Failed to transmit WoL magic packet");
		}
	}

	async function handlePurge(mac: string) {
		if (!confirm(`Purge device ${mac} from cache and dynamic memory?`)) return;
		try {
			await purge(mac);
			toast.success(`Device ${mac} purged successfully`);
			await loadDevices();
		} catch (err: any) {
			toast.error(err?.message || "Failed to purge device");
		}
	}

	async function openDetails(device: DeviceEntry) {
		selectedDevice = device;
		detailsOpen = true;
		loadingDetails = true;
		whoisHistory = [];
		try {
			const res = await whois(device.mac);
			whoisHistory = res?.history || [];
		} catch {
			whoisHistory = [];
		} finally {
			loadingDetails = false;
		}
	}

	function openPromoteModal(device: DeviceEntry) {
		promoteMac = device.mac;
		promoteHostname = device.hostname || "";
		promoteV4 = device.display_v4 || device.v4?.ip || "";
		promoteV6Suffix = device.display_v6 || device.v6?.ip || "";
		promoteOpen = true;
	}

	onMount(() => {
		loadDevices();

		try {
			const url = eventsUrl();
			eventSource = new EventSource(url);

			eventSource.onmessage = (e) => {
				try {
					const data = JSON.parse(e.data);
					const kindStr = typeof data?.kind === "string" ? data.kind : "";
					const eventObj = data?.event;
					const isDeviceUpdate =
						kindStr.includes("Device") ||
						kindStr.includes("Scan") ||
						kindStr.includes("Neighbor") ||
						kindStr.includes("Dhcp") ||
						Boolean(
							eventObj?.Device ||
								eventObj?.Network ||
								eventObj?.System?.ConfigDhcpV4Changed ||
								eventObj?.System?.ConfigDhcpV6Changed
						);
					if (isDeviceUpdate) {
						loadDevices(false);
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

</script>

<svelte:head>
	<title>Devices — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Description -->
	<p class="text-muted-foreground text-xs sm:text-sm">
		Discovered LAN endpoints tracked via ARP, NDP, and DHCP.
	</p>

	<!-- Device Table with integrated DataTableCard -->
	<DeviceTable
		{devices}
		totalCount={meta?.total ?? devices.length}
		onlineCount={meta?.online ?? devices.filter((d) => d.online).length}
		{loading}
		{scanning}
		onRefresh={loadDevices}
		onScan={triggerScan}
		onInspect={openDetails}
		onWol={handleWol}
		onPromote={openPromoteModal}
		onPurge={handlePurge}
	/>
</div>

<DeviceWhoisModal
	bind:open={detailsOpen}
	device={selectedDevice}
	history={whoisHistory}
	loading={loadingDetails}
/>

<DevicePromoteModal
	bind:open={promoteOpen}
	mac={promoteMac}
	hostname={promoteHostname}
	v4={promoteV4}
	v6Suffix={promoteV6Suffix}
	onPromoted={loadDevices}
/>
