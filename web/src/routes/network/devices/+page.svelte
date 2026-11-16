<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
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
	import { createDebounce } from "$lib/utils";

	import DeviceTable from "./components/DeviceTable.svelte";
	import DeviceWhoisModal from "./components/DeviceWhoisModal.svelte";
	import DevicePromoteModal from "./components/DevicePromoteModal.svelte";
	import DeviceAdblockModal from "./components/DeviceAdblockModal.svelte";
	import DeviceLinkedModal from "./components/DeviceLinkedModal.svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";

	const lanTabs: NavTabItem[] = [
		{ label: "Discovered Devices", href: "/network/devices", icon: MonitorIcon },
		{ label: "Static Hosts", href: "/network/hosts", icon: BookmarkIcon },
	];

	let devices = $state<DeviceEntry[]>([]);
	let meta = $state<{ total: number; online: number } | null>(null);
	let loading = $state(true);
	let scanning = $state(false);

	// Details Modal State
	let selectedDevice = $state<DeviceEntry | null>(null);
	let detailsOpen = $state(false);
	let loadingDetails = $state(false);

	// Promote Modal State
	let promoteOpen = $state(false);
	let promoteMac = $state("");
	let promoteHostname = $state("");
	let promoteV4 = $state("");
	let promoteV6Suffix = $state("");
	// Adblock Groups Modal State
	let adblockOpen = $state(false);
	let adblockDevice = $state<DeviceEntry | null>(null);
	let linkedOpen = $state(false);
	let linkedDevice = $state<DeviceEntry | null>(null);
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
		try {
			const res = await whois(device.mac);
			if (res?.entry) {
				selectedDevice = res.entry;
			}
		} catch {
			// keep fallback device
		} finally {
			loadingDetails = false;
		}
	}

	function openPromoteModal(device: DeviceEntry) {
		promoteMac = device.mac;
		promoteHostname = device.hostname || "";
		promoteV4 = device.primary_v4 || device.v4?.ip || "";
		promoteV6Suffix = device.primary_v6 || device.v6?.ip || "";
		promoteOpen = true;
	}

	const debouncedLoad = createDebounce(() => {
		loadDevices(false);
	}, 300);

	onMount(() => {
		loadDevices();

		try {
			const url = eventsUrl({ filter: "device" });
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
								String(eventObj?.System?.ConfigChanged?.sections ?? '').includes('DHCP')
						);
					if (isDeviceUpdate) {
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

	const onlineCount = $derived(
		meta?.online ?? devices.filter((d) => d.online).length
	);
	const totalCount = $derived(meta?.total ?? devices.length);
</script>

<svelte:head>
	<title>Devices — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Header -->
	<PageHeader
		title="Devices"
		description="Everything seen on the LAN through ARP, NDP and DHCP."
		icon={MonitorIcon}
	/>

	<!-- LAN Inventory Tabs -->
	<NavTabs tabs={lanTabs} ariaLabel="LAN inventory navigation" />


	<!-- Device Table with integrated DataTableCard -->
	<DeviceTable
		{devices}
		{totalCount}
		{onlineCount}
		{loading}
		{scanning}
		onRefresh={loadDevices}
		onScan={auth.can("admin") ? triggerScan : undefined}
		onInspect={openDetails}
		onWol={auth.can("device_write") ? handleWol : undefined}
		onPromote={auth.can("device_write") ? openPromoteModal : undefined}
		onAdblock={auth.can("dns_write")
			? (dev) => {
					adblockDevice = dev;
					adblockOpen = true;
				}
			: undefined}
		onLinked={auth.can("device_write")
			? (dev) => {
					linkedDevice = dev;
					linkedOpen = true;
				}
			: undefined}
		onPurge={auth.can("device_write") ? handlePurge : undefined}
	/>
</div>

<DeviceWhoisModal
	bind:open={detailsOpen}
	device={selectedDevice}
	loading={loadingDetails}
/>

<DeviceAdblockModal bind:open={adblockOpen} device={adblockDevice} />

<DeviceLinkedModal bind:open={linkedOpen} device={linkedDevice} onSaved={() => loadDevices(false)} />

<DevicePromoteModal
	bind:open={promoteOpen}
	mac={promoteMac}
	hostname={promoteHostname}
	v4={promoteV4}
	v6Suffix={promoteV6Suffix}
	onPromoted={loadDevices}
/>
