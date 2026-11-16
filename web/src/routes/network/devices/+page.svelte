<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
	import { onMount, onDestroy } from "svelte";
	import { toast } from "svelte-sonner";
	import {
		listDevices,
		purge,
		wol,
		scan,
		eventsUrl,
	} from "$lib/api/client";
	import type { DeviceEntry } from "$lib/api/types";
	import { createDebounce } from "$lib/utils";

	import DeviceTable from "./components/DeviceTable.svelte";
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
		if (!confirm(`Forget ${mac}? Its addresses and history are removed; it comes back when seen again.`)) return;
		try {
			await purge(mac);
			toast.success(`${mac} forgotten`);
			await loadDevices();
		} catch (err: any) {
			toast.error(err?.message || "Failed to forget the device");
		}
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
		onWol={auth.can("device_write") ? handleWol : undefined}
		onPurge={auth.can("device_write") ? handlePurge : undefined}
	/>
</div>
