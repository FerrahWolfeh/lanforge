<script lang="ts">
	import { onMount } from "svelte";
	import { toast } from "svelte-sonner";
	import {
		listDevices,
		whois,
		purge,
		wol,
		scan,
	} from "$lib/api/client";
	import type { DeviceEntry } from "$lib/api/types";

	import DeviceStatsHeader from "./components/DeviceStatsHeader.svelte";
	import DeviceTable from "./components/DeviceTable.svelte";
	import DeviceWhoisModal from "./components/DeviceWhoisModal.svelte";
	import DevicePromoteModal from "./components/DevicePromoteModal.svelte";

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
		} catch (err: any) {
			toast.error(err?.message || "Failed to load devices");
		} finally {
			loading = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		toast.info("Triggering background network ARP/NDP sweep...");
		try {
			await scan();
			toast.success("Scan initiated successfully");
			setTimeout(loadDevices, 1500);
		} catch (err: any) {
			toast.error(err?.message || "Failed to trigger scan");
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
</script>

<svelte:head>
	<title>Devices — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<DeviceStatsHeader
		{loading}
		{scanning}
		totalCount={meta?.total ?? devices.length}
		onlineCount={meta?.online ?? devices.filter((d) => d.online).length}
		bind:searchQuery
		bind:statusFilter
		onRefresh={loadDevices}
		onScan={triggerScan}
	/>

	<DeviceTable
		devices={filteredDevices}
		{loading}
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
