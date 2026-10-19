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
	import { createDebounce } from "$lib/utils";

	import DeviceTable from "./components/DeviceTable.svelte";
	import DeviceWhoisModal from "./components/DeviceWhoisModal.svelte";
	import DevicePromoteModal from "./components/DevicePromoteModal.svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";

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
								eventObj?.System?.ConfigDhcpV4Changed ||
								eventObj?.System?.ConfigDhcpV6Changed
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
	const dualStackCount = $derived(
		devices.filter((d) => (d.v4 || d.primary_v4) && (d.v6 || d.primary_v6)).length
	);
	const staticCount = $derived(
		devices.filter((d) => d.origin === "Static").length
	);
</script>

<svelte:head>
	<title>Devices — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Header -->
	<PageHeader
		title="Network Devices"
		description="Discovered LAN endpoints tracked via ARP, NDP, and DHCP."
		icon={MonitorIcon}
	/>

	<!-- LAN Inventory Tabs -->
	<NavTabs tabs={lanTabs} ariaLabel="LAN inventory navigation" />

	<!-- Vitals Cards Grid -->
	<StatCardGrid cols={4}>
		<StatCard
			label="Connected Endpoints"
			value={`${onlineCount} / ${totalCount}`}
			subtext={`${onlineCount} active hosts responding on LAN`}
			icon={WifiIcon}
			color="emerald"
			{loading}
			badge={{
				text: "L2/L3 Active",
				variant: "online",
				showDot: true,
			}}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Online Hosts" value={onlineCount} color="text-emerald-400" />
				<StatCardFooterItem label="Offline Hosts" value={Math.max(0, totalCount - onlineCount)} />
			{/snippet}
		</StatCard>

		<StatCard
			label="Dual-Stack Adoption"
			value={dualStackCount}
			subtext="Hosts with both IPv4 and IPv6 routes"
			icon={GlobeIcon}
			color="sky"
			{loading}
			badge={{
				text: totalCount > 0 ? `${Math.round((dualStackCount / totalCount) * 100)}% Dual-Stack` : "IPv4 / IPv6",
				variant: "sky",
			}}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Dual-Stack" value={dualStackCount} color="text-sky-400" />
				<StatCardFooterItem label="Single-Stack" value={Math.max(0, totalCount - dualStackCount)} />
			{/snippet}
		</StatCard>

		<StatCard
			label="Static Reservations"
			value={staticCount}
			subtext="Pinned fixed IP leases and DHCP mappings"
			icon={BookmarkIcon}
			color="indigo"
			{loading}
			badge={{
				text: "Pinned",
				variant: "indigo",
			}}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Fixed Leases" value={staticCount} color="text-indigo-400" />
				<StatCardFooterItem label="Dynamic Scope" value={Math.max(0, totalCount - staticCount)} />
			{/snippet}
		</StatCard>

		<StatCard
			label="Neighbor Monitor"
			value="Kernel Netlink"
			subtext="Passive ARP & NDP neighbor tracking"
			icon={ActivityIcon}
			color="violet"
			{loading}
			badge={{
				text: scanning ? "Scanning..." : "Passive Active",
				variant: scanning ? "starting" : "online",
				showDot: true,
				pulse: true,
			}}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Protocol" value="ARP / NDP" />
				<StatCardFooterItem label="Monitoring" value="Zero Overhead" color="text-emerald-400" />
			{/snippet}
		</StatCard>
	</StatCardGrid>

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
