<script lang="ts">
	import {
		hostList,
		hostRemove,
		hostExport,
		hostImport,
		listDevices,
	} from "$lib/api/client";
	import type { HostConfigEntry, DeviceEntry } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";

	import HostTable from "./components/HostTable.svelte";
	import HostDialog from "./components/HostDialog.svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import TagIcon from "@lucide/svelte/icons/tag";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";

	const lanTabs: NavTabItem[] = [
		{ label: "Discovered Devices", href: "/network/devices", icon: MonitorIcon },
		{ label: "Static Hosts", href: "/network/hosts", icon: BookmarkIcon },
	];

	let hosts = $state<HostConfigEntry[]>([]);
	let discoveredDevices = $state<DeviceEntry[]>([]);
	let loading = $state(true);

	// Add/Edit Host Modal state
	let dialogOpen = $state(false);
	let isEditing = $state(false);
	let activeHost = $state<HostConfigEntry | null>(null);

	onMount(loadHostsAndDevices);

	async function loadHostsAndDevices() {
		loading = true;
		try {
			const [hRes, dRes] = await Promise.allSettled([
				hostList(),
				listDevices(),
			]);
			if (hRes.status === "fulfilled") {
				hosts = hRes.value;
			}
			if (dRes.status === "fulfilled") {
				discoveredDevices = dRes.value.devices;
			}
		} catch {
			toast.error("Failed to load static host configurations");
		} finally {
			loading = false;
		}
	}

	function openAddModal() {
		activeHost = null;
		isEditing = false;
		dialogOpen = true;
	}

	function openEditModal(host: HostConfigEntry) {
		activeHost = host;
		isEditing = true;
		dialogOpen = true;
	}

	async function handleRemoveHost(mac: string) {
		if (!confirm(`Remove static host assignment for ${mac}?`)) return;
		try {
			await hostRemove(mac);
			toast.success(`Removed static host rule for ${mac}`);
			await loadHostsAndDevices();
		} catch {
			toast.error(`Failed to remove static host rule for ${mac}`);
		}
	}

	async function handleExportJson() {
		try {
			const entries = await hostExport();
			const jsonStr = JSON.stringify(entries, null, 2);
			const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			a.href = url;
			a.download = "lanforge-hosts.json";
			a.click();
			URL.revokeObjectURL(url);
			toast.success("Static host definitions exported as JSON");
		} catch {
			toast.error("Failed to export static hosts");
		}
	}

	function handleImportFile(e: Event) {
		const target = e.target as HTMLInputElement;
		const file = target.files?.[0];
		if (!file) return;

		const reader = new FileReader();
		reader.onload = async (event) => {
			const content = event.target?.result as string;
			if (!content) return;
			try {
				const entries = JSON.parse(content);
				if (!Array.isArray(entries)) throw new Error("File must contain a JSON array of host rules");
				await hostImport(entries);
				toast.success("Successfully imported host rules");
				await loadHostsAndDevices();
			} catch (err: any) {
				toast.error(err?.message || "Failed to parse and import JSON");
			}
		};
		reader.readAsText(file);
		target.value = "";
	}

	const v4Count = $derived(hosts.filter((h) => h.v4 || h.v4_fixed).length);
	const v6SuffixCount = $derived(hosts.filter((h) => h.v6_suffix).length);
	const hostnameCount = $derived(hosts.filter((h) => h.hostname).length);
</script>

<svelte:head>
	<title>Static Hosts — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Header -->
	<PageHeader
		title="Static Hosts & Reservations"
		description="Fixed IP reservations, DNS name overrides, and predictable interface suffixes."
		icon={BookmarkIcon}
	/>

	<!-- LAN Inventory Tabs -->
	<NavTabs tabs={lanTabs} ariaLabel="LAN inventory navigation" />

	<!-- Vitals Cards Grid -->
	<StatCardGrid cols={4}>
		<StatCard
			label="Static Reservations"
			value={hosts.length}
			subtext="Pinned MAC-to-IP/hostname rules"
			icon={BookmarkIcon}
			color="emerald"
			{loading}
			badge={{
				text: "Static Leases",
				variant: "online",
				showDot: true,
			}}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Allocation" value="Deterministic" />
				<StatCardFooterItem label="Persistence" value="Saved to redb" color="text-emerald-400" />
			{/snippet}
		</StatCard>

		<StatCard
			label="IPv4 Pinned Leases"
			value={v4Count}
			subtext="Fixed IPv4 assignments"
			icon={NetworkIcon}
			color="sky"
			{loading}
		>
			{#snippet footer()}
				<StatCardFooterItem label="DHCP Pool" value="Excluded" />
				<StatCardFooterItem label="Lease Window" value="Infinite" />
			{/snippet}
		</StatCard>

		<StatCard
			label="IPv6 Suffix Overrides"
			value={v6SuffixCount}
			subtext="Configured IID tokens"
			icon={GlobeIcon}
			color="indigo"
			{loading}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Prefix Extension" value="Dynamic" />
				<StatCardFooterItem label="Token Strategy" value="Stateless SLAAC" />
			{/snippet}
		</StatCard>

		<StatCard
			label="DNS Hostname Aliases"
			value={hostnameCount}
			subtext="Custom local domain mappings"
			icon={TagIcon}
			color="amber"
			{loading}
		>
			{#snippet footer()}
				<StatCardFooterItem label="Resolution" value="Authoritative" />
				<StatCardFooterItem label="Reverse PTR" value="Synthesized" />
			{/snippet}
		</StatCard>
	</StatCardGrid>

	<!-- Host Table with integrated DataTableCard -->
	<HostTable
		{hosts}
		{loading}
		onRefresh={loadHostsAndDevices}
		onExport={handleExportJson}
		onImport={handleImportFile}
		onAdd={openAddModal}
		onEdit={openEditModal}
		onDelete={handleRemoveHost}
	/>
</div>

<!-- Add/Edit Modal -->
<HostDialog
	bind:open={dialogOpen}
	{isEditing}
	host={activeHost}
	devices={discoveredDevices}
	onSaved={loadHostsAndDevices}
/>
