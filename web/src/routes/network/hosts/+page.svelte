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
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";

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
</script>

<svelte:head>
	<title>Static Hosts — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Description Toolbar -->
	<p class="text-muted-foreground text-xs sm:text-sm">
		Fixed IP reservations, DNS name overrides, and interface suffixes.
	</p>

	<!-- LAN Inventory Tabs -->
	<NavTabs tabs={lanTabs} ariaLabel="LAN inventory navigation" />

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
