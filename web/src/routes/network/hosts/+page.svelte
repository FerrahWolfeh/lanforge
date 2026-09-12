<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
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

	import SearchIcon from "@lucide/svelte/icons/search";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import FileDownIcon from "@lucide/svelte/icons/file-down";
	import FileUpIcon from "@lucide/svelte/icons/file-up";

	import HostTable from "./components/HostTable.svelte";
	import HostDialog from "./components/HostDialog.svelte";

	let hosts = $state<HostConfigEntry[]>([]);
	let discoveredDevices = $state<DeviceEntry[]>([]);
	let loading = $state(true);
	let searchQuery = $state("");

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

	const filteredHosts = $derived.by(() => {
		if (!searchQuery.trim()) return hosts;
		const q = searchQuery.toLowerCase().trim();
		return hosts.filter((h) => {
			const macMatch = h.mac?.toLowerCase().includes(q);
			const hostMatch = h.hostname?.toLowerCase().includes(q);
			const v4Match = (h.v4_fixed || h.v4 || "")
				.toLowerCase()
				.includes(q);
			const v6Match = (h.v6_suffix || "").toLowerCase().includes(q);
			return macMatch || hostMatch || v4Match || v6Match;
		});
	});
</script>

<svelte:head>
	<title>Static Hosts — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-5">
	<!-- Page Header -->
	<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-foreground text-2xl font-bold tracking-tight">
				Static Hosts & Overrides
			</h1>
			<p class="text-muted-foreground text-xs sm:text-sm">
				Fixed IP reservations, DNS name overrides, and interface suffixes
			</p>
		</div>

		<div class="flex flex-wrap items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={loadHostsAndDevices}
				disabled={loading}
				class="h-8 text-xs gap-1.5"
			>
				<RefreshCwIcon class="size-3.5 {loading ? 'animate-spin' : ''}" />
				<span>Refresh</span>
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={handleExportJson}
				class="h-8 text-xs gap-1.5"
			>
				<FileDownIcon class="size-3.5 text-muted-foreground" />
				<span class="hidden sm:inline">Export</span>
			</Button>

			<label class="cursor-pointer">
				<input
					type="file"
					accept=".json"
					class="hidden"
					onchange={handleImportFile}
				/>
				<Button
					variant="outline"
					size="sm"
					class="h-8 text-xs gap-1.5 pointer-events-none"
				>
					<FileUpIcon class="size-3.5 text-muted-foreground" />
					<span class="hidden sm:inline">Import</span>
				</Button>
			</label>

			<Button
				size="sm"
				onclick={openAddModal}
				class="h-8 text-xs gap-1.5"
			>
				<PlusIcon class="size-3.5" />
				<span>Add Host</span>
			</Button>
		</div>
	</div>

	<!-- Controls & Search Bar -->
	<Card.Root>
		<Card.Content class="flex flex-col gap-3 p-3 sm:flex-row sm:items-center sm:justify-between">
			<!-- Search input -->
			<div class="relative flex-1 max-w-sm">
				<SearchIcon class="text-muted-foreground absolute left-3 top-1/2 size-3.5 -translate-y-1/2" />
				<Input
					type="search"
					placeholder="Search hostname, MAC, or IP..."
					class="pl-8 text-xs h-8"
					bind:value={searchQuery}
				/>
			</div>

			<span class="text-xs text-muted-foreground">
				Total Rules: <span class="font-mono font-semibold text-foreground">{hosts.length}</span>
			</span>
		</Card.Content>
	</Card.Root>

	<!-- Host Table / Mobile Cards -->
	<HostTable
		hosts={filteredHosts}
		{loading}
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
