<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import * as Dialog from "$lib/components/ui/dialog";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import FileDownIcon from "@lucide/svelte/icons/file-down";
	import FileUpIcon from "@lucide/svelte/icons/file-up";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";

	const dnsTabs: NavTabItem[] = [
		{ label: "Resolver & Analytics", href: "/dns/resolver", icon: GlobeIcon },
		{ label: "Cache Inspection", href: "/dns/cache", icon: DatabaseIcon },
		{ label: "Custom Rewrites", href: "/dns/rewrites", icon: BookmarkIcon },
	];
	import {
		dnsRewriteList,
		dnsRewriteAdd,
		dnsRewriteClear,
		dnsRewriteExport,
	} from "$lib/api/client";
	import type { RewriteRule } from "$lib/api/types";

	// Child components
	import DnsRewriteStatsCards from "./components/DnsRewriteStatsCards.svelte";
	import DnsRewriteTable from "./components/DnsRewriteTable.svelte";
	import DnsRewriteDialog from "./components/DnsRewriteDialog.svelte";
	import DnsRewriteImportDialog from "./components/DnsRewriteImportDialog.svelte";

	let loading = $state(true);
	let rules = $state<RewriteRule[]>([]);

	// Filters & Pagination
	let searchQuery = $state("");
	let selectedType = $state("");
	let limit = $state(50);
	let offset = $state(0);

	// Dialogs & Modals
	let addEditModalOpen = $state(false);
	let activeEditRule = $state<RewriteRule | null>(null);

	let importModalOpen = $state(false);
	let clearModalOpen = $state(false);
	let clearing = $state(false);

	async function loadRewrites() {
		loading = true;
		try {
			rules = await dnsRewriteList();
		} catch {
			toast.error("Failed to load DNS rewrite rules");
		} finally {
			loading = false;
		}
	}

	function handleOpenAdd() {
		activeEditRule = null;
		addEditModalOpen = true;
	}

	function handleOpenEdit(rule: RewriteRule) {
		activeEditRule = rule;
		addEditModalOpen = true;
	}

	async function handleSaveRule(
		payload: Omit<RewriteRule, "id"> | RewriteRule,
	) {
		try {
			await dnsRewriteAdd(payload);
			const isEdit = "id" in payload && Boolean(payload.id);
			toast.success(
				isEdit ? "Updated DNS rewrite rule" : "Added DNS rewrite rule",
			);
			await loadRewrites();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save DNS rewrite rule");
			throw err;
		}
	}

	async function handleExport() {
		try {
			const data = await dnsRewriteExport();
			const jsonStr = JSON.stringify(data, null, 2);
			const blob = new Blob([jsonStr], { type: "application/json" });
			const url = URL.createObjectURL(blob);
			const a = document.createElement("a");
			a.href = url;
			a.download = `lanforge-dns-rewrites-${Date.now()}.json`;
			a.click();
			URL.revokeObjectURL(url);
			toast.success("Exported DNS rewrite rules to JSON");
		} catch {
			toast.error("Failed to export DNS rewrite rules");
		}
	}

	async function confirmClearAll() {
		clearing = true;
		try {
			await dnsRewriteClear();
			toast.success("Cleared all DNS rewrite rules");
			clearModalOpen = false;
			offset = 0;
			await loadRewrites();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to clear rewrite rules");
		} finally {
			clearing = false;
		}
	}

	onMount(() => {
		loadRewrites();
	});
</script>

<svelte:head>
	<title>DNS Rewrites — Lanforge</title>
</svelte:head>

<div class="space-y-6">
	<!-- Top Action Bar -->
	<PageHeader
		title="DNS Rewrites"
		description="Custom DNS response overrides, domain wildcards, and dynamic LAN device bindings."
		icon={ArrowRightLeftIcon}
	>
		{#snippet actions()}
			<!-- Add Rule Button -->
			<Button size="sm" onclick={handleOpenAdd} class="gap-2">
				<PlusIcon class="h-4 w-4" />
				Add Rewrite Rule
			</Button>

			<!-- Export Button -->
			<Button
				variant="outline"
				size="sm"
				onclick={handleExport}
				class="gap-2"
			>
				<FileDownIcon class="h-4 w-4" />
				Export
			</Button>

			<!-- Import Button -->
			<Button
				variant="outline"
				size="sm"
				onclick={() => (importModalOpen = true)}
				class="gap-2"
			>
				<FileUpIcon class="h-4 w-4" />
				Import
			</Button>

			<!-- Refresh Button -->
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadRewrites()}
				disabled={loading}
				class="gap-2"
			>
				<RefreshCwIcon
					class="h-4 w-4 {loading ? 'animate-spin' : ''}"
				/>
				Refresh
			</Button>

			<!-- Clear All Button -->
			<Button
				variant="destructive"
				size="sm"
				onclick={() => (clearModalOpen = true)}
				disabled={rules.length === 0}
				class="gap-2"
			>
				<Trash2Icon class="h-4 w-4" />
				Clear All
			</Button>
		{/snippet}
	</PageHeader>

	<!-- DNS Sub-Navigation Tabs -->
	<NavTabs tabs={dnsTabs} ariaLabel="DNS system navigation" />

	<!-- Top Metric Summary Cards -->
	<DnsRewriteStatsCards {loading} {rules} />

	<!-- DNS Rewrites Data Table -->
	<DnsRewriteTable
		{loading}
		{rules}
		{searchQuery}
		{selectedType}
		{limit}
		{offset}
		onSearchChange={(q) => {
			searchQuery = q;
			offset = 0;
		}}
		onTypeChange={(type) => {
			selectedType = type;
			offset = 0;
		}}
		onPageChange={(newOffset) => (offset = newOffset)}
		onEditRule={handleOpenEdit}
		onRuleDeleted={loadRewrites}
	/>
</div>

<!-- Add/Edit Rewrite Rule Dialog -->
<DnsRewriteDialog
	bind:open={addEditModalOpen}
	rule={activeEditRule}
	onSave={handleSaveRule}
/>

<!-- Bulk Import Modal -->
<DnsRewriteImportDialog
	bind:open={importModalOpen}
	onImportSuccess={loadRewrites}
/>

<!-- Clear All Confirmation Modal -->
<Dialog.Root bind:open={clearModalOpen}>
	<Dialog.Content class="sm:max-w-[425px]">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2 text-destructive">
				<AlertTriangleIcon class="h-5 w-5" />
				Clear All Rewrite Rules
			</Dialog.Title>
			<Dialog.Description class="text-xs pt-1">
				Are you sure you want to delete all configured DNS rewrite
				rules? This operation cannot be undone.
			</Dialog.Description>
		</Dialog.Header>

		<Dialog.Footer class="gap-2 sm:gap-0 mt-4">
			<Button
				variant="outline"
				onclick={() => (clearModalOpen = false)}
				disabled={clearing}
			>
				Cancel
			</Button>
			<Button
				variant="destructive"
				onclick={confirmClearAll}
				disabled={clearing}
				class="gap-2"
			>
				{#if clearing}
					<RefreshCwIcon class="h-4 w-4 animate-spin" />
					Clearing...
				{:else}
					<Trash2Icon class="h-4 w-4" />
					Clear All Now
				{/if}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
