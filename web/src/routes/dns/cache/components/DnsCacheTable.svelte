<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import * as Select from "$lib/components/ui/select";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import { toast } from "svelte-sonner";
	import { dnsBlock, dnsAllow } from "$lib/api/client";
	import type { DnsCacheEntry, DnsRecordType } from "$lib/api/types";
	import DnsCacheRecordDialog from "./DnsCacheRecordDialog.svelte";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	let {
		loading = false,
		entries = [],
		total = 0,
		searchQuery = "",
		selectedType = "",
		limit = 50,
		offset = 0,
		onSearchChange = (q: string) => {},
		onTypeChange = (type: string) => {},
		onPageChange = (newOffset: number) => {},
		onAddRewrite = (domain: string, target: string) => {},
	}: {
		loading?: boolean;
		entries?: DnsCacheEntry[];
		total?: number;
		searchQuery?: string;
		selectedType?: string;
		limit?: number;
		offset?: number;
		onSearchChange?: (q: string) => void;
		onTypeChange?: (type: string) => void;
		onPageChange?: (newOffset: number) => void;
		onAddRewrite?: (domain: string, target: string) => void;
	} = $props();

	let copiedItem = $state<string | null>(null);
	let selectedRecord = $state<DnsCacheEntry | null>(null);
	let dialogOpen = $state(false);

	const RECORD_TYPES: DnsRecordType[] = [
		"A",
		"AAAA",
		"CNAME",
		"PTR",
		"TXT",
		"MX",
		"NS",
		"SOA",
		"SRV",
		"HTTPS",
		"SVCB",
	];

	const typeVariants: Record<string, string> = {
		A: "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20",
		AAAA: "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20",
		CNAME: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20",
		PTR: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
		TXT: "bg-slate-500/10 text-slate-600 dark:text-slate-400 border-slate-500/20",
		MX: "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20",
		NS: "bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/20",
		SOA: "bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20",
		SRV: "bg-teal-500/10 text-teal-600 dark:text-teal-400 border-teal-500/20",
		HTTPS: "bg-violet-500/10 text-violet-600 dark:text-violet-400 border-violet-500/20",
		SVCB: "bg-fuchsia-500/10 text-fuchsia-600 dark:text-fuchsia-400 border-fuchsia-500/20",
	};

	function cleanDomain(raw: string): string {
		if (!raw) return "";
		return raw.trim().replace(/\.$/, "");
	}

	function cleanData(raw: string): string {
		if (!raw) return "—";
		return raw
			.replace(/^"|"$/g, "")
			.replace(/^(A|AAAA|CNAME|PTR|NS)\((.*)\)$/, "$2")
			.trim()
			.replace(/\.$/, "");
	}

	function formatTtl(secs: number): string {
		if (secs <= 0) return "Expiring...";
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		if (m === 0) return `${s}s`;
		return `${m}m ${s}s`;
	}

	async function copyToClipboard(text: string, label: string) {
		try {
			await navigator.clipboard.writeText(text);
			copiedItem = text;
			toast.success(`Copied ${label} to clipboard`);
			setTimeout(() => {
				copiedItem = null;
			}, 2000);
		} catch {
			toast.error("Failed to copy to clipboard");
		}
	}

	function inspectRecord(entry: DnsCacheEntry) {
		selectedRecord = entry;
		dialogOpen = true;
	}

	async function handleQuickBlock(domain: string) {
		const target = cleanDomain(domain);
		try {
			await dnsBlock(target);
			toast.success(`Added ${target} to adblock black list`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to block domain");
		}
	}

	async function handleQuickAllow(domain: string) {
		const target = cleanDomain(domain);
		try {
			await dnsAllow(target);
			toast.success(`Added ${target} to allowlist`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to allow domain");
		}
	}

</script>

<DataTableCard
	title="Cached Records"
	icon={DatabaseIcon}
	total={total}
	itemName="cached entries"
	searchPlaceholder="Search domain or answer..."
	bind:searchQuery
	{onSearchChange}
	{loading}
	columns={5}
	pageIndex={Math.floor(offset / limit)}
	pageSize={limit}
	onPageChange={(newIdx) => onPageChange(newIdx * limit)}
	emptyMessage="DNS cache is currently empty."
	emptyFilteredMessage="No cached records match the active filter."
>
	{#snippet filters()}
		<Select.Root
			type="single"
			value={selectedType}
			onValueChange={(val) => onTypeChange(val ?? "")}
		>
			<Select.Trigger class="h-9 w-[130px] text-xs">
				{selectedType
					? `Type: ${selectedType}`
					: "All Record Types"}
			</Select.Trigger>
			<Select.Content>
				<Select.Item value="" class="text-xs">All Record Types</Select.Item>
				{#each RECORD_TYPES as rtype (rtype)}
					<Select.Item value={rtype} class="text-xs">{rtype}</Select.Item>
				{/each}
			</Select.Content>
		</Select.Root>
	{/snippet}

	{#snippet header()}
		<Table.Head class="w-[280px]">Domain Name</Table.Head>
		<Table.Head class="w-[90px]">Type</Table.Head>
		<Table.Head>Resolved Value / Target</Table.Head>
		<Table.Head class="w-[120px] text-right">TTL / Expires</Table.Head>
		<Table.Head class="w-[60px] text-right">Actions</Table.Head>
	{/snippet}

	{#each entries as entry (entry.name + entry.kind + entry.data)}
						{@const domainClean = cleanDomain(entry.name)}
						{@const dataClean = cleanData(entry.data)}
						{@const style =
							typeVariants[entry.kind] ||
							"bg-secondary text-secondary-foreground border-border"}
						{@const isExpiringSoon = entry.expires_in_secs < 30}
						<Table.Row
							class="hover:bg-muted/50 transition-colors cursor-pointer group"
							onclick={() => inspectRecord(entry)}
						>
							<!-- Domain Name -->
							<Table.Cell class="font-medium text-xs">
								<div class="flex items-center gap-1.5">
									<span
										class="truncate max-w-[240px] font-mono text-foreground font-medium"
										title={domainClean}
									>
										{domainClean}
									</span>
									<button
										type="button"
										onclick={(e) => {
											e.stopPropagation();
											copyToClipboard(
												domainClean,
												"domain name",
											);
										}}
										class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
										title="Copy domain"
									>
										{#if copiedItem === domainClean}
											<CheckIcon
												class="h-3.5 w-3.5 text-emerald-500"
											/>
										{:else}
											<CopyIcon
												class="h-3.5 w-3.5 text-muted-foreground"
											/>
										{/if}
									</button>
								</div>
							</Table.Cell>

							<!-- Type Badge -->
							<Table.Cell>
								<Badge
									variant="outline"
									class="px-2 py-0.5 text-[11px] font-mono border font-semibold {style}"
								>
									{entry.kind}
								</Badge>
							</Table.Cell>

							<!-- Value / Target -->
							<Table.Cell
								class="font-mono text-xs text-muted-foreground"
							>
								<div class="flex items-center gap-1.5">
									{#if dataClean === "no-data"}
										<span
											class="inline-flex items-center gap-1 text-muted-foreground/70 italic text-[11px]"
										>
											no-data
										</span>
									{:else if dataClean === "wire-error"}
										<span
											class="inline-flex items-center gap-1 text-rose-500/80 font-medium text-[11px]"
										>
											wire-error
										</span>
									{:else}
										<span
											class="truncate max-w-[380px] text-foreground/90 font-mono"
											title={dataClean}
										>
											{dataClean}
										</span>
										<button
											type="button"
											onclick={(e) => {
												e.stopPropagation();
												copyToClipboard(
													dataClean,
													"answer value",
												);
											}}
											class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
											title="Copy resolved value"
										>
											{#if copiedItem === dataClean}
												<CheckIcon
													class="h-3.5 w-3.5 text-emerald-500"
												/>
											{:else}
												<CopyIcon
													class="h-3.5 w-3.5 text-muted-foreground"
												/>
											{/if}
										</button>
									{/if}
								</div>
							</Table.Cell>

							<!-- TTL Expiration -->
							<Table.Cell class="text-right font-mono text-xs">
								<span
									class={isExpiringSoon
										? "text-amber-500 font-semibold"
										: "text-muted-foreground"}
								>
									{formatTtl(entry.expires_in_secs)}
								</span>
							</Table.Cell>

							<!-- Row Action Menu -->
							<Table.Cell
								class="text-right"
								onclick={(e) => e.stopPropagation()}
							>
								<DropdownMenu.Root>
									<DropdownMenu.Trigger
										class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
									>
										<MoreHorizontalIcon class="h-4 w-4" />
									</DropdownMenu.Trigger>
									<DropdownMenu.Content
										align="end"
										class="w-44 text-xs"
									>
										<DropdownMenu.Item
											onclick={() => inspectRecord(entry)}
											class="gap-2"
										>
											<EyeIcon
												class="h-3.5 w-3.5 text-primary"
											/>
											Inspect Record
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() =>
												copyToClipboard(
													domainClean,
													"domain name",
												)}
											class="gap-2"
										>
											<CopyIcon
												class="h-3.5 w-3.5 text-muted-foreground"
											/>
											Copy Domain
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() =>
												copyToClipboard(
													dataClean,
													"answer value",
												)}
											class="gap-2"
										>
											<CopyIcon
												class="h-3.5 w-3.5 text-muted-foreground"
											/>
											Copy Resolved Target
										</DropdownMenu.Item>
										<DropdownMenu.Separator />
										<DropdownMenu.Item
											onclick={() =>
												handleQuickBlock(domainClean)}
											class="gap-2 text-rose-500"
										>
											<ShieldAlertIcon
												class="h-3.5 w-3.5"
											/>
											Block Domain
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() =>
												handleQuickAllow(domainClean)}
											class="gap-2 text-emerald-500"
										>
											<ShieldCheckIcon
												class="h-3.5 w-3.5"
											/>
											Allow Domain
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() =>
												onAddRewrite(
													domainClean,
													dataClean !== "no-data"
														? dataClean
														: "",
												)}
											class="gap-2"
										>
											<ArrowRightLeftIcon
												class="h-3.5 w-3.5 text-amber-500"
											/>
											Create Rewrite
										</DropdownMenu.Item>
									</DropdownMenu.Content>
								</DropdownMenu.Root>
							</Table.Cell>
						</Table.Row>
					{/each}
</DataTableCard>

<!-- Inspection Dialog -->
<DnsCacheRecordDialog
	bind:open={dialogOpen}
	entry={selectedRecord}
	onAddRewrite={(domain, target) => onAddRewrite(domain, target)}
/>
