<script lang="ts">
	import { RECORD_TYPES, cleanDomain, cleanAnswer, quickDnsRule } from "$lib/components/dns/dnsLog";
	import { copyToClipboard } from "$lib/utils";
	import { auth } from "$lib/stores/auth.svelte";
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
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
	import type { DnsCacheEntry } from "$lib/api/types";
	import DnsCacheRecordDialog from "./DnsCacheRecordDialog.svelte";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	// Block, allow and rewrites need dns_write.
	const canDnsWrite = $derived(auth.can("dns_write"));

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

	const typeVariants: Record<string, string> = {
		A: "bg-muted text-muted-foreground border-border",
		AAAA: "bg-muted text-muted-foreground border-border",
		CNAME: "bg-muted text-muted-foreground border-border",
		PTR: "bg-muted text-muted-foreground border-border",
		TXT: "bg-muted text-muted-foreground border-border",
		MX: "bg-muted text-muted-foreground border-border",
		NS: "bg-muted text-muted-foreground border-border",
		SOA: "bg-muted text-muted-foreground border-border",
		SRV: "bg-muted text-muted-foreground border-border",
		HTTPS: "bg-muted text-muted-foreground border-border",
		SVCB: "bg-muted text-muted-foreground border-border",
	};

	function formatTtl(secs: number): string {
		if (secs <= 0) return "Expiring...";
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		if (m === 0) return `${s}s`;
		return `${m}m ${s}s`;
	}

	async function copyItem(text: string, label: string) {
		if (!(await copyToClipboard(text, label))) return;
		copiedItem = text;
		setTimeout(() => {
			copiedItem = null;
		}, 2000);
	}

	function inspectRecord(entry: DnsCacheEntry) {
		selectedRecord = entry;
		dialogOpen = true;
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
						{@const dataClean = cleanAnswer(entry.data)}
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
											copyItem(
												domainClean,
												"domain name",
											);
										}}
										class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
										title="Copy domain"
									>
										{#if copiedItem === domainClean}
											<CheckIcon
												class="h-3.5 w-3.5 text-success"
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
									class="px-2 py-0.5 text-xs font-mono border font-semibold {style}"
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
											class="inline-flex items-center gap-1 text-muted-foreground/70 italic text-xs"
										>
											no-data
										</span>
									{:else if dataClean === "wire-error"}
										<span
											class="inline-flex items-center gap-1 text-danger font-medium text-xs"
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
												copyItem(
													dataClean,
													"answer value",
												);
											}}
											class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
											title="Copy resolved value"
										>
											{#if copiedItem === dataClean}
												<CheckIcon
													class="h-3.5 w-3.5 text-success"
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
										? "text-warning font-semibold"
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
												copyItem(
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
												copyItem(
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
										{#if canDnsWrite}
										<DropdownMenu.Separator />
										<DropdownMenu.Item
											onclick={() =>
												quickDnsRule("block", domainClean)}
											class="gap-2 text-danger"
										>
											<ShieldAlertIcon
												class="h-3.5 w-3.5"
											/>
											Block Domain
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() =>
												quickDnsRule("allow", domainClean)}
											class="gap-2 text-success"
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
												class="h-3.5 w-3.5 text-warning"
											/>
											Create Rewrite
										</DropdownMenu.Item>
										{/if}
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
