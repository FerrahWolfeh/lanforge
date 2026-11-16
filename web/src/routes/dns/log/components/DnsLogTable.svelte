<script lang="ts">
	import { RECORD_TYPES, cleanDomain, cleanAnswer, getResultBadge, quickDnsRule } from "$lib/components/dns/dnsLog";
	import { copyToClipboard, formatClockTime, formatLatency } from "$lib/utils";
	import { goto } from "$app/navigation";
	import { auth } from "$lib/stores/auth.svelte";
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import * as Select from "$lib/components/ui/select";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import type { DnsQueryLogEntry } from "$lib/api/types";
	import DnsLogDetailDialog from "./DnsLogDetailDialog.svelte";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	// Block, allow and rewrites need dns_write.
	const canDnsWrite = $derived(auth.can("dns_write"));

	let {
		loading = false,
		entries = [],
		total = 0,
		searchQuery = "",
		selectedType = "",
		selectedResult = "",
		limit = 50,
		offset = 0,
		onSearchChange = (q: string) => {},
		onTypeChange = (type: string) => {},
		onResultChange = (res: string) => {},
		onPageChange = (newOffset: number) => {},
		onAddRewrite = (domain: string, target: string) => {},
	}: {
		loading?: boolean;
		entries?: DnsQueryLogEntry[];
		total?: number;
		searchQuery?: string;
		selectedType?: string;
		selectedResult?: string;
		limit?: number;
		offset?: number;
		onSearchChange?: (q: string) => void;
		onTypeChange?: (type: string) => void;
		onResultChange?: (res: string) => void;
		onPageChange?: (newOffset: number) => void;
		onAddRewrite?: (domain: string, target: string) => void;
	} = $props();

	let copiedItem = $state<string | null>(null);
	let selectedRecord = $state<DnsQueryLogEntry | null>(null);
	let dialogOpen = $state(false);
	let hoveredCoalesceId = $state<number | null>(null);

	const batchCounts = $derived.by(() => {
		const counts = new Map<number, number>();
		for (const e of entries) {
			if (e.coalesce_id != null) {
				counts.set(e.coalesce_id, (counts.get(e.coalesce_id) ?? 0) + 1);
			}
		}
		return counts;
	});

	const RESULT_FILTERS = [
		{ value: "", label: "All Outcomes" },
		{ value: "blocked", label: "Blocked" },
		{ value: "cachedblock", label: "Cached Block" },
		{ value: "forwarded", label: "Forwarded" },
		{ value: "cached", label: "Cached" },
		{ value: "coalesced", label: "Coalesced" },
		{ value: "rewritten", label: "Rewritten" },
		{ value: "local", label: "Local" },
		{ value: "nxdomain", label: "NXDomain" },
		{ value: "error", label: "Error" },
	];

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

	async function copyItem(text: string, label: string) {
		if (!(await copyToClipboard(text, label))) return;
		copiedItem = text;
		setTimeout(() => {
			copiedItem = null;
		}, 2000);
	}

	function inspectRecord(entry: DnsQueryLogEntry) {
		selectedRecord = entry;
		dialogOpen = true;
	}

</script>

{#snippet actionsMenu(entry: DnsQueryLogEntry, domainClean: string, answerClean: string)}
<DropdownMenu.Root>
	<DropdownMenu.Trigger
		class="h-7 w-7 max-md:size-9 shrink-0 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
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
			Inspect Log
		</DropdownMenu.Item>
		<DropdownMenu.Item
			onclick={() => goto(`/dns/domains/${encodeURIComponent(domainClean)}`)}
			class="gap-2"
		>
			<GlobeIcon
				class="h-3.5 w-3.5 text-muted-foreground"
			/>
			Open domain stats
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
					entry.src_ip,
					"client IP",
				)}
			class="gap-2"
		>
			<CopyIcon
				class="h-3.5 w-3.5 text-muted-foreground"
			/>
			Copy Client IP
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
					answerClean !== "—"
						? answerClean
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
{/snippet}

<DataTableCard
	title="DNS Query Log Entries"
	icon={ListFilterIcon}
	total={total}
	itemName="logged queries"
	searchPlaceholder="Search domain, client IP, or answer..."
	bind:searchQuery
	{onSearchChange}
	{loading}
	columns={7}
	pageIndex={Math.floor(offset / limit)}
	pageSize={limit}
	onPageChange={(newIdx) => onPageChange(newIdx * limit)}
	emptyMessage="No DNS queries have been logged yet."
	emptyFilteredMessage="No DNS log entries match the active filter criteria."
>
	{#snippet filters()}
		<!-- Outcome Filter -->
		<Select.Root
			type="single"
			value={selectedResult}
			onValueChange={(val) => onResultChange(val ?? "")}
		>
			<Select.Trigger class="h-9 w-[130px] text-xs">
				{selectedResult
					? `Outcome: ${selectedResult}`
					: "All Outcomes"}
			</Select.Trigger>
			<Select.Content>
				{#each RESULT_FILTERS as filter (filter.value)}
					<Select.Item value={filter.value} class="text-xs">
						{filter.label}
					</Select.Item>
				{/each}
			</Select.Content>
		</Select.Root>

		<!-- Record Type Filter -->
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

	{#snippet mobile()}
		{#each entries as entry, i (`${entry.timestamp}-${entry.src_ip}-${entry.domain}-${entry.qtype}-${i}`)}
			{@const domainClean = cleanDomain(entry.domain)}
			{@const answerClean = cleanAnswer(entry.answer)}
			{@const style = typeVariants[entry.qtype] || "bg-secondary text-secondary-foreground border-border"}
			{@const badgeInfo = getResultBadge(entry.result, entry.cached, entry.filter)}
			<div
				class="flex items-start gap-2 px-4 py-3 {entry.coalesce_id != null ? 'border-l-4 border-l-info/70' : ''}"
			>
				<button
					class="flex flex-1 min-w-0 flex-col gap-1 text-left cursor-pointer"
					onclick={() => inspectRecord(entry)}
				>
					<span class="flex items-baseline justify-between gap-2">
						<span class="flex items-center gap-1.5 min-w-0">
							{#if entry.result === "coalesced"}
								<span class="shrink-0 font-mono text-xs text-info">↳</span>
							{/if}
							<a
								href={`/dns/domains/${encodeURIComponent(domainClean)}`}
								class="truncate font-mono text-xs font-medium text-foreground hover:underline"
								onclick={(e) => e.stopPropagation()}>{domainClean}</a
							>
							{#if entry.repeats > 1}
								<span class="shrink-0 rounded border border-border bg-muted px-1 font-mono text-xs text-muted-foreground">
									×{entry.repeats}
								</span>
							{/if}
						</span>
						<span class="shrink-0 font-mono text-xs text-muted-foreground">
							{formatClockTime(entry.timestamp)}
						</span>
					</span>
					<span class="flex items-center gap-1.5 flex-wrap text-xs text-muted-foreground">
						{#if entry.src_mac}
							<a
								href={`/network/devices/${encodeURIComponent(entry.src_mac)}`}
								class="truncate max-w-[45%] hover:underline {entry.src_hostname ? 'text-foreground' : 'font-mono'}"
								onclick={(e) => e.stopPropagation()}
							>
								{entry.src_hostname || entry.src_ip}
							</a>
						{:else}
							<span class="truncate max-w-[45%] {entry.src_hostname ? 'text-foreground' : 'font-mono'}">
								{entry.src_hostname || entry.src_ip}
							</span>
						{/if}
						<Badge variant="outline" class="px-1.5 py-0 text-xs font-mono border font-semibold {style}">
							{entry.qtype}
						</Badge>
						<Badge variant="outline" class="px-1.5 py-0 text-xs font-mono border font-semibold {badgeInfo.class}">
							{badgeInfo.label}
						</Badge>
						<span class="font-mono">{formatLatency(entry.upstream_us)}</span>
					</span>
				</button>
				{@render actionsMenu(entry, domainClean, answerClean)}
			</div>
		{/each}
	{/snippet}

	{#snippet header()}
		<Table.Head class="w-[100px]">Time</Table.Head>
		<Table.Head class="w-[180px]">Client</Table.Head>
		<Table.Head class="w-[260px]">Domain Name</Table.Head>
		<Table.Head class="w-[80px]">Type</Table.Head>
		<Table.Head class="w-[110px]">Status</Table.Head>
		<Table.Head class="w-[100px] text-right">Latency</Table.Head>
		<Table.Head class="w-[60px] text-right">Actions</Table.Head>
	{/snippet}

	{#each entries as entry, i (`${entry.timestamp}-${entry.src_ip}-${entry.domain}-${entry.qtype}-${i}`)}
						{@const domainClean = cleanDomain(entry.domain)}
						{@const answerClean = cleanAnswer(entry.answer)}
						{@const style =
							typeVariants[entry.qtype] ||
							"bg-secondary text-secondary-foreground border-border"}
						{@const badgeInfo = getResultBadge(
							entry.result,
							entry.cached,
							entry.filter,
						)}
						{@const isCoalesced = entry.result === "coalesced"}
						{@const isLeader = entry.coalesce_id != null && !isCoalesced}
						{@const isBatchHovered = entry.coalesce_id != null && hoveredCoalesceId === entry.coalesce_id}
						{@const batchSize = entry.coalesce_id != null ? (batchCounts.get(entry.coalesce_id) ?? 1) : 0}
						<Table.Row
							class="transition-colors cursor-pointer group {entry.coalesce_id != null ? 'border-l-4 border-l-info/70' : ''} {isBatchHovered ? 'bg-info/[0.08]' : 'hover:bg-muted/50'}"
							onclick={() => inspectRecord(entry)}
							onmouseenter={() => {
								if (entry.coalesce_id != null) hoveredCoalesceId = entry.coalesce_id;
							}}
							onmouseleave={() => {
								if (entry.coalesce_id != null && hoveredCoalesceId === entry.coalesce_id) hoveredCoalesceId = null;
							}}
						>
							<!-- Time -->
							<Table.Cell
								class="font-mono text-xs text-muted-foreground"
							>
								{formatClockTime(entry.timestamp)}
							</Table.Cell>

							<!-- Client -->
							<Table.Cell class="text-xs">
								{#if entry.src_hostname}
									<div
										class="flex flex-col min-w-0"
										title={`${entry.src_hostname} (${entry.src_ip})`}
									>
										<div class="flex items-center gap-1.5">
											<LaptopIcon
												class="h-3.5 w-3.5 text-primary shrink-0"
											/>
											{#if entry.src_mac}
												<a
													href={`/network/devices/${encodeURIComponent(entry.src_mac)}`}
													class="truncate max-w-[150px] font-medium text-foreground text-xs hover:underline"
													onclick={(e) => e.stopPropagation()}
												>
													{entry.src_hostname}
												</a>
											{:else}
												<span
													class="truncate max-w-[150px] font-medium text-foreground text-xs"
												>
													{entry.src_hostname}
												</span>
											{/if}
										</div>
										<span
											class="text-xs font-mono text-muted-foreground truncate pl-5"
										>
											{entry.src_ip}
										</span>
									</div>
								{:else}
									<div
										class="flex items-center gap-1.5"
										title={entry.src_ip}
									>
										<LaptopIcon
											class="h-3.5 w-3.5 text-muted-foreground shrink-0"
										/>
										{#if entry.src_mac}
											<a
												href={`/network/devices/${encodeURIComponent(entry.src_mac)}`}
												class="truncate max-w-[150px] font-mono text-foreground text-xs hover:underline"
												onclick={(e) => e.stopPropagation()}
											>
												{entry.src_ip}
											</a>
										{:else}
											<span
												class="truncate max-w-[150px] font-mono text-foreground text-xs"
											>
												{entry.src_ip}
											</span>
										{/if}
									</div>
								{/if}
							</Table.Cell>

							<!-- Domain Name -->
							<Table.Cell class="font-medium text-xs">
								<div class="flex items-center gap-1.5 {isCoalesced ? 'pl-3' : ''}">
									{#if isCoalesced}
										<span class="text-info font-mono text-xs shrink-0" title="Coalesced into in-flight query">↳</span>
									{/if}
									<a
										href={`/dns/domains/${encodeURIComponent(domainClean)}`}
										class="truncate max-w-[220px] font-mono text-foreground font-medium hover:underline"
										title={domainClean}
										onclick={(e) => e.stopPropagation()}
									>
										{domainClean}
									</a>
									{#if entry.repeats > 1}
										<span
											class="shrink-0 rounded border border-border bg-muted px-1 font-mono text-xs text-muted-foreground"
											title={`${entry.repeats} identical queries from this client, folded into one line`}
										>
											×{entry.repeats}
										</span>
									{/if}
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
									{entry.qtype}
								</Badge>
							</Table.Cell>

							<!-- Outcome Status Badge -->
							<Table.Cell>
								<div class="flex items-center gap-1.5 flex-wrap">
									<Badge
										variant="outline"
										class="px-2 py-0.5 text-xs font-mono border font-semibold {badgeInfo.class}"
										title={entry.filter?.rule ? `Rule: ${entry.filter.rule}` : undefined}
									>
										{badgeInfo.label}
									</Badge>
									{#if isLeader && batchSize > 1}
										<span
											class="inline-flex items-center px-1.5 py-0.5 text-xs rounded font-mono font-medium bg-info/10 text-info border border-info/20"
											title={`Leader of batch #${entry.coalesce_id} with ${batchSize} concurrent queries`}
										>
											Leader ({batchSize}x)
										</span>
									{:else if isCoalesced}
										<span
											class="text-xs text-info font-mono"
											title={`In-flight multiplexed from batch #${entry.coalesce_id}`}
										>
											multiplex
										</span>
									{/if}
								</div>
							</Table.Cell>

							<!-- Latency -->
							<Table.Cell
								class="text-right font-mono text-xs text-muted-foreground"
							>
								{formatLatency(entry.upstream_us)}
							</Table.Cell>

							<!-- Actions Dropdown -->
							<Table.Cell
								class="text-right"
								onclick={(e) => e.stopPropagation()}
							>
								{@render actionsMenu(entry, domainClean, answerClean)}
							</Table.Cell>
						</Table.Row>
					{/each}
</DataTableCard>

<!-- Inspection Dialog -->
<DnsLogDetailDialog
	bind:open={dialogOpen}
	entry={selectedRecord}
	onAddRewrite={(domain, target) => onAddRewrite(domain, target)}
/>
