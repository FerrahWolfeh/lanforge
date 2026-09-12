<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Input } from "$lib/components/ui/input";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import * as Select from "$lib/components/ui/select";
	import SearchIcon from "@lucide/svelte/icons/search";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import ChevronLeftIcon from "@lucide/svelte/icons/chevron-left";
	import ChevronRightIcon from "@lucide/svelte/icons/chevron-right";
	import ListFilterIcon from "@lucide/svelte/icons/list-filter";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import { toast } from "svelte-sonner";
	import { dnsBlock, dnsAllow } from "$lib/api/client";
	import type { DnsQueryLogEntry, DnsRecordType } from "$lib/api/types";
	import DnsLogDetailDialog from "./DnsLogDetailDialog.svelte";

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

	const RESULT_FILTERS = [
		{ value: "", label: "All Outcomes" },
		{ value: "forwarded", label: "Forwarded" },
		{ value: "local", label: "Local" },
		{ value: "cached", label: "Cached" },
		{ value: "rewrite", label: "Rewritten" },
		{ value: "blocked", label: "Blocked" },
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

	function cleanAnswer(raw?: string | null): string {
		if (!raw) return "—";
		return raw
			.replace(/^"|"$/g, "")
			.replace(/^(A|AAAA|CNAME|PTR|NS)\((.*)\)$/, "$2")
			.trim()
			.replace(/\.$/, "");
	}

	function formatTime(ts: number): string {
		if (!ts) return "—";
		const d = new Date(ts);
		return d.toLocaleTimeString(undefined, {
			hour12: false,
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
		});
	}

	function formatLatency(us: number): string {
		if (us === 0) return "0 ms";
		if (us < 1000) return `${us} µs`;
		return `${(us / 1000).toFixed(1)} ms`;
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

	function inspectRecord(entry: DnsQueryLogEntry) {
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

	function getResultBadge(result: string, cached: boolean) {
		const lower = (result || "").toLowerCase();
		if (lower.includes("block") || lower.includes("deny")) {
			return {
				label: "Blocked",
				class: "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20",
			};
		}
		if (lower === "rewritten" || lower.includes("rewrite")) {
			return {
				label: "Rewritten",
				class: "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20",
			};
		}
		if (lower === "local") {
			return {
				label: "Local",
				class: "bg-teal-500/10 text-teal-600 dark:text-teal-400 border-teal-500/20",
			};
		}
		if (cached || lower === "cached") {
			return {
				label: "Cached",
				class: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
			};
		}
		return {
			label: "Forwarded",
			class: "bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/20",
		};
	}

	const currentPage = $derived(Math.floor(offset / limit) + 1);
	const totalPages = $derived(Math.max(1, Math.ceil(total / limit)));
	const startItem = $derived(total === 0 ? 0 : offset + 1);
	const endItem = $derived(Math.min(offset + limit, total));
</script>

<Card.Root
	class="flex flex-col h-[calc(100vh-250px)] min-h-[480px] max-h-[750px] overflow-hidden border shadow-sm"
>
	<Card.Header class="pb-3 shrink-0 border-b bg-card">
		<div
			class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
		>
			<div>
				<Card.Title
					class="text-base font-semibold flex items-center gap-2"
				>
					<ListFilterIcon class="h-4 w-4 text-primary" />
					DNS Query Log Entries
				</Card.Title>
				<Card.Description class="text-xs">
					Showing {startItem}–{endItem} of {total.toLocaleString()} logged
					queries
				</Card.Description>
			</div>

			<!-- Search & Filter Controls Toolbar -->
			<div class="flex flex-wrap items-center gap-2">
				<div class="relative w-full sm:w-60">
					<SearchIcon
						class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground"
					/>
					<Input
						type="text"
						placeholder="Search domain, client IP, or answer..."
						class="pl-9 h-9 text-xs"
						value={searchQuery}
						oninput={(e: Event) =>
							onSearchChange(
								(e.target as HTMLInputElement).value,
							)}
					/>
				</div>

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
							<Select.Item value={filter.value} class="text-xs"
								>{filter.label}</Select.Item
							>
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
						<Select.Item value="" class="text-xs"
							>All Record Types</Select.Item
						>
						{#each RECORD_TYPES as rtype (rtype)}
							<Select.Item value={rtype} class="text-xs"
								>{rtype}</Select.Item
							>
						{/each}
					</Select.Content>
				</Select.Root>
			</div>
		</div>
	</Card.Header>

	<!-- Table Body with Fixed Scroll Container -->
	<Card.Content class="p-0 flex-1 min-h-0 overflow-auto relative">
		<Table.Root class="min-w-[750px]">
			<Table.Header
				class="sticky top-0 z-10 bg-card/95 backdrop-blur-md border-b shadow-xs"
			>
				<Table.Row class="hover:bg-transparent">
					<Table.Head class="w-[100px]">Time</Table.Head>
					<Table.Head class="w-[180px]">Client</Table.Head>
					<Table.Head class="w-[260px]">Domain Name</Table.Head>
					<Table.Head class="w-[80px]">Type</Table.Head>
					<Table.Head class="w-[110px]">Status</Table.Head>
					<Table.Head class="w-[100px] text-right">Latency</Table.Head
					>
					<Table.Head class="w-[60px] text-right">Actions</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#if loading && entries.length === 0}
					{#each Array(6) as _}
						<Table.Row>
							<Table.Cell
								><Skeleton class="h-4 w-16" /></Table.Cell
							>
							<Table.Cell
								><Skeleton class="h-4 w-32" /></Table.Cell
							>
							<Table.Cell
								><Skeleton class="h-4 w-48" /></Table.Cell
							>
							<Table.Cell
								><Skeleton
									class="h-5 w-10 rounded-full"
								/></Table.Cell
							>
							<Table.Cell
								><Skeleton
									class="h-5 w-16 rounded-full"
								/></Table.Cell
							>
							<Table.Cell class="text-right"
								><Skeleton
									class="h-4 w-14 ml-auto"
								/></Table.Cell
							>
							<Table.Cell
								><Skeleton
									class="h-4 w-6 ml-auto"
								/></Table.Cell
							>
						</Table.Row>
					{/each}
				{:else if entries.length === 0}
					<Table.Row>
						<Table.Cell
							colspan={7}
							class="h-48 text-center text-muted-foreground text-sm"
						>
							{#if searchQuery || selectedType || selectedResult}
								No DNS log entries match the active filter
								criteria.
							{:else}
								No DNS queries have been logged yet.
							{/if}
						</Table.Cell>
					</Table.Row>
				{:else}
					{#each entries as entry, i (`${entry.timestamp}-${entry.src_ip}-${entry.domain}-${entry.qtype}-${i}`)}
						{@const domainClean = cleanDomain(entry.domain)}
						{@const answerClean = cleanAnswer(entry.answer)}
						{@const style =
							typeVariants[entry.qtype] ||
							"bg-secondary text-secondary-foreground border-border"}
						{@const badgeInfo = getResultBadge(
							entry.result,
							entry.cached,
						)}
						{@const clientDisplay =
							entry.src_hostname ?? entry.src_ip}

						<Table.Row
							class="hover:bg-muted/50 transition-colors cursor-pointer group"
							onclick={() => inspectRecord(entry)}
						>
							<!-- Time -->
							<Table.Cell
								class="font-mono text-xs text-muted-foreground"
							>
								{formatTime(entry.timestamp)}
							</Table.Cell>

							<!-- Client -->
							<Table.Cell class="font-mono text-xs">
								<div
									class="flex items-center gap-1.5"
									title={entry.src_ip}
								>
									<LaptopIcon
										class="h-3.5 w-3.5 text-muted-foreground shrink-0"
									/>
									<span
										class="truncate max-w-[150px] text-foreground"
									>
										{clientDisplay}
									</span>
								</div>
							</Table.Cell>

							<!-- Domain Name -->
							<Table.Cell class="font-medium text-xs">
								<div class="flex items-center gap-1.5">
									<span
										class="truncate max-w-[220px] font-mono text-foreground font-medium"
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
									{entry.qtype}
								</Badge>
							</Table.Cell>

							<!-- Outcome Status Badge -->
							<Table.Cell>
								<Badge
									variant="outline"
									class="px-2 py-0.5 text-[11px] font-mono border font-semibold {badgeInfo.class}"
								>
									{badgeInfo.label}
								</Badge>
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
											Inspect Log
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
													answerClean !== "—"
														? answerClean
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
				{/if}
			</Table.Body>
		</Table.Root>
	</Card.Content>

	<!-- Fixed Pinned Pagination Footer -->
	<div
		class="flex items-center justify-between px-4 py-2.5 border-t bg-card shrink-0 z-10"
	>
		<p class="text-xs text-muted-foreground">
			Page {currentPage} of {totalPages}
		</p>
		<div class="flex items-center gap-1">
			<Button
				variant="outline"
				size="sm"
				disabled={offset === 0 || loading}
				onclick={() => onPageChange(Math.max(0, offset - limit))}
				class="h-8 gap-1 px-2.5 text-xs"
			>
				<ChevronLeftIcon class="h-3.5 w-3.5" />
				Previous
			</Button>
			<Button
				variant="outline"
				size="sm"
				disabled={offset + limit >= total || loading}
				onclick={() => onPageChange(offset + limit)}
				class="h-8 gap-1 px-2.5 text-xs"
			>
				Next
				<ChevronRightIcon class="h-3.5 w-3.5" />
			</Button>
		</div>
	</div>
</Card.Root>

<!-- Inspection Dialog -->
<DnsLogDetailDialog
	bind:open={dialogOpen}
	entry={selectedRecord}
	onAddRewrite={(domain, target) => onAddRewrite(domain, target)}
/>
