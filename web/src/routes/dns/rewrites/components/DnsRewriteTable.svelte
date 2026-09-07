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
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SearchCodeIcon from "@lucide/svelte/icons/search-code";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import ServerIcon from "@lucide/svelte/icons/server";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import { toast } from "svelte-sonner";
	import { dnsQuery, dnsRewriteRemove } from "$lib/api/client";
	import {
		type RewriteRule,
		type DnsRecordType,
		formatRewriteAnswer,
	} from "$lib/api/types";

	let {
		loading = false,
		rules = [],
		searchQuery = "",
		selectedType = "",
		limit = 50,
		offset = 0,
		onSearchChange = (q: string) => {},
		onTypeChange = (type: string) => {},
		onPageChange = (newOffset: number) => {},
		onEditRule = (rule: RewriteRule) => {},
		onRuleDeleted = () => {},
	}: {
		loading?: boolean;
		rules?: RewriteRule[];
		searchQuery?: string;
		selectedType?: string;
		limit?: number;
		offset?: number;
		onSearchChange?: (q: string) => void;
		onTypeChange?: (type: string) => void;
		onPageChange?: (newOffset: number) => void;
		onEditRule?: (rule: RewriteRule) => void;
		onRuleDeleted?: () => void;
	} = $props();

	let copiedItem = $state<string | null>(null);

	const RECORD_TYPES: DnsRecordType[] = [
		"A",
		"AAAA",
		"DEVICE",
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
		DEVICE: "bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20",
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

	async function handleTestResolution(rule: RewriteRule) {
		const dom = cleanDomain(rule.domain);
		try {
			const res = await dnsQuery(dom, rule.rtype);
			toast.success(`Resolution test for ${dom}: ${JSON.stringify(res)}`);
		} catch (err: any) {
			toast.error(err?.message ?? `Failed resolution test for ${dom}`);
		}
	}

	async function handleDelete(rule: RewriteRule) {
		if (!rule.id) return;
		try {
			await dnsRewriteRemove(rule.id);
			toast.success(
				`Removed rewrite rule for ${cleanDomain(rule.domain)}`,
			);
			onRuleDeleted();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to delete rewrite rule");
		}
	}

	// Filter rules client side
	const filteredRules = $derived.by(() => {
		let list = rules;
		if (searchQuery.trim()) {
			const q = searchQuery.trim().toLowerCase();
			list = list.filter(
				(r) =>
					r.domain.toLowerCase().includes(q) ||
					formatRewriteAnswer(r.answer).toLowerCase().includes(q),
			);
		}
		if (selectedType) {
			list = list.filter((r) => r.rtype === selectedType);
		}
		return list;
	});

	const total = $derived(filteredRules.length);
	const paginatedRules = $derived(
		filteredRules.slice(offset, offset + limit),
	);

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
					<ArrowRightLeftIcon class="h-4 w-4 text-primary" />
					Configured DNS Rewrite Rules
				</Card.Title>
				<Card.Description class="text-xs">
					Showing {startItem}–{endItem} of {total.toLocaleString()} configured
					rules
				</Card.Description>
			</div>

			<!-- Search & Type Filter Controls Toolbar -->
			<div class="flex flex-wrap items-center gap-2">
				<div class="relative w-full sm:w-64">
					<SearchIcon
						class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground"
					/>
					<Input
						type="text"
						placeholder="Search domain or answer target..."
						class="pl-9 h-9 text-xs"
						value={searchQuery}
						oninput={(e: Event) =>
							onSearchChange(
								(e.target as HTMLInputElement).value,
							)}
					/>
				</div>

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
	<Card.Content class="p-0 flex-1 min-h-0 overflow-y-auto relative">
		<Table.Root>
			<Table.Header
				class="sticky top-0 z-10 bg-card/95 backdrop-blur-md border-b shadow-xs"
			>
				<Table.Row class="hover:bg-transparent">
					<Table.Head class="w-[260px]">Domain / Pattern</Table.Head>
					<Table.Head class="w-[90px]">Type</Table.Head>
					<Table.Head>Target / Answer</Table.Head>
					<Table.Head class="w-[60px] text-right">Actions</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#if loading}
					{#each Array(6) as _}
						<Table.Row>
							<Table.Cell
								><Skeleton class="h-4 w-48" /></Table.Cell
							>
							<Table.Cell
								><Skeleton
									class="h-5 w-10 rounded-full"
								/></Table.Cell
							>
							<Table.Cell
								><Skeleton class="h-4 w-64" /></Table.Cell
							>
							<Table.Cell
								><Skeleton
									class="h-4 w-6 ml-auto"
								/></Table.Cell
							>
						</Table.Row>
					{/each}
				{:else if paginatedRules.length === 0}
					<Table.Row>
						<Table.Cell
							colspan={4}
							class="h-48 text-center text-muted-foreground text-sm"
						>
							{#if searchQuery || selectedType}
								No rewrite rules match the active filter
								criteria.
							{:else}
								No DNS rewrite rules have been configured yet.
							{/if}
						</Table.Cell>
					</Table.Row>
				{:else}
					{#each paginatedRules as rule, i (`${rule.id}-${rule.domain}-${rule.rtype}-${i}`)}
						{@const domainClean = cleanDomain(rule.domain)}
						{@const ans = formatRewriteAnswer(rule.answer)}
						{@const style =
							typeVariants[rule.rtype] ||
							"bg-secondary text-secondary-foreground border-border"}
						{@const isDevice = ans.startsWith("dev:") || rule.rtype === "DEVICE"}
						{@const isService =
							ans.startsWith("srv:") || rule.rtype === "SRV"}

						<Table.Row
							class="hover:bg-muted/50 transition-colors cursor-pointer group"
							onclick={() => onEditRule(rule)}
						>
							<!-- Domain Pattern -->
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
												"domain pattern",
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

							<!-- Record Type Badge -->
							<Table.Cell>
								<Badge
									variant="outline"
									class="px-2 py-0.5 text-[11px] font-mono border font-semibold {style}"
									title={rule.rtype === "DEVICE"
										? "Dynamic Dual-Stack A / AAAA Device Binding"
										: rule.rtype}
								>
									{rule.rtype}
								</Badge>
							</Table.Cell>

							<!-- Target / Answer Column -->
							<Table.Cell
								class="font-mono text-xs text-muted-foreground"
							>
								<div class="flex items-center gap-2 flex-wrap">
									{#if isDevice}
										<div
											class="flex items-center gap-1.5 min-w-0"
										>
											<Badge
												variant="outline"
												class="bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20 text-[11px] font-mono gap-1 shrink-0"
											>
												<LaptopIcon class="h-3 w-3" />
												dev:
											</Badge>
											<span
												class="truncate max-w-[220px] text-foreground font-mono font-medium"
											>
												{ans.slice(4)}
											</span>
										</div>
									{:else if isService}
										<div
											class="flex items-center gap-1.5 min-w-0"
										>
											<Badge
												variant="outline"
												class="bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20 text-[11px] font-mono gap-1 shrink-0"
											>
												<ServerIcon class="h-3 w-3" />
												srv:
											</Badge>
											<span
												class="truncate max-w-[220px] text-foreground font-mono font-medium"
											>
												{ans.startsWith("srv:")
													? ans.slice(4)
													: ans}
											</span>
										</div>
									{:else}
										<div
											class="flex items-center gap-1.5 min-w-0"
										>
											<GlobeIcon
												class="h-3.5 w-3.5 text-muted-foreground shrink-0"
											/>
											<span
												class="truncate max-w-[260px] text-foreground font-mono"
												title={ans}
											>
												{ans}
											</span>
											<button
												type="button"
												onclick={(e) => {
													e.stopPropagation();
													copyToClipboard(
														ans,
														"target answer",
													);
												}}
												class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
												title="Copy answer"
											>
												{#if copiedItem === ans}
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
									{/if}

									{#if rule.resolved_ips && rule.resolved_ips.length > 0}
										<span
											class="inline-flex items-center gap-1 text-[11px] text-emerald-500 bg-emerald-500/10 border border-emerald-500/20 px-1.5 py-0.5 rounded font-mono font-medium"
											title={rule.resolved_ips.join(", ")}
										>
											● {rule.resolved_ips[0]}
										</span>
									{/if}
								</div>
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
											onclick={() => onEditRule(rule)}
											class="gap-2"
										>
											<PencilIcon
												class="h-3.5 w-3.5 text-primary"
											/>
											Edit Rule
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() =>
												copyToClipboard(
													domainClean,
													"domain pattern",
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
													ans,
													"target answer",
												)}
											class="gap-2"
										>
											<CopyIcon
												class="h-3.5 w-3.5 text-muted-foreground"
											/>
											Copy Target
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() =>
												handleTestResolution(rule)}
											class="gap-2 text-blue-500"
										>
											<SearchCodeIcon
												class="h-3.5 w-3.5"
											/>
											Test Resolution
										</DropdownMenu.Item>
										<DropdownMenu.Separator />
										<DropdownMenu.Item
											onclick={() => handleDelete(rule)}
											class="gap-2 text-rose-500"
										>
											<Trash2Icon class="h-3.5 w-3.5" />
											Delete Rule
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
