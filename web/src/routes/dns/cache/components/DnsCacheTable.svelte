<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
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
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import { toast } from "svelte-sonner";
	import type { DnsCacheEntry, DnsRecordType } from "$lib/api/types";

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
	} = $props();

	let copiedItem = $state<string | null>(null);

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

	const currentPage = $derived(Math.floor(offset / limit) + 1);
	const totalPages = $derived(Math.max(1, Math.ceil(total / limit)));
	const startItem = $derived(total === 0 ? 0 : offset + 1);
	const endItem = $derived(Math.min(offset + limit, total));
</script>

<Card.Root>
	<Card.Header class="pb-3">
		<div
			class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
		>
			<div>
				<Card.Title
					class="text-base font-semibold flex items-center gap-2"
				>
					<DatabaseIcon class="h-4 w-4 text-primary" />
					Cached Records
				</Card.Title>
				<Card.Description class="text-xs">
					Showing {startItem}–{endItem} of {total.toLocaleString()} cached
					entries
				</Card.Description>
			</div>

			<!-- Search & Type Filter Toolbar -->
			<div class="flex flex-wrap items-center gap-2">
				<div class="relative w-full sm:w-64">
					<SearchIcon
						class="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground"
					/>
					<Input
						type="text"
						placeholder="Search domain or answer..."
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

	<Card.Content class="p-0">
		<div class="overflow-x-auto">
			<Table.Root>
				<Table.Header class="bg-muted/30">
					<Table.Row>
						<Table.Head class="w-[280px]">Domain Name</Table.Head>
						<Table.Head class="w-[90px]">Type</Table.Head>
						<Table.Head>Resolved Value / Target</Table.Head>
						<Table.Head class="w-[120px] text-right"
							>TTL / Expires</Table.Head
						>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#if loading}
						{#each Array(5) as _}
							<Table.Row>
								<Table.Cell
									><Skeleton class="h-4 w-48" /></Table.Cell
								>
								<Table.Cell
									><Skeleton
										class="h-5 w-12 rounded-full"
									/></Table.Cell
								>
								<Table.Cell
									><Skeleton class="h-4 w-64" /></Table.Cell
								>
								<Table.Cell class="text-right"
									><Skeleton
										class="h-4 w-16 ml-auto"
									/></Table.Cell
								>
							</Table.Row>
						{/each}
					{:else if entries.length === 0}
						<Table.Row>
							<Table.Cell
								colspan={4}
								class="h-32 text-center text-muted-foreground text-sm"
							>
								{#if searchQuery || selectedType}
									No cached records match the active filter.
								{:else}
									DNS cache is currently empty.
								{/if}
							</Table.Cell>
						</Table.Row>
					{:else}
						{#each entries as entry (entry.name + entry.kind + entry.data)}
							{@const style =
								typeVariants[entry.kind] ||
								"bg-secondary text-secondary-foreground border-border"}
							{@const isExpiringSoon = entry.expires_in_secs < 30}
							<Table.Row
								class="hover:bg-muted/40 transition-colors"
							>
								<!-- Domain Name -->
								<Table.Cell class="font-medium text-xs">
									<div
										class="flex items-center gap-1.5 group"
									>
										<span
											class="truncate max-w-[240px]"
											title={entry.name}
										>
											{entry.name}
										</span>
										<button
											type="button"
											onclick={() =>
												copyToClipboard(
													entry.name,
													"domain name",
												)}
											class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
											title="Copy domain"
										>
											{#if copiedItem === entry.name}
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
									<div
										class="flex items-center gap-1.5 group"
									>
										<span
											class="truncate max-w-[380px]"
											title={entry.data}
										>
											{entry.data}
										</span>
										<button
											type="button"
											onclick={() =>
												copyToClipboard(
													entry.data,
													"answer value",
												)}
											class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
											title="Copy resolved value"
										>
											{#if copiedItem === entry.data}
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

								<!-- TTL Expiration -->
								<Table.Cell
									class="text-right font-mono text-xs"
								>
									<span
										class={isExpiringSoon
											? "text-amber-600 dark:text-amber-400 font-semibold"
											: "text-muted-foreground"}
									>
										{formatTtl(entry.expires_in_secs)}
									</span>
								</Table.Cell>
							</Table.Row>
						{/each}
					{/if}
				</Table.Body>
			</Table.Root>
		</div>

		<!-- Pagination Footer -->
		{#if total > limit}
			<div class="flex items-center justify-between px-4 py-3 border-t">
				<p class="text-xs text-muted-foreground">
					Page {currentPage} of {totalPages}
				</p>
				<div class="flex items-center gap-1">
					<Button
						variant="outline"
						size="sm"
						disabled={offset === 0 || loading}
						onclick={() =>
							onPageChange(Math.max(0, offset - limit))}
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
		{/if}
	</Card.Content>
</Card.Root>
