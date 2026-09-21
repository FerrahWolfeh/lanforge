<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { toast } from "svelte-sonner";
	import type { HostConfigEntry } from "$lib/api/types";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	import ServerIcon from "@lucide/svelte/icons/server";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import FileDownIcon from "@lucide/svelte/icons/file-down";
	import FileUpIcon from "@lucide/svelte/icons/file-up";

	let {
		hosts = [],
		loading = false,
		onRefresh = () => {},
		onExport = () => {},
		onImport = () => {},
		onAdd = () => {},
		onEdit = () => {},
		onDelete = () => {},
	}: {
		hosts?: HostConfigEntry[];
		loading?: boolean;
		onRefresh?: () => void;
		onExport?: () => void;
		onImport?: (e: Event) => void;
		onAdd?: () => void;
		onEdit?: (host: HostConfigEntry) => void;
		onDelete?: (mac: string) => void;
	} = $props();

	let searchQuery = $state("");
	let pageIndex = $state(0);
	let pageSize = $state(15);

	$effect(() => {
		hosts;
		searchQuery;
		pageIndex = 0;
	});

	const filteredHosts = $derived(
		hosts.filter((h) => {
			if (!searchQuery.trim()) return true;
			const q = searchQuery.toLowerCase().trim();
			const macMatch = h.mac?.toLowerCase().includes(q);
			const hostMatch = h.hostname?.toLowerCase().includes(q);
			const v4Match = (h.v4_fixed || h.v4 || "").toLowerCase().includes(q);
			const v6Match = (h.v6_suffix || "").toLowerCase().includes(q);
			return macMatch || hostMatch || v4Match || v6Match;
		})
	);

	const paginatedHosts = $derived(
		filteredHosts.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize)
	);

	function copyText(text: string, label: string) {
		navigator.clipboard.writeText(text);
		toast.success(`Copied ${label}`);
	}
</script>

<DataTableCard
	title="Static Hosts & Overrides"
	icon={ServerIcon}
	total={filteredHosts.length}
	itemName="hosts"
	searchPlaceholder="Search hostname, MAC, or IP..."
	bind:searchQuery
	bind:pageIndex
	bind:pageSize
	pageSizeOptions={[10, 15, 25, 50]}
	{loading}
	columns={6}
	minTableWidth="min-w-[650px]"
	emptyMessage="No static host configurations found."
	emptyFilteredMessage="No static hosts match the search criteria."
>
	{#snippet actions()}
		<Button
			variant="outline"
			size="sm"
			onclick={onRefresh}
			disabled={loading}
			class="h-8 text-xs gap-1.5"
		>
			<RefreshCwIcon class="size-3.5 {loading ? 'animate-spin' : ''}" />
			<span class="hidden sm:inline">Refresh</span>
		</Button>

		<Button
			variant="outline"
			size="sm"
			onclick={onExport}
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
				onchange={onImport}
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
			onclick={onAdd}
			class="h-8 text-xs gap-1.5"
		>
			<PlusIcon class="size-3.5" />
			<span>Add Host</span>
		</Button>
	{/snippet}

	{#snippet emptyAction()}
		<Button
			size="sm"
			onclick={onAdd}
			class="h-8 text-xs gap-1.5"
		>
			<PlusIcon class="size-3.5" />
			<span>Add Host</span>
		</Button>
	{/snippet}

	{#snippet header()}
		<Table.Head>Hostname</Table.Head>
		<Table.Head>Target MAC</Table.Head>
		<Table.Head>Fixed IPv4</Table.Head>
		<Table.Head>IPv6 Suffix / Addr</Table.Head>
		<Table.Head>Origin</Table.Head>
		<Table.Head class="text-right w-[60px]">Actions</Table.Head>
	{/snippet}

	{#each paginatedHosts as host (host.mac)}
		<Table.Row class="hover:bg-muted/50 transition-colors font-mono text-xs">
			<!-- Hostname -->
			<Table.Cell class="font-sans font-semibold text-foreground text-xs sm:text-sm">
				<div class="flex items-center gap-1.5 flex-wrap">
					<span>{host.hostname || "—"}</span>
					{#if host.ignore_dns_log}
						<Badge variant="secondary" class="text-[9px] font-mono px-1 py-0 text-muted-foreground border-border/50">
							DNS Muted
						</Badge>
					{:else if host.ignored_log_domains && host.ignored_log_domains.length > 0}
						<Badge variant="outline" class="text-[9px] font-mono px-1 py-0 text-muted-foreground" title={host.ignored_log_domains.join(", ")}>
							{host.ignored_log_domains.length} {host.ignored_log_domains.length === 1 ? "domain" : "domains"} muted
						</Badge>
					{/if}
				</div>
			</Table.Cell>

			<!-- MAC -->
			<Table.Cell>
				<div class="flex items-center gap-1.5 text-muted-foreground">
					<span>{host.mac}</span>
					<button
						class="text-muted-foreground hover:text-foreground transition-colors p-0.5 cursor-pointer"
						onclick={() => copyText(host.mac, "MAC")}
						title="Copy MAC"
					>
						<CopyIcon class="size-3" />
					</button>
				</div>
			</Table.Cell>

			<!-- Fixed IPv4 -->
			<Table.Cell>
				{#if host.v4_fixed || host.v4}
					<div class="flex items-center gap-1.5">
						<span class="text-emerald-400 font-medium">{host.v4_fixed || host.v4}</span>
						<button
							class="text-muted-foreground hover:text-foreground transition-colors p-0.5 cursor-pointer"
							onclick={() => copyText(host.v4_fixed || host.v4 || "", "IPv4")}
							title="Copy IPv4"
						>
							<CopyIcon class="size-3" />
						</button>
					</div>
				{:else}
					<span class="text-muted-foreground">—</span>
				{/if}
			</Table.Cell>

			<!-- IPv6 Suffix -->
			<Table.Cell class="text-sky-400">
				{host.v6_suffix || "—"}
			</Table.Cell>

			<!-- Origin -->
			<Table.Cell class="font-sans">
				<Badge variant="outline" class="text-[10px] uppercase font-mono">
					{host.origin || "Config"}
				</Badge>
			</Table.Cell>

			<!-- Actions Dropdown -->
			<Table.Cell class="text-right font-sans">
				<DropdownMenu.Root>
					<DropdownMenu.Trigger
						class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
					>
						<MoreHorizontalIcon class="size-4" />
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="end" class="w-48 text-xs">
						<DropdownMenu.Item onclick={() => onEdit(host)} class="gap-2">
							<PencilIcon class="size-3.5 text-amber-400" />
							Edit Host Assignment
						</DropdownMenu.Item>
						<DropdownMenu.Separator />
						<DropdownMenu.Item onclick={() => copyText(host.mac, "MAC")} class="gap-2">
							<CopyIcon class="size-3.5 text-muted-foreground" />
							Copy MAC Address
						</DropdownMenu.Item>
						{#if host.v4_fixed || host.v4}
							<DropdownMenu.Item onclick={() => copyText(host.v4_fixed || host.v4 || "", "Fixed IPv4")} class="gap-2">
								<CopyIcon class="size-3.5 text-muted-foreground" />
								Copy Fixed IPv4
							</DropdownMenu.Item>
						{/if}
						<DropdownMenu.Separator />
						<DropdownMenu.Item onclick={() => onDelete(host.mac)} class="gap-2 text-rose-500">
							<Trash2Icon class="size-3.5" />
							Delete Static Host
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>
