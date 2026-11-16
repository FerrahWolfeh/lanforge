<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { toast } from "svelte-sonner";
	import type { LeaseEntry } from "$lib/api/types";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	import NetworkIcon from "@lucide/svelte/icons/network";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import BookmarkPlusIcon from "@lucide/svelte/icons/bookmark-plus";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";

	let {
		leases = [],
		loading = false,
		onRenew = () => {},
		onRelease = () => {},
		onPromote = () => {},
		onWol = () => {},
		canEdit = true,
	}: {
		leases?: LeaseEntry[];
		loading?: boolean;
		onRenew?: (lease: LeaseEntry) => void;
		onRelease?: (lease: LeaseEntry) => void;
		onPromote?: (lease: LeaseEntry) => void;
		onWol?: (mac: string) => void;
		/** False hides renew, promote, wake-on-LAN and release (no device_write). */
		canEdit?: boolean;
	} = $props();

	let searchQuery = $state("");
	let selectedKind = $state<"all" | "v4" | "v6" | "v6_prefix">("all");
	let pageIndex = $state(0);
	let pageSize = $state(15);

	// A filter change starts over at page 1. Live updates of the list must not move
	// the page, or a refresh every few seconds throws the reader back to page 1.
	$effect(() => {
		searchQuery;
		selectedKind;
		pageIndex = 0;
	});

	const v4Count = $derived(leases.filter((l) => l.kind === "v4").length);
	const v6Count = $derived(
		leases.filter((l) => l.kind === "v6" || l.kind === "v6_prefix").length
	);

	const filteredLeases = $derived(
		leases.filter((lease) => {
			if (selectedKind !== "all" && lease.kind !== selectedKind) {
				return false;
			}
			if (!searchQuery.trim()) return true;
			const q = searchQuery.toLowerCase().trim();
			return (
				lease.hostname.toLowerCase().includes(q) ||
				lease.mac.toLowerCase().includes(q) ||
				lease.address.toLowerCase().includes(q)
			);
		})
	);

	const paginatedLeases = $derived(
		filteredLeases.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize)
	);

	// Keep the page in range when the list shrinks under it.
	$effect(() => {
		const lastPage = Math.max(0, Math.ceil(filteredLeases.length / pageSize) - 1);
		if (pageIndex > lastPage) pageIndex = lastPage;
	});

	function formatDuration(secs: number): string {
		if (secs <= 0) return "Expired";
		if (secs < 60) return `${secs}s`;
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		if (m < 60) return `${m}m ${s}s`;
		const h = Math.floor(m / 60);
		const remM = m % 60;
		if (h < 24) return `${h}h ${remM}m`;
		const d = Math.floor(h / 24);
		const remH = h % 24;
		return `${d}d ${remH}h`;
	}

	function copyText(text: string, label: string) {
		navigator.clipboard.writeText(text);
		toast.success(`Copied ${label}`);
	}
</script>

{#snippet actionsMenu(lease: LeaseEntry)}
	<DropdownMenu.Root>
		<DropdownMenu.Trigger
			class="h-7 w-7 max-md:size-9 shrink-0 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
		>
			<MoreHorizontalIcon class="size-4" />
		</DropdownMenu.Trigger>
		<DropdownMenu.Content align="end" class="w-48 text-xs">
			{#if canEdit}
			<!-- Only DHCPv4 has a server-initiated renewal (FORCERENEW); DHCPv6 Reconfigure is not implemented. -->
			{#if lease.kind === "v4"}
				<DropdownMenu.Item onclick={() => onRenew(lease)} class="gap-2">
					<RotateCcwIcon class="size-3.5 text-muted-foreground" />
					Renew Lease
				</DropdownMenu.Item>
			{/if}
			{#if lease.kind !== "v6_prefix"}
				<DropdownMenu.Item onclick={() => onPromote(lease)} class="gap-2">
					<BookmarkPlusIcon class="size-3.5 text-muted-foreground" />
					Convert to Static Host
				</DropdownMenu.Item>
			{/if}
			<DropdownMenu.Item onclick={() => onWol(lease.mac)} class="gap-2">
				<ZapIcon class="size-3.5 text-muted-foreground" />
				Send Wake-on-LAN
			</DropdownMenu.Item>
			<DropdownMenu.Separator />
			{/if}
			<DropdownMenu.Item onclick={() => copyText(lease.mac, "MAC")} class="gap-2">
				<CopyIcon class="size-3.5 text-muted-foreground" />
				Copy MAC
			</DropdownMenu.Item>
			<DropdownMenu.Item onclick={() => copyText(lease.address, "IP")} class="gap-2">
				<CopyIcon class="size-3.5 text-muted-foreground" />
				Copy IP
			</DropdownMenu.Item>
			{#if canEdit}
			<DropdownMenu.Separator />
			<DropdownMenu.Item onclick={() => onRelease(lease)} class="gap-2 text-danger">
				<Trash2Icon class="size-3.5" />
				Release Lease
			</DropdownMenu.Item>
			{/if}
		</DropdownMenu.Content>
	</DropdownMenu.Root>
{/snippet}

<DataTableCard
	title="Active DHCP Leases"
	icon={NetworkIcon}
	total={filteredLeases.length}
	itemName="leases"
	searchPlaceholder="Search hostname, IP, MAC..."
	bind:searchQuery
	bind:pageIndex
	bind:pageSize
	pageSizeOptions={[10, 15, 25, 50]}
	{loading}
	columns={6}
	minTableWidth="min-w-[680px]"
	emptyMessage="No active dynamic DHCP leases found."
	emptyFilteredMessage="No leases match the active search or protocol filter."
>
	{#snippet filters()}
		<div class="flex items-center rounded-lg border border-border/80 bg-muted/40 p-0.5 text-xs">
			<button
				class={[
					"rounded px-2.5 py-1 text-xs font-medium transition-colors",
					selectedKind === "all"
						? "bg-selected text-selected-foreground"
						: "text-muted-foreground hover:text-foreground",
				].join(" ")}
				onclick={() => (selectedKind = "all")}
			>
				All ({leases.length})
			</button>
			<button
				class={[
					"rounded px-2.5 py-1 text-xs font-medium transition-colors",
					selectedKind === "v4"
						? "bg-selected text-selected-foreground"
						: "text-muted-foreground hover:text-foreground",
				].join(" ")}
				onclick={() => (selectedKind = "v4")}
			>
				IPv4 ({v4Count})
			</button>
			<button
				class={[
					"rounded px-2.5 py-1 text-xs font-medium transition-colors",
					selectedKind === "v6"
						? "bg-selected text-selected-foreground"
						: "text-muted-foreground hover:text-foreground",
				].join(" ")}
				onclick={() => (selectedKind = "v6")}
			>
				IPv6
			</button>
			<button
				class={[
					"rounded px-2.5 py-1 text-xs font-medium transition-colors",
					selectedKind === "v6_prefix"
						? "bg-selected text-selected-foreground"
						: "text-muted-foreground hover:text-foreground",
				].join(" ")}
				onclick={() => (selectedKind = "v6_prefix")}
			>
				Prefixes
			</button>
		</div>
	{/snippet}

	{#snippet mobile()}
		{#each paginatedLeases as lease (lease.mac + lease.address + lease.kind)}
			{@const isExpiring = lease.remaining_secs > 0 && lease.remaining_secs < 3600}
			{@const isExpired = lease.remaining_secs <= 0}
			<div class="flex items-start gap-2 px-4 py-3">
				<div class="flex flex-1 min-w-0 flex-col gap-0.5">
					<span class="flex items-baseline justify-between gap-2">
						<span class="truncate text-sm font-semibold tracking-tight text-foreground">
							{lease.hostname || "—"}
						</span>
						<span
							class={[
								"shrink-0 font-mono text-xs font-medium",
								isExpired ? "text-destructive" : isExpiring ? "text-warning" : "text-muted-foreground",
							].join(" ")}
						>
							{formatDuration(lease.remaining_secs)}
						</span>
					</span>
					<span
						class={[
							"truncate font-mono text-xs font-medium",
							"text-foreground",
						].join(" ")}
					>
						{lease.kind === "v6_prefix" ? `${lease.address}/64` : lease.address}
					</span>
					<span class="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
						{lease.mac}
						<Badge variant="outline" class="text-xs px-1.5 py-0">
							{lease.kind === "v4" ? "IPv4" : lease.kind === "v6" ? "IPv6" : "IA_PD"}
						</Badge>
					</span>
				</div>
				{@render actionsMenu(lease)}
			</div>
		{/each}
	{/snippet}

	{#snippet header()}
		<Table.Head>Hostname</Table.Head>
		<Table.Head>MAC Address</Table.Head>
		<Table.Head>Assigned Address</Table.Head>
		<Table.Head class="w-[90px]">Type</Table.Head>
		<Table.Head class="w-[160px]">Lifetime</Table.Head>
		<Table.Head class="w-[60px] text-right">Actions</Table.Head>
	{/snippet}

	{#each paginatedLeases as lease (lease.mac + lease.address + lease.kind)}
		{@const isExpiring = lease.remaining_secs > 0 && lease.remaining_secs < 3600}
		{@const isExpired = lease.remaining_secs <= 0}
		<Table.Row class="hover:bg-muted/50 transition-colors font-mono text-xs">
			<!-- Hostname -->
			<Table.Cell class="font-sans">
				<span class="font-semibold text-foreground text-xs sm:text-sm tracking-tight">
					{lease.hostname || "—"}
				</span>
			</Table.Cell>

			<!-- MAC Address -->
			<Table.Cell>
				<div class="flex items-center gap-1.5 text-muted-foreground">
					<span>{lease.mac}</span>
					<button
						class="text-muted-foreground hover:text-foreground transition-colors p-0.5 cursor-pointer"
						onclick={() => copyText(lease.mac, "MAC")}
						title="Copy MAC"
					>
						<CopyIcon class="size-3" />
					</button>
				</div>
			</Table.Cell>

			<!-- Assigned IP -->
			<Table.Cell>
				<div class="flex items-center gap-1.5">
					<span
						class={[
							"font-medium",
							"text-foreground",
						].join(" ")}
					>
						{lease.kind === "v6_prefix" ? `${lease.address}/64` : lease.address}
					</span>
					<button
						class="text-muted-foreground hover:text-foreground transition-colors p-0.5 cursor-pointer"
						onclick={() => copyText(lease.address, "IP")}
						title="Copy IP"
					>
						<CopyIcon class="size-3" />
					</button>
				</div>
			</Table.Cell>

			<!-- Type Badge -->
			<Table.Cell class="font-sans">
				{#if lease.kind === "v4"}
					<Badge variant="outline" class="font-mono text-xs text-muted-foreground border-muted-foreground/30">
						IPv4
					</Badge>
				{:else if lease.kind === "v6"}
					<Badge variant="outline" class="font-mono text-xs text-muted-foreground border-muted-foreground/30">
						IPv6
					</Badge>
				{:else}
					<Badge variant="outline" class="font-mono text-xs text-muted-foreground border-muted-foreground/30">
						IA_PD
					</Badge>
				{/if}
			</Table.Cell>

			<!-- Remaining Lifetime -->
			<Table.Cell class="font-sans">
				<span
					class={[
						"font-mono font-medium text-xs",
						isExpired ? "text-destructive" : isExpiring ? "text-warning" : "text-foreground",
					].join(" ")}
				>
					{formatDuration(lease.remaining_secs)}
				</span>
			</Table.Cell>

			<!-- Actions Dropdown -->
			<Table.Cell class="text-right font-sans">
				{@render actionsMenu(lease)}
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>
