<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { formatTimeAgo as formatLastSeen, copyToClipboard as copyText } from "$lib/utils";
	import type { DeviceEntry } from "$lib/api/types";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	import WifiIcon from "@lucide/svelte/icons/wifi";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import { goto } from "$app/navigation";

	let {
		devices = [],
		totalCount,
		onlineCount,
		loading = false,
		scanning = false,
		onRefresh = () => {},
		// An action left out is hidden: the page passes only what the session may do.
		onScan,
		onWol,
		onPurge,
	}: {
		devices?: DeviceEntry[];
		totalCount?: number;
		onlineCount?: number;
		loading?: boolean;
		scanning?: boolean;
		onRefresh?: () => void;
		onScan?: () => void;
		onWol?: (mac: string) => void;
		onPurge?: (mac: string) => void;
	} = $props();

	const pageOf = (dev: DeviceEntry) => `/network/devices/${encodeURIComponent(dev.mac)}`;

	let searchQuery = $state("");
	let statusFilter = $state<"all" | "online" | "offline">("all");
	let pageIndex = $state(0);
	let pageSize = $state(15);

	// A filter change starts over at page 1. Live updates of the list must not move
	// the page, or a refresh every few seconds throws the reader back to page 1.
	$effect(() => {
		searchQuery;
		statusFilter;
		pageIndex = 0;
	});

	const totalDevices = $derived(totalCount ?? devices.length);
	const onlineDevices = $derived(
		onlineCount ?? devices.filter((d) => d.online).length
	);
	const offlineDevices = $derived(Math.max(0, totalDevices - onlineDevices));

	const filteredDevices = $derived(
		devices.filter((dev) => {
			if (statusFilter === "online" && !dev.online) return false;
			if (statusFilter === "offline" && dev.online) return false;
			if (!searchQuery.trim()) return true;
			const q = searchQuery.toLowerCase().trim();
			const macMatch = dev.mac?.toLowerCase().includes(q);
			const hostMatch = dev.hostname?.toLowerCase().includes(q);
			const v4Match = (dev.primary_v4 || dev.v4?.ip || "")
				.toLowerCase()
				.includes(q);
			const v6Match = (dev.primary_v6 || dev.v6?.ip || "")
				.toLowerCase()
				.includes(q);
			return macMatch || hostMatch || v4Match || v6Match;
		})
	);

	const paginatedDevices = $derived(
		filteredDevices.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize)
	);

	// Keep the page in range when the list shrinks under it.
	$effect(() => {
		const lastPage = Math.max(0, Math.ceil(filteredDevices.length / pageSize) - 1);
		if (pageIndex > lastPage) pageIndex = lastPage;
	});
</script>

{#snippet actionsMenu(dev: DeviceEntry)}
	<DropdownMenu.Root>
		<DropdownMenu.Trigger
			class="h-7 w-7 max-md:size-9 shrink-0 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
		>
			<MoreHorizontalIcon class="size-4" />
		</DropdownMenu.Trigger>
		<DropdownMenu.Content align="end" class="w-48 text-xs">
			{#if onWol}
			<DropdownMenu.Item onclick={() => onWol(dev.mac)} class="gap-2">
				<ZapIcon class="size-3.5 text-muted-foreground" />
				Send Wake-on-LAN
			</DropdownMenu.Item>
			{/if}
			{#if onWol}
			<DropdownMenu.Separator />
			{/if}
			<DropdownMenu.Item onclick={() => copyText(dev.mac, "MAC")} class="gap-2">
				<CopyIcon class="size-3.5 text-muted-foreground" />
				Copy MAC Address
			</DropdownMenu.Item>
			{#if dev.primary_v4 || dev.v4?.ip}
				<DropdownMenu.Item onclick={() => copyText(dev.primary_v4 || dev.v4?.ip || "", "IPv4")} class="gap-2">
					<CopyIcon class="size-3.5 text-muted-foreground" />
					Copy IPv4 Address
				</DropdownMenu.Item>
			{/if}
			{#if onPurge}
			<DropdownMenu.Separator />
			<DropdownMenu.Item onclick={() => onPurge(dev.mac)} class="gap-2 text-danger">
				<Trash2Icon class="size-3.5" />
				Forget device
			</DropdownMenu.Item>
			{/if}
		</DropdownMenu.Content>
	</DropdownMenu.Root>
{/snippet}

<DataTableCard
	title="Network Devices"
	icon={WifiIcon}
	total={filteredDevices.length}
	itemName="devices"
	searchPlaceholder="Search hostname, MAC, or IP..."
	bind:searchQuery
	bind:pageIndex
	bind:pageSize
	pageSizeOptions={[10, 15, 25, 50]}
	{loading}
	columns={6}
	minTableWidth="min-w-[680px]"
	emptyMessage="No network devices discovered."
	emptyFilteredMessage="No devices matched your search or status filter criteria."
>
	{#snippet filters()}
		<div class="flex items-center gap-1 rounded-lg border border-border/80 bg-muted/40 p-0.5 text-xs">
			<button
				class={[
					"rounded px-2.5 py-1 text-xs font-medium transition-colors",
					statusFilter === "all"
						? "bg-background text-foreground"
						: "text-muted-foreground hover:text-foreground",
				].join(" ")}
				onclick={() => (statusFilter = "all")}
			>
				All ({totalDevices})
			</button>
			<button
				class={[
					"rounded px-2.5 py-1 text-xs font-medium transition-colors",
					statusFilter === "online"
						? "bg-background text-success"
						: "text-muted-foreground hover:text-foreground",
				].join(" ")}
				onclick={() => (statusFilter = "online")}
			>
				Online ({onlineDevices})
			</button>
			<button
				class={[
					"rounded px-2.5 py-1 text-xs font-medium transition-colors",
					statusFilter === "offline"
						? "bg-background text-danger"
						: "text-muted-foreground hover:text-foreground",
				].join(" ")}
				onclick={() => (statusFilter = "offline")}
			>
				Offline ({offlineDevices})
			</button>
		</div>
	{/snippet}

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
		{#if onScan}
		<Button
			size="sm"
			onclick={onScan}
			disabled={scanning}
			aria-label="Scan Network"
			title="Scan Network"
			class="h-8 text-xs gap-1.5"
		>
			{#if scanning}
				<span class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
			{:else}
				<ZapIcon class="size-3.5" />
			{/if}
			<span class="hidden sm:inline">Scan Network</span>
		</Button>
		{/if}
	{/snippet}

	{#snippet mobile()}
		{#each paginatedDevices as dev (dev.mac)}
			{@const v4 = dev.primary_v4 || dev.v4?.ip}
			{@const v6 = dev.primary_v6 || dev.v6?.ip}
			<div class="flex items-start gap-2 px-4 py-3">
				<span
					class={[
						"mt-1.5 size-2 rounded-full shrink-0",
						dev.online
							? "bg-success"
							: "bg-muted-foreground",
					].join(" ")}
					title={dev.online ? "Online" : "Offline"}
				></span>
				<a
					class="flex flex-1 min-w-0 flex-col gap-0.5 text-left"
					href={pageOf(dev)}
				>
					<span class="flex items-baseline justify-between gap-2">
						<span class="truncate text-sm font-semibold tracking-tight text-foreground">
							{dev.hostname || "Unassigned Host"}
						</span>
						<span class="shrink-0 text-xs text-muted-foreground">
							{formatLastSeen(dev.last_seen)}
						</span>
					</span>
					{#if v4}
						<span class="truncate font-mono text-xs text-foreground">{v4}</span>
					{/if}
					{#if v6}
						<span class="truncate font-mono text-xs text-muted-foreground">{v6}</span>
					{/if}
					<span class="flex items-center gap-1.5 flex-wrap font-mono text-xs text-muted-foreground">
						{dev.mac}
						{#if dev.learning_method}
							<Badge variant="outline" class="text-xs uppercase px-1.5 py-0">
								{dev.learning_method}
							</Badge>
						{/if}
					</span>
				</a>
				{@render actionsMenu(dev)}
			</div>
		{/each}
	{/snippet}

	{#snippet header()}
		<Table.Head class="w-[90px]">Status</Table.Head>
		<Table.Head>Host / MAC</Table.Head>
		<Table.Head>IP Address</Table.Head>
		<Table.Head>Discovery</Table.Head>
		<Table.Head>Last Seen</Table.Head>
		<Table.Head class="text-right w-[60px]">Actions</Table.Head>
	{/snippet}

	{#each paginatedDevices as dev (dev.mac)}
		<Table.Row
			class="hover:bg-muted/50 transition-colors font-mono text-xs cursor-pointer"
			onclick={(e: MouseEvent) => {
				// Buttons and menus in the row keep their own action.
				if ((e.target as HTMLElement).closest("button, a, [role='menu']")) return;
				goto(pageOf(dev));
			}}
		>
			<!-- Status -->
			<Table.Cell class="font-sans">
				<div class="flex items-center gap-2">
					<span
						class={[
							"size-2 rounded-full shrink-0",
							dev.online
								? "bg-success"
								: "bg-muted-foreground",
						].join(" ")}
					></span>
					<span class="text-xs font-medium capitalize">
						{dev.online ? "Online" : "Offline"}
					</span>
				</div>
			</Table.Cell>

			<!-- Hostname & MAC -->
			<Table.Cell class="font-sans">
				<div class="flex flex-col">
					<a href={pageOf(dev)} class="text-foreground text-xs sm:text-sm font-semibold tracking-tight hover:underline">
						{dev.hostname || "Unassigned Host"}
					</a>
					<div class="flex items-center gap-1.5 text-muted-foreground font-mono text-xs">
						<span>{dev.mac}</span>
						<button
							class="text-muted-foreground hover:text-foreground transition-colors p-0.5 cursor-pointer"
							onclick={() => copyText(dev.mac, "MAC")}
							title="Copy MAC"
						>
							<CopyIcon class="size-2.5" />
						</button>
					</div>
				</div>
			</Table.Cell>

			<!-- IP Addresses -->
			<Table.Cell>
				<div class="flex flex-col gap-0.5">
					{#if dev.primary_v4 || dev.v4?.ip}
						<div class="flex items-center gap-1">
							<span class="text-foreground font-medium">
								{dev.primary_v4 || dev.v4?.ip}
							</span>
							<button
								class="text-muted-foreground hover:text-foreground transition-colors p-0.5 cursor-pointer"
								onclick={() => copyText(dev.primary_v4 || dev.v4?.ip || "", "IPv4")}
								title="Copy IPv4"
							>
								<CopyIcon class="size-2.5" />
							</button>
						</div>
					{/if}
					{#if dev.primary_v6 || dev.v6?.ip}
						<span class="text-muted-foreground text-xs truncate max-w-[200px]">
							{dev.primary_v6 || dev.v6?.ip}
						</span>
					{/if}
					{#if !dev.primary_v4 && !dev.v4?.ip && !dev.primary_v6 && !dev.v6?.ip}
						<span class="text-muted-foreground font-sans text-xs">—</span>
					{/if}
				</div>
			</Table.Cell>

			<!-- Method & Class -->
			<Table.Cell class="font-sans">
				<div class="flex items-center gap-1.5 flex-wrap">
					{#if dev.learning_method}
						<Badge variant="outline" class="text-xs uppercase font-mono px-1.5 py-0">
							{dev.learning_method}
						</Badge>
					{/if}
					{#if dev.class}
						<Badge variant="secondary" class="text-xs capitalize px-1.5 py-0">
							{dev.class}
						</Badge>
					{/if}
				</div>
			</Table.Cell>

			<!-- Last Seen -->
			<Table.Cell class="font-sans text-muted-foreground text-xs">
				{formatLastSeen(dev.last_seen)}
			</Table.Cell>

			<!-- Actions Dropdown -->
			<Table.Cell class="text-right font-sans">
				{@render actionsMenu(dev)}
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>
