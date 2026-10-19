<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { formatTimeAgo as formatLastSeen, copyToClipboard as copyText } from "$lib/utils";
	import type { DeviceEntry } from "$lib/api/types";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	import WifiIcon from "@lucide/svelte/icons/wifi";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	let {
		devices = [],
		totalCount,
		onlineCount,
		loading = false,
		scanning = false,
		onRefresh = () => {},
		onScan = () => {},
		onInspect = () => {},
		onWol = () => {},
		onPromote = () => {},
		onPurge = () => {},
	}: {
		devices?: DeviceEntry[];
		totalCount?: number;
		onlineCount?: number;
		loading?: boolean;
		scanning?: boolean;
		onRefresh?: () => void;
		onScan?: () => void;
		onInspect?: (dev: DeviceEntry) => void;
		onWol?: (mac: string) => void;
		onPromote?: (dev: DeviceEntry) => void;
		onPurge?: (mac: string) => void;
	} = $props();

	let searchQuery = $state("");
	let statusFilter = $state<"all" | "online" | "offline">("all");
	let pageIndex = $state(0);
	let pageSize = $state(15);

	$effect(() => {
		devices;
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
</script>

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
						? "bg-background text-foreground shadow-xs"
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
						? "bg-background text-emerald-400 shadow-xs"
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
						? "bg-background text-rose-400 shadow-xs"
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
		<Button
			size="sm"
			onclick={onScan}
			disabled={scanning}
			class="h-8 text-xs gap-1.5"
		>
			{#if scanning}
				<span class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
			{:else}
				<ZapIcon class="size-3.5 text-amber-300" />
			{/if}
			<span>Scan Network</span>
		</Button>
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
		<Table.Row class="hover:bg-muted/50 transition-colors font-mono text-xs">
			<!-- Status -->
			<Table.Cell class="font-sans">
				<div class="flex items-center gap-2">
					<span
						class={[
							"size-2 rounded-full shrink-0",
							dev.online
								? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
								: "bg-zinc-600",
						].join(" ")}
					></span>
					<span class="text-[11px] font-medium capitalize">
						{dev.online ? "Online" : "Offline"}
					</span>
				</div>
			</Table.Cell>

			<!-- Hostname & MAC -->
			<Table.Cell class="font-sans">
				<div class="flex flex-col">
					<span class="text-foreground text-xs sm:text-sm font-semibold tracking-tight">
						{dev.hostname || "Unassigned Host"}
					</span>
					<div class="flex items-center gap-1.5 text-muted-foreground font-mono text-[11px]">
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
							<span class="text-emerald-400 font-medium">
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
						<span class="text-sky-400 text-[10px] truncate max-w-[200px]">
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
						<Badge variant="outline" class="text-[10px] uppercase font-mono px-1.5 py-0">
							{dev.learning_method}
						</Badge>
					{/if}
					{#if dev.class}
						<Badge variant="secondary" class="text-[10px] capitalize px-1.5 py-0">
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
				<DropdownMenu.Root>
					<DropdownMenu.Trigger
						class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
					>
						<MoreHorizontalIcon class="size-4" />
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="end" class="w-48 text-xs">
						<DropdownMenu.Item onclick={() => onInspect(dev)} class="gap-2">
							<SearchIcon class="size-3.5 text-sky-400" />
							Inspect Details (Whois)
						</DropdownMenu.Item>
						<DropdownMenu.Item onclick={() => onWol(dev.mac)} class="gap-2">
							<ZapIcon class="size-3.5 text-emerald-400" />
							Send Wake-on-LAN
						</DropdownMenu.Item>
						<DropdownMenu.Item onclick={() => onPromote(dev)} class="gap-2">
							<BookmarkIcon class="size-3.5 text-amber-400" />
							Promote to Static Host
						</DropdownMenu.Item>
						<DropdownMenu.Separator />
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
						<DropdownMenu.Separator />
						<DropdownMenu.Item onclick={() => onPurge(dev.mac)} class="gap-2 text-rose-500">
							<Trash2Icon class="size-3.5" />
							Purge Endpoint
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>
