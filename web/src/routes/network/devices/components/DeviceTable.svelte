<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import type { DeviceEntry } from "$lib/api/types";

	import WifiIcon from "@lucide/svelte/icons/wifi";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";

	let {
		devices = [],
		loading = false,
		onInspect = () => {},
		onWol = () => {},
		onPromote = () => {},
		onPurge = () => {},
	}: {
		devices?: DeviceEntry[];
		loading?: boolean;
		onInspect?: (dev: DeviceEntry) => void;
		onWol?: (mac: string) => void;
		onPromote?: (dev: DeviceEntry) => void;
		onPurge?: (mac: string) => void;
	} = $props();

	import DataTablePagination from "$lib/components/DataTablePagination.svelte";

	let pageIndex = $state(0);
	let pageSize = $state(15);

	$effect(() => {
		devices;
		pageIndex = 0;
	});

	const paginatedDevices = $derived(
		devices.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize)
	);

	function formatLastSeen(ts: string | number | undefined): string {
		if (!ts) return "—";
		let ms = typeof ts === "string" ? Date.parse(ts) : ts;
		if (isNaN(ms) || ms === 0) return "Never";
		if (ms < 10000000000) ms *= 1000;
		const secsAgo = Math.floor((Date.now() - ms) / 1000);
		if (secsAgo < 0 || secsAgo < 10) return "Just now";
		if (secsAgo < 60) return `${secsAgo}s ago`;
		const minsAgo = Math.floor(secsAgo / 60);
		if (minsAgo < 60) return `${minsAgo}m ago`;
		const hoursAgo = Math.floor(minsAgo / 60);
		if (hoursAgo < 24) return `${hoursAgo}h ago`;
		return `${Math.floor(hoursAgo / 24)}d ago`;
	}

	function copyText(text: string, label: string) {
		navigator.clipboard.writeText(text);
		toast.success(`Copied ${label}`);
	}
</script>

<Card.Root class="overflow-hidden">
	<Card.Content class="p-0">
		{#if loading}
			<div class="flex flex-col gap-3 p-4">
				{#each { length: 5 } as _, i (i)}
					<div class="flex items-center justify-between gap-4">
						<Skeleton class="h-5 w-28" />
						<Skeleton class="h-5 w-36" />
						<Skeleton class="h-5 w-20" />
						<Skeleton class="h-7 w-16 rounded-md" />
					</div>
				{/each}
			</div>
		{:else if devices.length === 0}
			<Empty.Root class="py-12">
				<Empty.Media>
					<WifiIcon class="size-8 text-muted-foreground/40" />
				</Empty.Media>
				<Empty.Title>No Devices Found</Empty.Title>
				<Empty.Description>
					No devices matched your search or status filter criteria.
				</Empty.Description>
			</Empty.Root>
		{:else}
			<!-- Mobile View (< sm): Touch-friendly stacked cards -->
			<div class="flex flex-col divide-y divide-border/60 sm:hidden">
				{#each paginatedDevices as dev (dev.mac)}
					<div class="p-3.5 flex flex-col gap-2.5 hover:bg-muted/20 transition-colors">
						<div class="flex items-center justify-between gap-2">
							<div class="flex items-center gap-2 min-w-0">
								<span
									class={[
										"size-2.5 rounded-full shrink-0",
										dev.online
											? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
											: "bg-zinc-600",
									].join(" ")}
								></span>
								<span class="text-sm font-semibold text-foreground truncate">
									{dev.hostname || "Unassigned Host"}
								</span>
							</div>

							<!-- Action Menu -->
							<DropdownMenu.Root>
								<DropdownMenu.Trigger
									class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors shrink-0"
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
									{#if dev.display_v4 || dev.v4?.ip}
										<DropdownMenu.Item onclick={() => copyText(dev.display_v4 || dev.v4?.ip || "", "IPv4")} class="gap-2">
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
						</div>

						<div class="flex items-center justify-between text-xs font-mono">
							<span class="text-muted-foreground">{dev.mac}</span>
							{#if dev.display_v4 || dev.v4?.ip}
								<span class="text-emerald-400 font-medium">{dev.display_v4 || dev.v4?.ip}</span>
							{/if}
						</div>

						{#if dev.display_v6 || dev.v6?.ip}
							<div class="text-[11px] font-mono text-sky-400 truncate">
								{dev.display_v6 || dev.v6?.ip}
							</div>
						{/if}

						<div class="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/40">
							<div class="flex items-center gap-1.5">
								{#if dev.learning_method}
									<Badge variant="outline" class="text-[9px] uppercase font-mono px-1.5 py-0">
										{dev.learning_method}
									</Badge>
								{/if}
								{#if dev.class}
									<Badge variant="secondary" class="text-[9px] capitalize px-1.5 py-0">
										{dev.class}
									</Badge>
								{/if}
							</div>
							<span>{formatLastSeen(dev.last_seen)}</span>
						</div>
					</div>
				{/each}
			</div>

			<!-- Desktop View (>= sm): Dense responsive table with horizontal scrolling -->
			<div class="hidden sm:block max-h-[600px] overflow-auto">
				<Table.Root class="min-w-[650px]">
					<Table.Header class="sticky top-0 z-10 bg-muted/90 backdrop-blur">
						<Table.Row class="hover:bg-transparent">
							<Table.Head class="w-[90px]">Status</Table.Head>
							<Table.Head>Host / MAC</Table.Head>
							<Table.Head>IP Address</Table.Head>
							<Table.Head>Discovery</Table.Head>
							<Table.Head>Last Seen</Table.Head>
							<Table.Head class="text-right w-[60px]">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body class="font-mono text-xs">
						{#each paginatedDevices as dev (dev.mac)}
							<Table.Row>
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
										<span class="text-muted-foreground font-mono text-[11px]">
											{dev.mac}
										</span>
									</div>
								</Table.Cell>

								<!-- IP Addresses -->
								<Table.Cell>
									<div class="flex flex-col gap-0.5">
										{#if dev.display_v4 || dev.v4?.ip}
											<span class="text-emerald-400 font-medium">
												{dev.display_v4 || dev.v4?.ip}
											</span>
										{/if}
										{#if dev.display_v6 || dev.v6?.ip}
											<span class="text-sky-400 text-[10px] truncate max-w-[200px]">
												{dev.display_v6 || dev.v6?.ip}
											</span>
										{/if}
										{#if !dev.display_v4 && !dev.v4?.ip && !dev.display_v6 && !dev.v6?.ip}
											<span class="text-muted-foreground font-sans text-xs">—</span>
										{/if}
									</div>
								</Table.Cell>

								<!-- Method & Class -->
								<Table.Cell class="font-sans">
									<div class="flex items-center gap-1.5">
										{#if dev.learning_method}
											<Badge variant="outline" class="text-[10px] uppercase font-mono px-2 py-0.5">
												{dev.learning_method}
											</Badge>
										{/if}
										{#if dev.class}
											<Badge variant="secondary" class="text-[10px] capitalize px-2 py-0.5">
												{dev.class}
											</Badge>
										{/if}
									</div>
								</Table.Cell>

								<!-- Last Seen -->
								<Table.Cell class="font-sans text-muted-foreground">
									{formatLastSeen(dev.last_seen)}
								</Table.Cell>

								<!-- Actions Dropdown -->
								<Table.Cell class="text-right font-sans">
									<DropdownMenu.Root>
										<DropdownMenu.Trigger
											class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
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
											{#if dev.display_v4 || dev.v4?.ip}
												<DropdownMenu.Item onclick={() => copyText(dev.display_v4 || dev.v4?.ip || "", "IPv4")} class="gap-2">
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
					</Table.Body>
				</Table.Root>
			</div>

			<DataTablePagination
				bind:pageIndex
				bind:pageSize
				totalItems={devices.length}
				itemName="devices"
			/>
		{/if}
	</Card.Content>
</Card.Root>
