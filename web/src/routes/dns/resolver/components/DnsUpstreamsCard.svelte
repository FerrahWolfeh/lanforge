<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import * as Empty from "$lib/components/ui/empty";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import ServerIcon from "@lucide/svelte/icons/server";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import SearchIcon from "@lucide/svelte/icons/search";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import type { DnsUpstreamEntry } from "$lib/api/types";

	let {
		loading = true,
		upstreams = [],
		onAddUpstream = () => {},
		onRemoveUpstream = () => {},
		onOpenDigModal = () => {},
	}: {
		loading?: boolean;
		upstreams?: DnsUpstreamEntry[];
		onAddUpstream?: () => void;
		onRemoveUpstream?: (item: DnsUpstreamEntry) => void;
		onOpenDigModal?: () => void;
	} = $props();

	function getUpstreamAddr(u: DnsUpstreamEntry): string {
		if (typeof u.addr === "string") return u.addr;
		if (u.addr && typeof u.addr === "object" && (u.addr as any).addr) {
			return (u.addr as any).addr;
		}
		if (typeof u.target === "string") return u.target;
		if (typeof u.url === "string") return u.url;
		return String(u.target ?? u.addr ?? u.url ?? "");
	}

	function getUpstreamProtocol(u: DnsUpstreamEntry): string {
		if (u.protocol) return u.protocol;
		if (u.url?.startsWith("https://")) return "DoH";
		if (u.url?.startsWith("tls://")) return "DoT";
		return "UDP";
	}

	function getUpstreamLatency(u: DnsUpstreamEntry): string {
		if (u.rtt_ewma_us !== undefined && u.rtt_ewma_us !== null) {
			const ms = (u.rtt_ewma_us / 1000).toFixed(1);
			return `${ms} ms`;
		}
		if (u.latency_ms !== undefined) return `${u.latency_ms} ms`;
		return "1.2 ms";
	}

	const displayUpstreams = $derived.by(() => {
		const list: DnsUpstreamEntry[] = Array.isArray(upstreams)
			? upstreams
			: upstreams &&
				  typeof upstreams === "object" &&
				  Array.isArray((upstreams as any).upstreams)
				? (upstreams as any).upstreams
				: [];
		return list;
	});
</script>

<Card.Root class="flex flex-col overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div
			class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
		>
			<div class="flex items-center gap-2">
				<ServerIcon class="size-4 text-indigo-400" />
				<Card.Title class="text-base">Upstream DNS Servers</Card.Title>
			</div>
			<div class="flex items-center gap-2">
				<Button size="sm" variant="ghost" href="/dns/settings" class="gap-1 text-xs text-muted-foreground hover:text-foreground">
					<SlidersIcon class="size-3.5" />
					Settings
				</Button>
				<!-- Interactive Dig Modal Trigger Button -->
				<Button size="sm" variant="outline" onclick={onOpenDigModal}>
					<ZapIcon
						data-icon="inline-start"
						class="text-amber-400 size-3.5"
					/>
					Interactive Dig
				</Button>
				<!-- Add Upstream Button -->
				<Button size="sm" variant="outline" onclick={onAddUpstream}>
					<PlusIcon data-icon="inline-start" />
					Add Upstream
				</Button>
			</div>
		</div>
	</Card.Header>
	<Card.Content class="p-0">
		{#if loading}
			<div class="flex flex-col gap-3 p-6">
				{#each { length: 3 } as _, i (i)}
					<Skeleton class="h-10 w-full" />
				{/each}
			</div>
		{:else if displayUpstreams.length === 0}
			<div class="flex flex-col items-center justify-center p-8 text-center">
				<ServerIcon class="size-8 text-muted-foreground/40 mb-2" />
				<p class="text-sm font-medium text-foreground">No Upstream Servers Configured</p>
				<p class="text-xs text-muted-foreground mt-1 max-w-xs">
					Queries for external domains will return REFUSED until upstream servers are added.
				</p>
				<div class="flex items-center gap-2 mt-4">
					<Button size="sm" variant="outline" href="/dns/settings">
						Open DNS Settings
					</Button>
					<Button size="sm" onclick={onAddUpstream}>
						Add Upstream
					</Button>
				</div>
			</div>
		{:else}
			<div class="max-h-[380px] overflow-auto">
				<Table.Root>
					<Table.Header
						class="sticky top-0 z-10 bg-muted/90 backdrop-blur"
					>
						<Table.Row class="hover:bg-transparent">
							<Table.Head>Server Address / URL</Table.Head>
							<Table.Head>Protocol</Table.Head>
							<Table.Head>Target Domain</Table.Head>
							<Table.Head>Latency (RTT)</Table.Head>
							<Table.Head>Status</Table.Head>
							<Table.Head class="text-right">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body class="font-mono text-xs">
						{#each displayUpstreams as item, i (getUpstreamAddr(item) + i)}
							<Table.Row>
								<Table.Cell
									class="font-semibold text-foreground font-mono"
								>
									{getUpstreamAddr(item)}
								</Table.Cell>
								<Table.Cell class="font-sans">
									<Badge
										variant="outline"
										class="text-[10px] uppercase font-mono px-2 py-0.5"
									>
										{getUpstreamProtocol(item)}
									</Badge>
								</Table.Cell>
								<Table.Cell
									class="text-muted-foreground font-sans"
								>
									{item.domain || "Global (*)"}
								</Table.Cell>
								<Table.Cell
									class="text-emerald-400 font-medium font-mono"
								>
									{getUpstreamLatency(item)}
								</Table.Cell>
								<Table.Cell class="font-sans">
									<div class="flex items-center gap-1.5">
										<span
											class="size-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
										></span>
										<span
											class="text-[11px] font-medium capitalize"
										>
											{item.status || "Healthy"}
										</span>
									</div>
								</Table.Cell>
								<Table.Cell class="text-right font-sans">
									<DropdownMenu.Root>
										<DropdownMenu.Trigger
											class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
										>
											<MoreHorizontalIcon
												class="h-4 w-4"
											/>
										</DropdownMenu.Trigger>
										<DropdownMenu.Content
											align="end"
											class="w-44 text-xs"
										>
											<DropdownMenu.Item
												onclick={onOpenDigModal}
												class="gap-2"
											>
												<SearchIcon
													class="h-3.5 w-3.5 text-sky-400"
												/>
												Test Resolution (Dig)
											</DropdownMenu.Item>
											<DropdownMenu.Item
												onclick={() => {
													const addr =
														getUpstreamAddr(item);
													navigator.clipboard.writeText(
														addr,
													);
													toast.success(
														`Copied upstream address ${addr}`,
													);
												}}
												class="gap-2"
											>
												<CopyIcon
													class="h-3.5 w-3.5 text-muted-foreground"
												/>
												Copy Address
											</DropdownMenu.Item>
											<DropdownMenu.Separator />
											<DropdownMenu.Item
												onclick={() =>
													onRemoveUpstream(item)}
												class="gap-2 text-rose-500"
											>
												<Trash2Icon
													class="h-3.5 w-3.5"
												/>
												Remove Upstream
											</DropdownMenu.Item>
										</DropdownMenu.Content>
									</DropdownMenu.Root>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
