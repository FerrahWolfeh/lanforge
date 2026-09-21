<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { toast } from "svelte-sonner";
	import type { TransientHostEntry } from "$lib/api/types";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	import RadioIcon from "@lucide/svelte/icons/radio";
	import BookmarkPlusIcon from "@lucide/svelte/icons/bookmark-plus";
	import CopyIcon from "@lucide/svelte/icons/copy";

	let {
		hosts = [],
		loading = false,
		onPromote = () => {},
	}: {
		hosts?: TransientHostEntry[];
		loading?: boolean;
		onPromote?: (host: TransientHostEntry) => void;
	} = $props();

	function formatTimeAgo(epochSecs: number): string {
		if (!epochSecs || epochSecs === 0) return "—";
		const secsAgo = Math.floor(Date.now() / 1000 - epochSecs);
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

<DataTableCard
	title="Dynamically Discovered Transient Hosts"
	icon={RadioIcon}
	description="Unregistered endpoints resolved via mDNS queries, reverse DNS PTR sweeps, or NetBIOS announcement packets."
	total={hosts.length}
	itemName="transient hosts"
	showSearch={false}
	showPagination={false}
	containerHeight="h-auto"
	minTableWidth="min-w-[550px]"
	columns={5}
	{loading}
	isEmpty={hosts.length === 0}
	emptyMessage="All active devices on your LAN currently match known DHCP leases or static configurations."
>
	{#snippet titleExtra()}
		<Badge variant="outline" class="font-mono text-xs">
			{hosts.length} active
		</Badge>
	{/snippet}

	{#snippet header()}
		<Table.Head>Resolved Hostname</Table.Head>
		<Table.Head>IP Address</Table.Head>
		<Table.Head>Discovery Origin</Table.Head>
		<Table.Head>Last Seen</Table.Head>
		<Table.Head class="text-right w-[120px]">Actions</Table.Head>
	{/snippet}

	{#each hosts as h (h.ip + h.hostname)}
		<Table.Row class="hover:bg-muted/50 transition-colors font-mono text-xs">
			<!-- Hostname -->
			<Table.Cell class="font-sans font-semibold text-foreground text-xs sm:text-sm">
				{h.hostname || "—"}
			</Table.Cell>

			<!-- IP Address -->
			<Table.Cell>
				<div class="flex items-center gap-1.5">
					<span class="text-emerald-400 font-medium">{h.ip}</span>
					<button
						class="text-muted-foreground hover:text-foreground transition-colors p-0.5 cursor-pointer"
						onclick={() => copyText(h.ip, "IP")}
						title="Copy IP"
					>
						<CopyIcon class="size-3" />
					</button>
				</div>
			</Table.Cell>

			<!-- Origin -->
			<Table.Cell class="font-sans">
				<Badge variant="secondary" class="text-[10px] uppercase font-mono px-2 py-0.5">
					{h.origin}
				</Badge>
			</Table.Cell>

			<!-- Last Seen -->
			<Table.Cell class="font-sans text-muted-foreground">
				{formatTimeAgo(h.last_seen)}
			</Table.Cell>

			<!-- Action -->
			<Table.Cell class="text-right font-sans">
				<Button
					variant="outline"
					size="sm"
					class="h-7 text-xs gap-1 px-2.5 text-amber-400 hover:text-amber-300 cursor-pointer"
					onclick={() => onPromote(h)}
				>
					<BookmarkPlusIcon class="size-3" />
					<span>Promote</span>
				</Button>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>
