<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import type { TransientHostEntry } from "$lib/api/types";

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

<Card.Root class="overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<RadioIcon class="size-4 text-primary" />
				<Card.Title class="text-sm font-semibold">
					Dynamically Discovered Transient Hosts
				</Card.Title>
			</div>
			<Badge variant="outline" class="font-mono text-xs">
				{hosts.length} active
			</Badge>
		</div>
		<Card.Description class="text-xs">
			Unregistered endpoints resolved via mDNS queries, reverse DNS PTR sweeps, or NetBIOS announcement packets.
		</Card.Description>
	</Card.Header>

	<Card.Content class="p-0">
		{#if loading}
			<div class="p-4 flex flex-col gap-3">
				{#each Array(4) as _}
					<div class="flex items-center justify-between gap-4">
						<Skeleton class="h-5 w-32" />
						<Skeleton class="h-5 w-40" />
						<Skeleton class="h-5 w-20" />
						<Skeleton class="h-7 w-24 rounded-md" />
					</div>
				{/each}
			</div>
		{:else if hosts.length === 0}
			<div class="py-12">
				<Empty.Root>
					<Empty.Media>
						<RadioIcon class="size-8 text-muted-foreground/50" />
					</Empty.Media>
					<Empty.Title>No Transient Hosts</Empty.Title>
					<Empty.Description>
						All active devices on your LAN currently match known DHCP leases or static configurations.
					</Empty.Description>
				</Empty.Root>
			</div>
		{:else}
			<!-- Mobile View (< sm): Cards -->
			<div class="flex flex-col divide-y divide-border/60 sm:hidden">
				{#each hosts as h (h.ip + h.hostname)}
					<div class="p-3.5 flex flex-col gap-2 hover:bg-muted/20 transition-colors">
						<div class="flex items-center justify-between gap-2">
							<div class="flex items-center gap-2 min-w-0">
								<span class="text-sm font-semibold text-foreground truncate">
									{h.hostname || "Unknown Hostname"}
								</span>
								<Badge variant="secondary" class="text-[9px] uppercase font-mono px-1.5 py-0">
									{h.origin}
								</Badge>
							</div>

							<Button
								variant="outline"
								size="sm"
								class="h-7 text-xs gap-1 px-2 text-amber-400 hover:text-amber-300 shrink-0"
								onclick={() => onPromote(h)}
							>
								<BookmarkPlusIcon class="size-3" />
								<span>Reserve</span>
							</Button>
						</div>

						<div class="flex items-center justify-between text-xs font-mono">
							<span class="text-emerald-400 font-medium">{h.ip}</span>
							<button
								class="text-muted-foreground hover:text-foreground transition-colors p-1"
								onclick={() => copyText(h.ip, "IP")}
								title="Copy IP"
							>
								<CopyIcon class="size-3" />
							</button>
						</div>

						<div class="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/40">
							<span>Last seen: {formatTimeAgo(h.last_seen)}</span>
							<span>Resolved: {formatTimeAgo(h.resolved_at)}</span>
						</div>
					</div>
				{/each}
			</div>

			<!-- Desktop View (>= sm): Dense table -->
			<div class="hidden sm:block max-h-[500px] overflow-auto">
				<Table.Root class="min-w-[550px]">
					<Table.Header class="sticky top-0 z-10 bg-muted/90 backdrop-blur">
						<Table.Row class="hover:bg-transparent">
							<Table.Head>Resolved Hostname</Table.Head>
							<Table.Head>IP Address</Table.Head>
							<Table.Head>Discovery Origin</Table.Head>
							<Table.Head>Last Seen</Table.Head>
							<Table.Head class="text-right w-[120px]">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body class="font-mono text-xs">
						{#each hosts as h (h.ip + h.hostname)}
							<Table.Row class="hover:bg-muted/50 transition-colors">
								<!-- Hostname -->
								<Table.Cell class="font-sans font-semibold text-foreground text-xs sm:text-sm">
									{h.hostname || "—"}
								</Table.Cell>

								<!-- IP Address -->
								<Table.Cell>
									<div class="flex items-center gap-1.5">
										<span class="text-emerald-400 font-medium">{h.ip}</span>
										<button
											class="text-muted-foreground hover:text-foreground transition-colors p-0.5"
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
										class="h-7 text-xs gap-1 px-2 text-amber-400 hover:text-amber-300"
										onclick={() => onPromote(h)}
									>
										<BookmarkPlusIcon class="size-3" />
										<span>Promote</span>
									</Button>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
