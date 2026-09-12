<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import type { LeaseEntry } from "$lib/api/types";

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
	}: {
		leases?: LeaseEntry[];
		loading?: boolean;
		onRenew?: (lease: LeaseEntry) => void;
		onRelease?: (lease: LeaseEntry) => void;
		onPromote?: (lease: LeaseEntry) => void;
		onWol?: (mac: string) => void;
	} = $props();

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

<Card.Root class="overflow-hidden">
	<Card.Content class="p-0">
		{#if loading}
			<div class="p-4 flex flex-col gap-3">
				{#each Array(5) as _}
					<Skeleton class="h-10 w-full" />
				{/each}
			</div>
		{:else if leases.length === 0}
			<div class="py-12">
				<Empty.Root>
					<Empty.Media>
						<NetworkIcon class="size-8 text-muted-foreground/60" />
					</Empty.Media>
					<Empty.Title>No leases found</Empty.Title>
					<Empty.Description>
						No active dynamic DHCP leases match your filter criteria.
					</Empty.Description>
				</Empty.Root>
			</div>
		{:else}
			<!-- Mobile View (< sm): Touch-friendly stacked cards -->
			<div class="flex flex-col divide-y divide-border/60 sm:hidden">
				{#each leases as lease (lease.mac + lease.address + lease.kind)}
					{@const isExpiring = lease.remaining_secs > 0 && lease.remaining_secs < 3600}
					{@const isExpired = lease.remaining_secs <= 0}
					<div class="p-3.5 flex flex-col gap-2 hover:bg-muted/20 transition-colors">
						<div class="flex items-center justify-between gap-2">
							<div class="flex items-center gap-2 min-w-0">
								<span class="text-sm font-semibold text-foreground truncate">
									{lease.hostname || "Unassigned Host"}
								</span>
								{#if lease.kind === "v4"}
									<Badge variant="outline" class="font-mono text-[9px] text-blue-400 border-blue-500/30 px-1 py-0">
										IPv4
									</Badge>
								{:else if lease.kind === "v6"}
									<Badge variant="outline" class="font-mono text-[9px] text-purple-400 border-purple-500/30 px-1 py-0">
										IPv6
									</Badge>
								{:else}
									<Badge variant="outline" class="font-mono text-[9px] text-emerald-400 border-emerald-500/30 px-1 py-0">
										IA_PD
									</Badge>
								{/if}
							</div>

							<!-- Actions Dropdown -->
							<DropdownMenu.Root>
								<DropdownMenu.Trigger
									class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors shrink-0"
								>
									<MoreHorizontalIcon class="size-4" />
								</DropdownMenu.Trigger>
								<DropdownMenu.Content align="end" class="w-48 text-xs">
									<DropdownMenu.Item onclick={() => onRenew(lease)} class="gap-2">
										<RotateCcwIcon class="size-3.5 text-sky-400" />
										Renew Lease
									</DropdownMenu.Item>
									<DropdownMenu.Item onclick={() => onPromote(lease)} class="gap-2">
										<BookmarkPlusIcon class="size-3.5 text-amber-400" />
										Convert to Static Host
									</DropdownMenu.Item>
									<DropdownMenu.Item onclick={() => onWol(lease.mac)} class="gap-2">
										<ZapIcon class="size-3.5 text-emerald-400" />
										Send Wake-on-LAN
									</DropdownMenu.Item>
									<DropdownMenu.Separator />
									<DropdownMenu.Item onclick={() => copyText(lease.mac, "MAC")} class="gap-2">
										<CopyIcon class="size-3.5 text-muted-foreground" />
										Copy MAC
									</DropdownMenu.Item>
									<DropdownMenu.Item onclick={() => copyText(lease.address, "IP")} class="gap-2">
										<CopyIcon class="size-3.5 text-muted-foreground" />
										Copy IP
									</DropdownMenu.Item>
									<DropdownMenu.Separator />
									<DropdownMenu.Item onclick={() => onRelease(lease)} class="gap-2 text-rose-500">
										<Trash2Icon class="size-3.5" />
										Release Lease
									</DropdownMenu.Item>
								</DropdownMenu.Content>
							</DropdownMenu.Root>
						</div>

						<div class="flex items-center justify-between text-xs font-mono">
							<span class="text-muted-foreground">{lease.mac}</span>
							<span class={[
								"font-medium",
								lease.kind === "v4" ? "text-emerald-400" : "text-sky-400",
							].join(" ")}>
								{lease.kind === "v6_prefix" ? `${lease.address}/64` : lease.address}
							</span>
						</div>

						<div class="flex items-center justify-between text-[11px] pt-1 border-t border-border/40">
							<span class="text-muted-foreground">Expires in:</span>
							<span class={[
								"font-mono font-medium",
								isExpired ? "text-destructive" : isExpiring ? "text-amber-500" : "text-foreground",
							].join(" ")}>
								{formatDuration(lease.remaining_secs)}
							</span>
						</div>
					</div>
				{/each}
			</div>

			<!-- Desktop View (>= sm): Dense table with horizontal scroll -->
			<div class="hidden sm:block max-h-[600px] overflow-auto">
				<Table.Root class="min-w-[650px]">
					<Table.Header class="sticky top-0 z-10 bg-muted/90 backdrop-blur">
						<Table.Row class="hover:bg-transparent">
							<Table.Head>Hostname</Table.Head>
							<Table.Head>MAC Address</Table.Head>
							<Table.Head>Assigned Address</Table.Head>
							<Table.Head class="w-[80px]">Type</Table.Head>
							<Table.Head class="w-[160px]">Lifetime</Table.Head>
							<Table.Head class="w-[60px] text-right">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body class="font-mono text-xs">
						{#each leases as lease (lease.mac + lease.address + lease.kind)}
							{@const isExpiring = lease.remaining_secs > 0 && lease.remaining_secs < 3600}
							{@const isExpired = lease.remaining_secs <= 0}
							<Table.Row class="hover:bg-muted/50 transition-colors">
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
											class="text-muted-foreground hover:text-foreground transition-colors p-0.5"
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
										<span class={[
											"font-medium",
											lease.kind === "v4" ? "text-emerald-400" : "text-sky-400",
										].join(" ")}>
											{lease.kind === "v6_prefix" ? `${lease.address}/64` : lease.address}
										</span>
										<button
											class="text-muted-foreground hover:text-foreground transition-colors p-0.5"
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
										<Badge variant="outline" class="font-mono text-[10px] text-blue-400 border-blue-500/30">
											IPv4
										</Badge>
									{:else if lease.kind === "v6"}
										<Badge variant="outline" class="font-mono text-[10px] text-purple-400 border-purple-500/30">
											IPv6
										</Badge>
									{:else}
										<Badge variant="outline" class="font-mono text-[10px] text-emerald-400 border-emerald-500/30">
											IA_PD
										</Badge>
									{/if}
								</Table.Cell>

								<!-- Remaining Lifetime -->
								<Table.Cell class="font-sans">
									<span class={[
										"font-mono font-medium text-xs",
										isExpired ? "text-destructive" : isExpiring ? "text-amber-500" : "text-foreground",
									].join(" ")}>
										{formatDuration(lease.remaining_secs)}
									</span>
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
											<DropdownMenu.Item onclick={() => onRenew(lease)} class="gap-2">
												<RotateCcwIcon class="size-3.5 text-sky-400" />
												Renew Lease
											</DropdownMenu.Item>
											<DropdownMenu.Item onclick={() => onPromote(lease)} class="gap-2">
												<BookmarkPlusIcon class="size-3.5 text-amber-400" />
												Convert to Static Host
											</DropdownMenu.Item>
											<DropdownMenu.Item onclick={() => onWol(lease.mac)} class="gap-2">
												<ZapIcon class="size-3.5 text-emerald-400" />
												Send Wake-on-LAN
											</DropdownMenu.Item>
											<DropdownMenu.Separator />
											<DropdownMenu.Item onclick={() => copyText(lease.mac, "MAC")} class="gap-2">
												<CopyIcon class="size-3.5 text-muted-foreground" />
												Copy MAC
											</DropdownMenu.Item>
											<DropdownMenu.Item onclick={() => copyText(lease.address, "IP")} class="gap-2">
												<CopyIcon class="size-3.5 text-muted-foreground" />
												Copy IP
											</DropdownMenu.Item>
											<DropdownMenu.Separator />
											<DropdownMenu.Item onclick={() => onRelease(lease)} class="gap-2 text-rose-500">
												<Trash2Icon class="size-3.5" />
												Release Lease
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
