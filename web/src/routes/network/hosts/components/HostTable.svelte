<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import type { HostConfigEntry } from "$lib/api/types";

	import ServerIcon from "@lucide/svelte/icons/server";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";

	let {
		hosts = [],
		loading = false,
		onEdit = () => {},
		onDelete = () => {},
	}: {
		hosts?: HostConfigEntry[];
		loading?: boolean;
		onEdit?: (host: HostConfigEntry) => void;
		onDelete?: (mac: string) => void;
	} = $props();

	import DataTablePagination from "$lib/components/DataTablePagination.svelte";

	let pageIndex = $state(0);
	let pageSize = $state(15);

	$effect(() => {
		hosts;
		pageIndex = 0;
	});

	const paginatedHosts = $derived(
		hosts.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize)
	);

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
					<div class="flex items-center justify-between gap-4">
						<Skeleton class="h-5 w-28" />
						<Skeleton class="h-5 w-36" />
						<Skeleton class="h-5 w-20" />
						<Skeleton class="h-7 w-16 rounded-md" />
					</div>
				{/each}
			</div>
		{:else if hosts.length === 0}
			<Empty.Root class="py-12">
				<Empty.Media>
					<ServerIcon class="size-8 text-muted-foreground/40" />
				</Empty.Media>
				<Empty.Title>No Static Hosts Configured</Empty.Title>
				<Empty.Description>
					Add a fixed IP binding or custom hostname override to get started.
				</Empty.Description>
			</Empty.Root>
		{:else}
			<!-- Mobile View (< sm): Touch-friendly stacked cards -->
			<div class="flex flex-col divide-y divide-border/60 sm:hidden">
				{#each paginatedHosts as host (host.mac)}
					<div class="p-3.5 flex flex-col gap-2 hover:bg-muted/20 transition-colors">
						<div class="flex items-center justify-between gap-2">
							<div class="flex items-center gap-2 min-w-0">
								<span class="text-sm font-semibold text-foreground truncate">
									{host.hostname || "Unassigned Host"}
								</span>
								<Badge variant="outline" class="text-[9px] uppercase font-mono px-1 py-0">
									{host.origin || "Config"}
								</Badge>
								{#if host.ignore_dns_log}
									<Badge variant="secondary" class="text-[9px] uppercase font-mono px-1 py-0 text-muted-foreground border-border/50">
										DNS Muted
									</Badge>
								{:else if host.ignored_log_domains && host.ignored_log_domains.length > 0}
									<Badge variant="outline" class="text-[9px] font-mono px-1 py-0 text-muted-foreground">
										{host.ignored_log_domains.length} {host.ignored_log_domains.length === 1 ? "domain" : "domains"} muted
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
										<DropdownMenu.Item onclick={() => copyText(host.v4_fixed || host.v4 || "", "IPv4")} class="gap-2">
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
						</div>

						<div class="flex items-center justify-between text-xs font-mono">
							<span class="text-muted-foreground">{host.mac}</span>
							{#if host.v4_fixed || host.v4}
								<span class="text-emerald-400 font-medium">{host.v4_fixed || host.v4}</span>
							{/if}
						</div>

						{#if host.v6_suffix}
							<div class="text-[11px] font-mono text-sky-400 truncate">
								IPv6: {host.v6_suffix}
							</div>
						{/if}
					</div>
				{/each}
			</div>

			<!-- Desktop View (>= sm): Dense table with horizontal scrolling -->
			<div class="hidden sm:block max-h-[600px] overflow-auto">
				<Table.Root class="min-w-[600px]">
					<Table.Header class="sticky top-0 z-10 bg-muted/90 backdrop-blur">
						<Table.Row class="hover:bg-transparent">
							<Table.Head>Hostname</Table.Head>
							<Table.Head>Target MAC</Table.Head>
							<Table.Head>Fixed IPv4</Table.Head>
							<Table.Head>IPv6 Suffix / Addr</Table.Head>
							<Table.Head>Origin</Table.Head>
							<Table.Head class="text-right w-[60px]">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body class="font-mono text-xs">
						{#each paginatedHosts as host (host.mac)}
							<Table.Row class="hover:bg-muted/50 transition-colors">
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
								<Table.Cell class="text-muted-foreground">
									{host.mac}
								</Table.Cell>

								<!-- Fixed IPv4 -->
								<Table.Cell class="text-emerald-400 font-medium">
									{host.v4_fixed || host.v4 || "—"}
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
											class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
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
					</Table.Body>
				</Table.Root>
			</div>

			<DataTablePagination
				bind:pageIndex
				bind:pageSize
				totalItems={hosts.length}
				itemName="hosts"
			/>
		{/if}
	</Card.Content>
</Card.Root>
