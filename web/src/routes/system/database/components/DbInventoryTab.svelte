<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import CheckIcon from "@lucide/svelte/icons/check";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";

	interface InventorySubsystem {
		id: string;
		title: string;
		category: string;
		icon: any;
		count: number;
		unit: string;
		route: string;
		description: string;
	}

	let {
		inventoryItems = [],
		totalStoredEntities = 0,
		isInMemory = false,
	}: {
		inventoryItems?: InventorySubsystem[];
		totalStoredEntities?: number;
		isInMemory?: boolean;
	} = $props();
</script>

<div class="flex flex-col gap-6">
	<Card.Root>
		<Card.Header class="pb-3">
			<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
				<div class="space-y-1">
					<Card.Title class="text-base flex items-center gap-2 font-semibold">
						<LayersIcon class="size-4 text-primary" />
						Persistent Subsystem Inventory
					</Card.Title>
					<Card.Description class="text-xs">
						Aggregated state records actively maintained in daemon memory and synchronized to the storage backend.
					</Card.Description>
				</div>
				<Badge variant="outline" class="font-mono text-xs w-fit">
					{totalStoredEntities} total entities
				</Badge>
			</div>
		</Card.Header>
		<Card.Content>
			<!-- Mobile View: Card List -->
			<div class="flex flex-col gap-3 sm:hidden">
				{#each inventoryItems as item}
					<div class="p-3.5 rounded-xl border bg-card/60 flex flex-col gap-2.5">
						<div class="flex items-start justify-between gap-2">
							<div class="flex items-center gap-2.5">
								<div class="flex size-8 items-center justify-center rounded-lg bg-muted text-muted-foreground shrink-0">
									<item.icon class="size-4" />
								</div>
								<div class="flex flex-col">
									<span class="text-xs font-semibold text-foreground">{item.title}</span>
									<span class="text-[10px] text-muted-foreground">{item.category}</span>
								</div>
							</div>
							<Badge variant="secondary" class="font-mono text-xs shrink-0 font-semibold">
								{item.count.toLocaleString()} {item.unit}
							</Badge>
						</div>

						<p class="text-[11px] text-muted-foreground leading-relaxed">
							{item.description}
						</p>

						<div class="flex items-center justify-between pt-1 border-t border-border/40 text-xs">
							<div>
								{#if isInMemory}
									<Badge variant="outline" class="border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-[10px]">
										RAM Only
									</Badge>
								{:else}
									<Badge variant="outline" class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-[10px]">
										<CheckIcon class="size-3 mr-1" />
										Persistent (redb)
									</Badge>
								{/if}
							</div>
							<Button
								variant="ghost"
								size="sm"
								class="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground"
								href={item.route}
							>
								<span>Manage</span>
								<ExternalLinkIcon class="size-3" />
							</Button>
						</div>
					</div>
				{/each}
			</div>

			<!-- Desktop View: Table -->
			<div class="hidden sm:block rounded-md border overflow-x-auto">
				<Table.Root>
					<Table.Header>
						<Table.Row>
							<Table.Head class="w-[260px]">Subsystem / Domain</Table.Head>
							<Table.Head>Category</Table.Head>
							<Table.Head class="text-right">Record Count</Table.Head>
							<Table.Head>Backend Persistence</Table.Head>
							<Table.Head class="text-right">Action</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body>
						{#each inventoryItems as item}
							<Table.Row class="hover:bg-muted/50 transition-colors">
								<Table.Cell class="font-medium">
									<div class="flex items-center gap-2.5">
										<div class="flex size-7 items-center justify-center rounded-lg bg-muted text-muted-foreground shrink-0">
											<item.icon class="size-4" />
										</div>
										<div class="flex flex-col">
											<span class="text-xs font-semibold text-foreground">{item.title}</span>
											<span class="text-[11px] text-muted-foreground line-clamp-1">{item.description}</span>
										</div>
									</div>
								</Table.Cell>
								<Table.Cell>
									<Badge variant="secondary" class="text-[11px] font-normal">
										{item.category}
									</Badge>
								</Table.Cell>
								<Table.Cell class="text-right font-mono font-semibold text-xs">
									{item.count.toLocaleString()}
									<span class="text-[10px] font-normal text-muted-foreground ml-1">{item.unit}</span>
								</Table.Cell>
								<Table.Cell>
									{#if isInMemory}
										<Badge variant="outline" class="border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-400 text-[10px]">
											RAM Only
										</Badge>
									{:else}
										<Badge variant="outline" class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 text-[10px]">
											<CheckIcon class="size-3 mr-1" />
											Persistent (redb)
										</Badge>
									{/if}
								</Table.Cell>
								<Table.Cell class="text-right">
									<Button
										variant="ghost"
										size="sm"
										class="h-7 text-xs gap-1 text-muted-foreground hover:text-foreground"
										href={item.route}
									>
										<span>View</span>
										<ExternalLinkIcon class="size-3" />
									</Button>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			</div>
		</Card.Content>
	</Card.Root>
</div>
