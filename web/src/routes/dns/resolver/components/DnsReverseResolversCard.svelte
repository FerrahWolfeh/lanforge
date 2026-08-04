<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import * as Empty from "$lib/components/ui/empty";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import type { ReverseResolverEntry } from "$lib/api/types";

	let {
		loading = true,
		reverseResolvers = [],
		onAddReverse = () => {},
		onRemoveReverse = () => {},
	}: {
		loading?: boolean;
		reverseResolvers?: ReverseResolverEntry[];
		onAddReverse?: () => void;
		onRemoveReverse?: (item: ReverseResolverEntry) => void;
	} = $props();

	function formatSubnet(subnet: any): string {
		if (typeof subnet === "string") return subnet;
		if (subnet && typeof subnet === "object") {
			if (subnet.net && subnet.prefix !== undefined) {
				return `${subnet.net}/${subnet.prefix}`;
			}
			if (subnet.cidr) return subnet.cidr;
			if (subnet.ip && subnet.mask) return `${subnet.ip}/${subnet.mask}`;
		}
		return String(subnet ?? "192.168.1.0/24");
	}

	function formatResolverUri(r: ReverseResolverEntry): string {
		if (r.resolver) return String(r.resolver);
		return "192.168.1.1:53";
	}
</script>

<Card.Root class="flex flex-col overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex items-center justify-between">
			<div class="flex flex-col gap-0.5">
				<Card.Title class="text-base flex items-center gap-2">
					<CpuIcon class="size-4 text-purple-400" />
					<span>Reverse DNS (PTR) Resolvers</span>
				</Card.Title>
				<p class="text-muted-foreground text-xs font-normal">
					Targeted PTR reverse lookup servers for specific LAN subnets
				</p>
			</div>
			<Button size="sm" variant="outline" onclick={onAddReverse}>
				<PlusIcon data-icon="inline-start" />
				Add Reverse PTR
			</Button>
		</div>
	</Card.Header>
	<Card.Content class="p-0">
		{#if loading}
			<div class="p-6">
				<Skeleton class="h-10 w-full" />
			</div>
		{:else if reverseResolvers.length === 0}
			<Empty.Root class="py-10">
				<Empty.Header>
					<Empty.Media>
						<CpuIcon class="size-8 text-muted-foreground/40" />
					</Empty.Media>
					<Empty.Title
						>No Reverse PTR Resolvers Configured</Empty.Title
					>
					<Empty.Description>
						Reverse PTR lookups currently fall back to standard
						local host tracking.
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<div class="max-h-[380px] overflow-auto">
				<Table.Root>
					<Table.Header
						class="sticky top-0 z-10 bg-muted/90 backdrop-blur"
					>
						<Table.Row class="hover:bg-transparent">
							<Table.Head>Target Subnet (CIDR)</Table.Head>
							<Table.Head>Resolver URI / Server</Table.Head>
							<Table.Head class="text-right">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body class="font-mono text-xs">
						{#each reverseResolvers as r, i (formatSubnet(r.subnet) + i)}
							<Table.Row>
								<Table.Cell
									class="font-semibold text-emerald-400 font-mono"
								>
									{formatSubnet(r.subnet)}
								</Table.Cell>
								<Table.Cell class="text-sky-400 font-mono">
									{formatResolverUri(r)}
								</Table.Cell>
								<Table.Cell class="text-right font-sans">
									<Tooltip.Root>
										<Tooltip.Trigger>
											{#snippet child({ props })}
												<Button
													variant="ghost"
													size="icon-sm"
													{...props}
													onclick={() =>
														onRemoveReverse(r)}
												>
													<Trash2Icon
														data-icon="inline-start"
														class="text-rose-400"
													/>
												</Button>
											{/snippet}
										</Tooltip.Trigger>
										<Tooltip.Content>
											<p>Delete PTR resolver rule</p>
										</Tooltip.Content>
									</Tooltip.Root>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
