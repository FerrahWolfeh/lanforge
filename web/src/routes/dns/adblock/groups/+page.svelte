<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import UsersIcon from "@lucide/svelte/icons/users";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SlidersIcon from "@lucide/svelte/icons/sliders-horizontal";
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import { toast } from "svelte-sonner";
	import {
		dnsAdblockGroups,
		dnsAdblockGroupDelete,
		dnsAdblockSources,
		dnsAdblockUrls,
	} from "$lib/api/client";
	import type {
		AdblockClientEntry,
		AdblockGroupEntry,
		DnsAdblockGroupsResponse,
	} from "$lib/api/types";
	import AdblockGroupDialog from "../components/AdblockGroupDialog.svelte";
	import AdblockBypassDialog from "../components/AdblockBypassDialog.svelte";

	let loading = $state(true);
	let data = $state<DnsAdblockGroupsResponse>({ groups: [], bypass: [] });
	/** Source names a group can add: every downloaded list outside the global layer. */
	let groupLists = $state<string[]>([]);

	let dialogOpen = $state(false);
	let editing = $state<AdblockGroupEntry | null>(null);
	let bypassOpen = $state(false);
	let deleting = $state<AdblockGroupEntry | null>(null);
	let deleteOpen = $state(false);

	async function load() {
		try {
			const [groups, sources, globals] = await Promise.all([
				dnsAdblockGroups(),
				dnsAdblockSources().catch(() => ({ sources: [] })),
				dnsAdblockUrls().catch(() => []),
			]);
			data = groups ?? { groups: [], bypass: [] };
			const global = new Set(globals.map((u) => u.url));
			groupLists = (sources?.sources ?? [])
				.filter((s) => !global.has(s.url) && s.name)
				.map((s) => s.name as string);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to load adblock groups");
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		editing = null;
		dialogOpen = true;
	}

	function openEdit(group: AdblockGroupEntry) {
		editing = group;
		dialogOpen = true;
	}

	async function confirmDelete() {
		if (!deleting) return;
		try {
			await dnsAdblockGroupDelete(deleting.name);
			toast.success(`Group "${deleting.name}" removed (its rules file stays on disk)`);
			await load();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to remove the group");
		} finally {
			deleting = null;
			deleteOpen = false;
		}
	}

	function clientLabel(c: AdblockClientEntry): string {
		return c.devices.length > 0 ? c.devices.map((d) => d.name).join(", ") : c.selector;
	}

	onMount(load);
</script>

<div class="space-y-6">
	<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
		<div>
			<h2 class="text-sm font-semibold flex items-center gap-2">
				<UsersIcon class="size-4 text-primary" />
				Client Groups
			</h2>
			<p class="text-xs text-muted-foreground mt-1 max-w-2xl">
				Every client gets the global layer. A group overrides it for its clients: its rules
				decide first (an allow beats any global block), then its lists, then the global layer.
			</p>
		</div>
		<div class="flex items-center gap-2">
			<Button variant="outline" size="sm" class="h-8 gap-1.5 text-xs" onclick={() => (bypassOpen = true)}>
				<ShieldOffIcon class="size-3.5" />
				Bypass
				<Badge variant="secondary" class="px-1.5 py-0 text-[10px] font-mono">{data.bypass.length}</Badge>
			</Button>
			<Button size="sm" class="h-8 gap-1.5 text-xs" onclick={openCreate}>
				<PlusIcon class="size-3.5" />
				New group
			</Button>
		</div>
	</div>

	{#if data.bypass.length > 0}
		<Card.Root class="border-amber-500/30 bg-amber-500/5">
			<Card.Content class="p-3 flex flex-wrap items-center gap-2 text-xs">
				<ShieldOffIcon class="size-3.5 text-amber-500" />
				<span class="font-medium">Never filtered:</span>
				{#each data.bypass as c (c.selector)}
					<Badge variant="outline" class="font-mono text-[11px]" title={c.selector}>{clientLabel(c)}</Badge>
				{/each}
			</Card.Content>
		</Card.Root>
	{/if}

	{#if loading}
		<div class="grid gap-4 md:grid-cols-2">
			{#each Array(2) as _}
				<Skeleton class="h-40 w-full rounded-xl" />
			{/each}
		</div>
	{:else if data.groups.length === 0}
		<Card.Root>
			<Card.Content class="h-40 flex flex-col items-center justify-center gap-2 text-center text-xs text-muted-foreground">
				<UsersIcon class="size-6 opacity-50" />
				<p>No groups yet. Every client gets the global layer.</p>
				<Button variant="outline" size="sm" class="h-7 text-xs gap-1" onclick={openCreate}>
					<PlusIcon class="size-3" /> New group
				</Button>
			</Card.Content>
		</Card.Root>
	{:else}
		<div class="grid gap-4 md:grid-cols-2">
			{#each data.groups as group (group.name)}
				<Card.Root class="flex flex-col">
					<Card.Header class="pb-3 border-b border-border/50">
						<div class="flex items-center justify-between gap-2">
							<Card.Title class="text-sm font-semibold font-mono">{group.name}</Card.Title>
							<div class="flex items-center gap-1.5">
								<Badge variant="outline" class="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 text-[10px] font-mono">
									{group.allow_rules} allow
								</Badge>
								<Badge variant="outline" class="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20 text-[10px] font-mono">
									{group.block_rules} block
								</Badge>
							</div>
						</div>
					</Card.Header>
					<Card.Content class="flex-1 py-3 space-y-3 text-xs">
						<div>
							<div class="text-[11px] font-medium text-muted-foreground mb-1">Clients</div>
							{#if group.clients.length === 0}
								<span class="text-muted-foreground">None: applies to nobody.</span>
							{:else}
								<div class="flex flex-wrap gap-1">
									{#each group.clients as c (c.selector)}
										<Badge variant="secondary" class="font-mono text-[11px]" title={c.selector}>
											{clientLabel(c)}
										</Badge>
									{/each}
								</div>
							{/if}
						</div>
						{#if group.lists.length > 0}
							<div>
								<div class="text-[11px] font-medium text-muted-foreground mb-1 flex items-center gap-1">
									<LayersIcon class="size-3" /> Extra lists
								</div>
								<div class="flex flex-wrap gap-1">
									{#each group.lists as list (list)}
										<Badge variant="outline" class="font-mono text-[11px]">{list}</Badge>
									{/each}
								</div>
							</div>
						{/if}
					</Card.Content>
					<Card.Footer class="border-t border-border/50 py-2 flex justify-end gap-1.5">
						<Button
							variant="ghost"
							size="sm"
							class="h-7 gap-1 text-xs"
							href="/dns/adblock/rules?group={encodeURIComponent(group.name)}"
						>
							<SlidersIcon class="size-3.5" /> Rules
						</Button>
						<Button variant="ghost" size="sm" class="h-7 gap-1 text-xs" onclick={() => openEdit(group)}>
							<PencilIcon class="size-3.5" /> Edit
						</Button>
						<Button
							variant="ghost"
							size="sm"
							class="h-7 gap-1 text-xs text-muted-foreground hover:text-destructive hover:bg-destructive/10"
							onclick={() => {
								deleting = group;
								deleteOpen = true;
							}}
						>
							<Trash2Icon class="size-3.5" /> Delete
						</Button>
					</Card.Footer>
				</Card.Root>
			{/each}
		</div>
	{/if}
</div>

<AdblockGroupDialog bind:open={dialogOpen} group={editing} lists={groupLists} onSaved={load} />
<AdblockBypassDialog bind:open={bypassOpen} bypass={data.bypass} onSaved={load} />

<AlertDialog.Root bind:open={deleteOpen}>
	<AlertDialog.Content class="rounded-xl">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold">Delete group?</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				<strong>{deleting?.name}</strong> is removed from the configuration and its clients get
				only the global layer. Its rules file stays on disk.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="cursor-pointer text-xs">Cancel</AlertDialog.Cancel>
			<AlertDialog.Action
				class="cursor-pointer text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={confirmDelete}
			>
				Delete group
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
