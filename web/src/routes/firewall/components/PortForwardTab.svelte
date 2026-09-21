<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Switch } from "$lib/components/ui/switch";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import TrashIcon from "@lucide/svelte/icons/trash-2";
	import ArrowLeftRightIcon from "@lucide/svelte/icons/arrow-left-right";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import DataTableCard from "$lib/components/DataTableCard.svelte";
	import PortForwardDialog from "./PortForwardDialog.svelte";
	import type { PortForwardRule, FirewallZone } from "$lib/api/types";

	interface Props {
		rules: PortForwardRule[];
		zones: FirewallZone[];
		onUpdate: (rules: PortForwardRule[]) => void;
	}

	let { rules, zones, onUpdate }: Props = $props();

	let showDialog = $state(false);
	let editingRule = $state<PortForwardRule | null>(null);
	let editingIndex = $state<number | null>(null);

	const zoneNames = $derived(zones.map((z) => z.name));

	function openAdd() {
		editingRule = null;
		editingIndex = null;
		showDialog = true;
	}

	function openEdit(rule: PortForwardRule, index: number) {
		editingRule = rule;
		editingIndex = index;
		showDialog = true;
	}

	function handleDialogSave(result: PortForwardRule | PortForwardRule[]) {
		const newRules = Array.isArray(result) ? result : [result];
		if (editingIndex !== null) {
			const next = [...rules];
			next.splice(editingIndex, 1, ...newRules);
			onUpdate(next);
		} else {
			onUpdate([...rules, ...newRules]);
		}
		showDialog = false;
		editingRule = null;
		editingIndex = null;
	}

	function handleDelete(index: number) {
		onUpdate(rules.filter((_, i) => i !== index));
	}

	function handleHairpinToggle(index: number, checked: boolean) {
		const next = rules.map((r, i) => (i === index ? { ...r, enable_hairpin: checked } : r));
		onUpdate(next);
	}
</script>

<DataTableCard
	title="Port Forwarding & IPv6 Pinholes"
	icon={ArrowLeftRightIcon}
	description="Manage inbound IPv4 port forwarding and IPv6 pinholes for internal LAN devices."
	total={rules.length}
	itemName="rules"
	showSearch={false}
	showPagination={false}
	containerHeight="h-auto"
	minTableWidth="min-w-[650px]"
	columns={8}
	isEmpty={rules.length === 0}
	emptyMessage="No port forwarding rules or IPv6 pinholes configured."
>
	{#snippet titleExtra()}
		<HelpPopover
			title="Port Forwarding & Pinholes Guide"
			description="How inbound connections from the Internet are routed to local LAN services."
		>
			<div class="flex flex-col gap-2 text-xs text-muted-foreground leading-relaxed">
				<p>
					<strong class="text-foreground">IPv4 DNAT (Port Forward):</strong> Translates an external WAN IP port to a private LAN IPv4 address (e.g. 192.168.0.128:8080).
				</p>
				<p>
					<strong class="text-foreground">IPv6 Pinholes:</strong> Direct routed hole punching for globally-routable IPv6 addresses without NAT rewriting (e.g. qBittorrent on 6881).
				</p>
				<p>
					<strong class="text-foreground">Dual-Stack & Device Pinning:</strong> When selecting a recognized device from the network table, Lanforge can open both IPv4 and IPv6 ports simultaneously using its tracked static leases or pinned suffixes.
				</p>
				<p>
					<strong class="text-foreground">Hairpin NAT:</strong> Allows internal LAN devices to access forwarded IPv4 services using your public WAN IP or DDNS hostname.
				</p>
			</div>
		</HelpPopover>
	{/snippet}

	{#snippet actions()}
		<Button size="sm" onclick={openAdd} class="h-8 text-xs gap-1.5">
			<PlusIcon class="size-3.5" />
			<span>Add Rule</span>
		</Button>
	{/snippet}

	{#snippet emptyAction()}
		<Button size="sm" onclick={openAdd} class="h-8 text-xs gap-1.5">
			<PlusIcon class="size-3.5" />
			<span>Add Rule</span>
		</Button>
	{/snippet}

	{#snippet header()}
		<Table.Head>Comment</Table.Head>
		<Table.Head>Type</Table.Head>
		<Table.Head>Protocol</Table.Head>
		<Table.Head>Source Zone</Table.Head>
		<Table.Head>External Port</Table.Head>
		<Table.Head>Internal Target</Table.Head>
		<Table.Head class="text-center">Hairpin NAT</Table.Head>
		<Table.Head class="w-24 text-right">Actions</Table.Head>
	{/snippet}

	{#each rules as rule, index (index)}
		{@const isV6 = rule.internal_ip.includes(":")}
		<Table.Row class="text-xs hover:bg-muted/40 transition-colors">
			<Table.Cell class="font-medium text-foreground">
				{rule.comment || "—"}
			</Table.Cell>
			<Table.Cell>
				{#if isV6}
					<Badge variant="outline" class="border-purple-500/30 text-purple-400 bg-purple-500/10 font-mono text-[10px]">
						IPv6 Pinhole
					</Badge>
				{:else}
					<Badge variant="outline" class="border-blue-500/30 text-blue-400 bg-blue-500/10 font-mono text-[10px]">
						IPv4 DNAT
					</Badge>
				{/if}
			</Table.Cell>
			<Table.Cell>
				<Badge variant="outline" class="font-mono text-[11px]">
					{rule.protocol}
				</Badge>
			</Table.Cell>
			<Table.Cell>
				<span class="font-mono">{rule.src_zone}</span>
			</Table.Cell>
			<Table.Cell>
				<span class="font-mono font-semibold">{rule.external_port}</span>
			</Table.Cell>
			<Table.Cell>
				<span class="font-mono text-muted-foreground">
					{#if isV6}
						[{rule.internal_ip}]:<strong class="text-foreground">{rule.internal_port}</strong>
					{:else}
						{rule.internal_ip}:<strong class="text-foreground">{rule.internal_port}</strong>
					{/if}
				</span>
			</Table.Cell>
			<Table.Cell class="text-center">
				{#if isV6}
					<span class="text-[11px] text-muted-foreground font-mono" title="Not applicable to routed IPv6 pinholes">—</span>
				{:else}
					<Switch
						checked={rule.enable_hairpin}
						onCheckedChange={(v) => handleHairpinToggle(index, v)}
						aria-label="Hairpin NAT"
					/>
				{/if}
			</Table.Cell>
			<Table.Cell class="text-right">
				<div class="flex items-center justify-end gap-1">
					<Button
						variant="ghost"
						size="icon"
						class="size-8"
						onclick={() => openEdit(rule, index)}
						aria-label="Edit"
					>
						<PencilIcon class="size-3.5 text-muted-foreground" />
						<span class="sr-only">Edit</span>
					</Button>
					<Button
						variant="ghost"
						size="icon"
						class="size-8 text-destructive hover:bg-destructive/10 hover:text-destructive"
						onclick={() => handleDelete(index)}
						aria-label="Delete"
					>
						<TrashIcon class="size-3.5" />
						<span class="sr-only">Delete</span>
					</Button>
				</div>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>

<!-- Dialog for Add / Edit -->
<PortForwardDialog
	bind:open={showDialog}
	zones={zoneNames}
	rule={editingRule}
	onSave={handleDialogSave}
	onClose={() => {
		showDialog = false;
		editingRule = null;
		editingIndex = null;
	}}
/>
