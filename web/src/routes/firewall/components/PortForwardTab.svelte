<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as Empty from "$lib/components/ui/empty";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Switch } from "$lib/components/ui/switch";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import TrashIcon from "@lucide/svelte/icons/trash-2";
	import ArrowLeftRightIcon from "@lucide/svelte/icons/arrow-left-right";
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

	function handleDialogSave(rule: PortForwardRule) {
		if (editingIndex !== null) {
			const next = [...rules];
			next[editingIndex] = rule;
			onUpdate(next);
		} else {
			onUpdate([...rules, rule]);
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

<div class="flex flex-col gap-4">
	<!-- Actions row -->
	<div class="flex items-center justify-between">
		<div>
			<h3 class="text-sm font-semibold tracking-tight text-foreground">Port Forwarding (DNAT)</h3>
			<p class="text-xs text-muted-foreground">Redirecionamento de portas de entrada para hosts da rede local.</p>
		</div>
		<Button size="sm" onclick={openAdd}>
			<PlusIcon data-icon="inline-start" />
			Adicionar Regra
		</Button>
	</div>

	{#if rules.length === 0}
		<Empty.Root class="rounded-xl border border-dashed py-12">
			<Empty.Media>
				<ArrowLeftRightIcon class="size-10 text-muted-foreground" />
			</Empty.Media>
			<Empty.Header>
				<Empty.Title>Nenhuma regra de redirecionamento</Empty.Title>
				<Empty.Description>
					Crie regras DNAT para permitir acesso externo a serviços rodando na sua rede local.
				</Empty.Description>
			</Empty.Header>
			<Empty.Content>
				<Button size="sm" onclick={openAdd}>
					<PlusIcon data-icon="inline-start" />
					Adicionar Regra
				</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		<div class="rounded-xl border border-border overflow-hidden bg-card">
			<Table.Root>
				<Table.Header>
					<Table.Row class="bg-muted/40 text-xs">
						<Table.Head>Comentário</Table.Head>
						<Table.Head>Protocolo</Table.Head>
						<Table.Head>Zona Origem</Table.Head>
						<Table.Head>Porta Externa</Table.Head>
						<Table.Head>Destino Interno</Table.Head>
						<Table.Head class="text-center">Hairpin NAT</Table.Head>
						<Table.Head class="w-24 text-right">Ações</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each rules as rule, index (index)}
						<Table.Row class="text-xs">
							<Table.Cell class="font-medium text-foreground">
								{rule.comment || "—"}
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
									{rule.internal_ip}:<strong class="text-foreground">{rule.internal_port}</strong>
								</span>
							</Table.Cell>
							<Table.Cell class="text-center">
								<Switch
									checked={rule.enable_hairpin}
									onCheckedChange={(v) => handleHairpinToggle(index, v)}
								/>
							</Table.Cell>
							<Table.Cell class="text-right">
								<div class="flex items-center justify-end gap-1">
									<Button
										variant="ghost"
										size="icon"
										class="size-8"
										onclick={() => openEdit(rule, index)}
									>
										<PencilIcon class="size-3.5 text-muted-foreground" />
										<span class="sr-only">Editar</span>
									</Button>
									<Button
										variant="ghost"
										size="icon"
										class="size-8 text-destructive hover:bg-destructive/10 hover:text-destructive"
										onclick={() => handleDelete(index)}
									>
										<TrashIcon class="size-3.5" />
										<span class="sr-only">Excluir</span>
									</Button>
								</div>
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		</div>
	{/if}

	<!-- Add / Edit Dialog -->
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
</div>
