<script lang="ts">
	import * as Alert from "$lib/components/ui/alert";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldOffIcon from "@lucide/svelte/icons/shield-off";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import type { FirewallStatus } from "$lib/api/types";

	interface Props {
		status: FirewallStatus | null;
		loading: boolean;
		activeTxId: string | null;
		rollbackSecsLeft: number | null;
		onAbort: () => void;
		onConfirmNow: () => void;
	}

	let { status, loading, activeTxId, rollbackSecsLeft, onAbort, onConfirmNow }: Props = $props();

	function formatSecsAgo(secs: number | null): string {
		if (secs === null) return "nunca";
		if (secs < 60) return `${secs}s atrás`;
		if (secs < 3600) return `${Math.floor(secs / 60)}min atrás`;
		return `${Math.floor(secs / 3600)}h atrás`;
	}
</script>

<div class="flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-card p-3 shadow-xs">
	<!-- Left: Status indicators -->
	<div class="flex min-w-0 flex-1 flex-wrap items-center gap-2">
		{#if loading}
			<Skeleton class="h-5 w-16 rounded-full" />
			<Skeleton class="h-4 w-48" />
			<Skeleton class="h-4 w-24" />
		{:else if status === null}
			<Alert.Root variant="destructive" class="py-1 px-3 text-xs w-auto">
				<AlertTriangleIcon class="size-4" data-icon="inline-start" />
				<Alert.Title class="text-xs">Serviço de firewall inacessível</Alert.Title>
			</Alert.Root>
		{:else}
			{#if status.enabled}
				<Badge
					variant="outline"
					class="border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-medium text-xs"
				>
					<span class="relative flex size-2 mr-1.5">
						<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
						<span class="relative inline-flex rounded-full size-2 bg-emerald-500"></span>
					</span>
					Ativo
				</Badge>
			{:else}
				<Badge variant="secondary" class="text-xs text-muted-foreground">
					<ShieldOffIcon class="size-3 mr-1" data-icon="inline-start" />
					Desativado
				</Badge>
			{/if}

			<span class="text-xs text-muted-foreground">
				<strong class="font-mono text-foreground">{status.rules_count}</strong> regras ·
				<strong class="font-mono text-foreground">{status.open_ports_count}</strong> portas abertas ·
				última aplicação: {formatSecsAgo(status.last_applied_secs_ago)}
			</span>

			{#if status.flow_offload_active}
				<Badge variant="secondary" class="text-[11px] gap-1">
					<ZapIcon class="size-3" data-icon="inline-start" />
					Flow Offload
				</Badge>
			{/if}

			{#if status.default_drop_active}
				<Badge variant="secondary" class="text-[11px]">
					Default Drop
				</Badge>
			{/if}
		{/if}
	</div>

	<!-- Right: Transaction & Auto-Rollback banner -->
	{#if rollbackSecsLeft !== null}
		<div class="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-700 dark:text-amber-400">
			<AlertTriangleIcon class="size-3.5 shrink-0" />
			<span>Rollback em <strong class="font-mono">{rollbackSecsLeft}s</strong></span>
			<Button
				size="sm"
				class="h-6 px-2 text-[11px] bg-amber-600 hover:bg-amber-700 text-white"
				onclick={onConfirmNow}
			>
				Confirmar Agora
			</Button>
			<Button
				variant="outline"
				size="sm"
				class="h-6 px-2 text-[11px] border-amber-500/40 text-amber-700 dark:text-amber-300"
				onclick={onAbort}
			>
				Abortar
			</Button>
		</div>
	{:else if activeTxId !== null}
		<div class="flex items-center gap-2 rounded-lg border border-border bg-muted/50 px-2.5 py-1 text-xs text-muted-foreground">
			<span>Transação pendente</span>
			<Button
				variant="outline"
				size="sm"
				class="h-6 px-2 text-[11px] text-destructive border-destructive/30 hover:bg-destructive/10"
				onclick={onAbort}
			>
				Abortar
			</Button>
		</div>
	{/if}
</div>
