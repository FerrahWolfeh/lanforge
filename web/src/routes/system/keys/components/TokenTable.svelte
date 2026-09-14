<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import * as Empty from "$lib/components/ui/empty";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import SearchIcon from "@lucide/svelte/icons/search";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { deleteToken, renewToken } from "$lib/api/client";
	import { copyToClipboard } from "$lib/utils";
	import type { AuthToken } from "$lib/api/types";
	import { toast } from "svelte-sonner";

	let {
		tokens = [],
		isLoading = false,
		onRefresh,
		onOpenCreate,
		onRenewed
	}: {
		tokens: AuthToken[];
		isLoading: boolean;
		onRefresh: () => Promise<void> | void;
		onOpenCreate: () => void;
		onRenewed: (token: AuthToken) => void;
	} = $props();

	let searchQuery = $state("");
	let scopeFilter = $state<string>("all");
	let copiedTokenId = $state<string | number | null>(null);

	// Revoke confirmation dialog
	let isRevokeOpen = $state(false);
	let tokenToRevoke = $state<AuthToken | null>(null);
	let isRevoking = $state(false);

	// Renew confirmation dialog
	let isRenewOpen = $state(false);
	let tokenToRenew = $state<AuthToken | null>(null);
	let isRenewing = $state(false);

	function isExpired(t: AuthToken): boolean {
		if (!t.expires_at) return false;
		const nowSecs = Math.floor(Date.now() / 1000);
		const expSecs = t.expires_at > 1e11 ? Math.floor(t.expires_at / 1000) : t.expires_at;
		return expSecs < nowSecs;
	}

	function formatDate(ts: number | null | undefined): string {
		if (!ts) return "Nunca";
		const ms = ts > 1e11 ? ts : ts * 1000;
		const d = new Date(ms);
		return d.toLocaleDateString(undefined, {
			year: "numeric",
			month: "short",
			day: "2-digit",
			hour: "2-digit",
			minute: "2-digit"
		});
	}

	function formatRelative(ts: number | null | undefined): string {
		if (!ts) return "Nunca utilizado";
		const ms = ts > 1e11 ? ts : ts * 1000;
		const diffSecs = Math.round((Date.now() - ms) / 1000);
		if (diffSecs < 60) return "Agora mesmo";
		if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m atrás`;
		if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h atrás`;
		return `${Math.floor(diffSecs / 86400)}d atrás`;
	}

	function confirmRevoke(token: AuthToken) {
		tokenToRevoke = token;
		isRevokeOpen = true;
	}

	async function handleRevokeToken() {
		if (!tokenToRevoke) return;
		isRevoking = true;
		try {
			await deleteToken(tokenToRevoke.id);
			toast.success(`Chave '${tokenToRevoke.name}' revogada com sucesso.`);
			isRevokeOpen = false;
			tokenToRevoke = null;
			await onRefresh();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro ao revogar chave.";
			toast.error(msg);
		} finally {
			isRevoking = false;
		}
	}

	function confirmRenew(token: AuthToken) {
		tokenToRenew = token;
		isRenewOpen = true;
	}

	async function handleRenewToken() {
		if (!tokenToRenew) return;
		isRenewing = true;
		try {
			const renewed = await renewToken(tokenToRenew.id);
			toast.success(`Chave '${tokenToRenew.name}' renovada! Novo segredo gerado.`);
			isRenewOpen = false;
			tokenToRenew = null;
			onRenewed(renewed);
			await onRefresh();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro ao renovar chave.";
			toast.error(msg);
		} finally {
			isRenewing = false;
		}
	}

	const filteredTokens = $derived(
		tokens.filter((t) => {
			const query = searchQuery.trim().toLowerCase();
			const matchesSearch =
				!query ||
				t.name.toLowerCase().includes(query) ||
				String(t.id).toLowerCase().includes(query);
			const matchesScope = scopeFilter === "all" || t.scopes.includes(scopeFilter);
			return matchesSearch && matchesScope;
		})
	);
</script>

<!-- Main List Section -->
<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/60">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div class="flex flex-col gap-0.5">
				<Card.Title class="text-base font-bold text-foreground">
					Tokens Cadastrados
				</Card.Title>
				<Card.Description class="text-xs">
					Tokens gerados podem ser passados no cabeçalho <code class="font-mono text-primary font-semibold text-[11px]">Authorization: Bearer lf_ak_...</code>.
				</Card.Description>
			</div>

			<!-- Search & Filter Controls -->
			<div class="flex flex-wrap items-center gap-2">
				<div class="relative w-full sm:w-56">
					<SearchIcon class="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
					<Input
						placeholder="Buscar por nome ou ID..."
						bind:value={searchQuery}
						class="text-xs pl-8 rounded-xl h-8.5 bg-background"
					/>
				</div>

				<select
					bind:value={scopeFilter}
					class="h-8.5 text-xs rounded-xl bg-background border border-input px-2.5 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
					aria-label="Filtrar por escopo"
				>
					<option value="all">Todos os Escopos</option>
					<option value="admin">Admin</option>
					<option value="monitoring">Monitoring</option>
					<option value="device_write">Device Write</option>
					<option value="dns_query">DNS Query</option>
					<option value="upstream_write">Upstream Write</option>
					<option value="config_write">Config Write</option>
				</select>
			</div>
		</div>
	</Card.Header>

	<Card.Content class="p-0">
		{#if isLoading}
			<div class="p-4 flex flex-col gap-3">
				<Skeleton class="h-14 w-full rounded-xl" />
				<Skeleton class="h-14 w-full rounded-xl" />
				<Skeleton class="h-14 w-full rounded-xl" />
			</div>
		{:else if filteredTokens.length === 0}
			<Empty.Root class="py-12">
				<Empty.Header>
					<Empty.Media>
						<div class="size-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
							<KeyRoundIcon class="size-6" />
						</div>
					</Empty.Media>
					<Empty.Title>Nenhum token encontrado</Empty.Title>
					<Empty.Description class="text-xs max-w-sm">
						{#if searchQuery.trim() || scopeFilter !== 'all'}
							Nenhuma chave de autenticação corresponde aos filtros informados.
						{:else}
							Você ainda não gerou nenhuma chave de autenticação programática. Crie sua primeira chave para integrar o Lanforge com suas ferramentas.
						{/if}
					</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					{#if !searchQuery.trim() && scopeFilter === 'all'}
						<Button
							size="sm"
							class="rounded-xl cursor-pointer text-xs"
							onclick={onOpenCreate}
						>
							<PlusIcon data-icon="inline-start" />
							Gerar Primeira Chave
						</Button>
					{:else}
						<Button
							variant="outline"
							size="sm"
							class="rounded-xl cursor-pointer text-xs"
							onclick={() => {
								searchQuery = "";
								scopeFilter = "all";
							}}
						>
							Limpar Filtros
						</Button>
					{/if}
				</Empty.Content>
			</Empty.Root>
		{:else}
			<Table.Root>
				<Table.Header>
					<Table.Row class="hover:bg-transparent border-b border-border/60">
						<Table.Head class="text-xs font-semibold">Nome & ID</Table.Head>
						<Table.Head class="text-xs font-semibold">Escopos de Acesso</Table.Head>
						<Table.Head class="text-xs font-semibold">Criado Em</Table.Head>
						<Table.Head class="text-xs font-semibold">Último Acesso</Table.Head>
						<Table.Head class="text-xs font-semibold">Status / Validade</Table.Head>
						<Table.Head class="text-xs font-semibold text-right">Ações</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each filteredTokens as token (token.id)}
						{@const expired = isExpired(token)}
						<Table.Row class="border-b border-border/50 hover:bg-muted/30 transition-colors">
							<!-- Nome & ID -->
							<Table.Cell class="py-3.5">
								<div class="flex items-center gap-2.5">
									<div class="size-8 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
										<KeyRoundIcon class="size-4" />
									</div>
									<div class="flex flex-col gap-0.5">
										<span class="text-xs font-bold text-foreground">{token.name}</span>
										<div class="flex items-center gap-1.5">
											<span class="text-[11px] font-mono text-muted-foreground">
												ID: #{token.id}
											</span>
											<button
												type="button"
												class="text-muted-foreground hover:text-foreground transition-colors cursor-pointer p-0.5"
												title="Copiar ID"
												onclick={async () => {
													const ok = await copyToClipboard(String(token.id), "ID do Token");
													if (ok) {
														copiedTokenId = token.id;
														setTimeout(() => (copiedTokenId = null), 2000);
													}
												}}
											>
												{#if copiedTokenId === token.id}
													<CheckIcon class="size-3 text-emerald-500" />
												{:else}
													<CopyIcon class="size-3" />
												{/if}
											</button>
										</div>
									</div>
								</div>
							</Table.Cell>

							<!-- Escopos -->
							<Table.Cell class="py-3.5">
								<div class="flex flex-wrap gap-1 max-w-xs">
									{#each token.scopes as sc}
										{#if sc === "admin"}
											<Badge variant="default" class="text-[10px] px-1.5 py-0 font-mono">
												admin
											</Badge>
										{:else if sc === "monitoring"}
											<Badge variant="secondary" class="text-[10px] px-1.5 py-0 font-mono">
												monitoring
											</Badge>
										{:else}
											<Badge variant="outline" class="text-[10px] px-1.5 py-0 font-mono text-muted-foreground">
												{sc}
											</Badge>
										{/if}
									{/each}
								</div>
							</Table.Cell>

							<!-- Criado Em -->
							<Table.Cell class="py-3.5 text-xs text-muted-foreground whitespace-nowrap">
								{formatDate(token.created_at)}
							</Table.Cell>

							<!-- Último Acesso -->
							<Table.Cell class="py-3.5 whitespace-nowrap">
								<span class="text-xs text-muted-foreground" title={formatDate(token.last_used)}>
									{formatRelative(token.last_used)}
								</span>
							</Table.Cell>

							<!-- Validade / Status -->
							<Table.Cell class="py-3.5 whitespace-nowrap">
								{#if expired}
									<Badge variant="destructive" class="text-[10px] px-1.5 py-0 font-medium">
										Expirado
									</Badge>
									<p class="text-[10px] text-destructive/80 mt-0.5">
										{formatDate(token.expires_at)}
									</p>
								{:else if token.expires_at}
									<Badge variant="outline" class="text-[10px] px-1.5 py-0 font-medium text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
										Ativo
									</Badge>
									<p class="text-[10px] text-muted-foreground mt-0.5">
										Expira em {formatDate(token.expires_at)}
									</p>
								{:else}
									<Badge variant="outline" class="text-[10px] px-1.5 py-0 font-medium text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
										Ativo (Permanente)
									</Badge>
								{/if}
							</Table.Cell>

							<!-- Ações -->
							<Table.Cell class="py-3.5 text-right whitespace-nowrap">
								<div class="flex items-center justify-end gap-1.5">
									<Button
										variant="outline"
										size="sm"
										class="rounded-xl cursor-pointer text-xs h-8 px-2.5"
										title="Renovar chave (gera novo token secreto)"
										onclick={() => confirmRenew(token)}
									>
										<RotateCwIcon data-icon="inline-start" />
										Renovar
									</Button>

									<Button
										variant="outline"
										size="sm"
										class="rounded-xl cursor-pointer text-xs h-8 px-2.5 text-destructive hover:bg-destructive/10 border-destructive/30"
										title="Revogar e excluir token"
										onclick={() => confirmRevoke(token)}
									>
										<Trash2Icon data-icon="inline-start" />
										Revogar
									</Button>
								</div>
							</Table.Cell>
						</Table.Row>
					{/each}
				</Table.Body>
			</Table.Root>
		{/if}
	</Card.Content>
</Card.Root>

<!-- AlertDialog para Revogação / Exclusão -->
<AlertDialog.Root bind:open={isRevokeOpen}>
	<AlertDialog.Content class="rounded-2xl">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold text-foreground">
				Revogar Chave de API?
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Tem certeza que deseja revogar permanentemente a chave <strong>{tokenToRevoke?.name}</strong> (ID #{tokenToRevoke?.id})? Qualquer automação ou cliente que utilize este token perderá o acesso imediatamente.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="rounded-xl cursor-pointer text-xs">
				Cancelar
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="rounded-xl cursor-pointer text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={handleRevokeToken}
				disabled={isRevoking}
			>
				{#if isRevoking}
					<Loader2Icon data-icon="inline-start" class="animate-spin" />
					Revogando...
				{:else}
					Sim, Revogar Chave
				{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>

<!-- AlertDialog para Renovação -->
<AlertDialog.Root bind:open={isRenewOpen}>
	<AlertDialog.Content class="rounded-2xl">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold text-foreground">
				Renovar Chave de API?
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				A renovação da chave <strong>{tokenToRenew?.name}</strong> revogará imediatamente o segredo anterior e gerará um novo token com os mesmos escopos e período de expiração.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="rounded-xl cursor-pointer text-xs">
				Cancelar
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="rounded-xl cursor-pointer text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
				onclick={handleRenewToken}
				disabled={isRenewing}
			>
				{#if isRenewing}
					<Loader2Icon data-icon="inline-start" class="animate-spin" />
					Renovando...
				{:else}
					Confirmar e Renovar
				{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
