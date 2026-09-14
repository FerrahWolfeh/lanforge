<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import * as Table from "$lib/components/ui/table";
	import * as Field from "$lib/components/ui/field";
	import * as Empty from "$lib/components/ui/empty";
	import * as Alert from "$lib/components/ui/alert";
	import * as Tabs from "$lib/components/ui/tabs";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";

	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import SearchIcon from "@lucide/svelte/icons/search";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import TerminalIcon from "@lucide/svelte/icons/terminal";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import KeyIcon from "@lucide/svelte/icons/key";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";

	import {
		listTokens,
		generateToken,
		deleteToken,
		renewToken,
		validateToken
	} from "$lib/api/client";
	import type { AuthToken, GenerateTokenRequest } from "$lib/api/types";
	import { auth } from "$lib/stores/auth.svelte";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";

	let tokens = $state<AuthToken[]>([]);
	let isLoading = $state(true);
	let isRefreshing = $state(false);
	let searchQuery = $state("");
	let scopeFilter = $state<string>("all");

	// Create dialog
	let isCreateOpen = $state(false);
	let formName = $state("");
	let formExpiryPreset = $state<"never" | "7d" | "30d" | "90d" | "1y">("30d");
	let formScopes = $state<Record<string, boolean>>({
		admin: true,
		monitoring: false,
		device_write: false,
		dns_query: false,
		upstream_write: false,
		config_write: false
	});
	let isSubmitting = $state(false);

	// Secret display modal (shown once after creation or renewal)
	let isSecretModalOpen = $state(false);
	let newlyCreatedToken = $state<AuthToken | null>(null);
	let hasCopiedSecret = $state(false);

	// Revoke confirmation dialog
	let isRevokeOpen = $state(false);
	let tokenToRevoke = $state<AuthToken | null>(null);
	let isRevoking = $state(false);

	// Renew confirmation dialog
	let isRenewOpen = $state(false);
	let tokenToRenew = $state<AuthToken | null>(null);
	let isRenewing = $state(false);

	// Token Validator
	let testTokenInput = $state("");
	let isValidating = $state(false);
	let validationResult = $state<{ valid: boolean; checked: boolean } | null>(null);

	// Clipboard state
	let copiedTokenId = $state<string | number | null>(null);

	const availableScopes = [
		{
			id: "admin",
			label: "Admin",
			desc: "Acesso administrativo irrestrito a todos os serviços, APIs e banco de dados"
		},
		{
			id: "monitoring",
			label: "Monitoring",
			desc: "Apenas leitura de telemetria, status dos serviços e métricas agregadas"
		},
		{
			id: "device_write",
			label: "Device Write",
			desc: "Registro, alteração de propriedades e disparo de pacotes Wake-on-LAN"
		},
		{
			id: "dns_query",
			label: "DNS Query",
			desc: "Execução de consultas de teste no resolvedor e inspeção de logs DNS"
		},
		{
			id: "upstream_write",
			label: "Upstream Write",
			desc: "Configuração e manutenção da lista de provedores DNS upstream"
		},
		{
			id: "config_write",
			label: "Config Write",
			desc: "Importação e aplicação de configurações de pools, leases e roteamento"
		}
	];

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

	function getExpiresAtTimestamp(preset: "never" | "7d" | "30d" | "90d" | "1y"): number | null {
		const now = Math.floor(Date.now() / 1000);
		switch (preset) {
			case "7d":
				return now + 7 * 86400;
			case "30d":
				return now + 30 * 86400;
			case "90d":
				return now + 90 * 86400;
			case "1y":
				return now + 365 * 86400;
			case "never":
			default:
				return null;
		}
	}

	async function loadTokens(showSpinner = true) {
		if (showSpinner) isRefreshing = true;
		try {
			tokens = await listTokens();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro ao listar tokens.";
			toast.error(msg);
		} finally {
			isLoading = false;
			if (showSpinner) isRefreshing = false;
		}
	}

	onMount(() => {
		loadTokens(false);
	});

	function openCreateDialog() {
		formName = "";
		formExpiryPreset = "30d";
		formScopes = {
			admin: true,
			monitoring: false,
			device_write: false,
			dns_query: false,
			upstream_write: false,
			config_write: false
		};
		isCreateOpen = true;
	}

	function toggleAdminScope(checked: boolean) {
		formScopes.admin = checked;
		if (checked) {
			// In admin mode, other scopes are implied
			formScopes.monitoring = false;
			formScopes.device_write = false;
			formScopes.dns_query = false;
			formScopes.upstream_write = false;
			formScopes.config_write = false;
		}
	}

	async function handleCreateToken() {
		if (!formName.trim()) {
			toast.error("Informe um nome ou identificador para a chave.");
			return;
		}

		isSubmitting = true;
		try {
			const selectedScopes: string[] = [];
			if (formScopes.admin) {
				selectedScopes.push("admin");
			} else {
				for (const [scope, enabled] of Object.entries(formScopes)) {
					if (enabled) selectedScopes.push(scope);
				}
			}

			if (selectedScopes.length === 0) {
				selectedScopes.push("admin");
			}

			const payload: GenerateTokenRequest = {
				name: formName.trim(),
				scopes: selectedScopes,
				expires_at: getExpiresAtTimestamp(formExpiryPreset)
			};

			const created = await generateToken(payload);
			toast.success(`Chave '${created.name}' gerada com sucesso!`);
			isCreateOpen = false;

			// Show the secret key once
			newlyCreatedToken = created;
			hasCopiedSecret = false;
			isSecretModalOpen = true;

			await loadTokens(false);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro ao gerar chave de API.";
			toast.error(msg);
		} finally {
			isSubmitting = false;
		}
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
			await loadTokens(false);
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

			// Show new secret key
			newlyCreatedToken = renewed;
			hasCopiedSecret = false;
			isSecretModalOpen = true;

			await loadTokens(false);
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Erro ao renovar chave.";
			toast.error(msg);
		} finally {
			isRenewing = false;
		}
	}

	async function copyToClipboard(text: string, label: string) {
		try {
			await navigator.clipboard.writeText(text);
			toast.success(`${label} copiado para a área de transferência!`);
		} catch {
			toast.error("Falha ao copiar para a área de transferência.");
		}
	}

	async function handleValidateToken() {
		const trimmed = testTokenInput.trim();
		if (!trimmed) {
			toast.error("Informe um token para validação.");
			return;
		}
		isValidating = true;
		validationResult = null;
		try {
			const res = await validateToken(trimmed);
			validationResult = { valid: res.valid, checked: true };
			if (res.valid) {
				toast.success("Token ativo e válido no sistema!");
			} else {
				toast.error("Token inválido, inexistente ou expirado.");
			}
		} catch (err: unknown) {
			validationResult = { valid: false, checked: true };
			const msg = err instanceof Error ? err.message : "Falha na checagem.";
			toast.error(msg);
		} finally {
			isValidating = false;
		}
	}

	const totalCount = $derived(tokens.length);
	const activeCount = $derived(tokens.filter((t) => !isExpired(t)).length);
	const expiredCount = $derived(tokens.filter((t) => isExpired(t)).length);
	const adminCount = $derived(tokens.filter((t) => t.scopes.includes("admin")).length);

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

<div class="flex flex-col gap-6 max-w-6xl mx-auto w-full pb-12">
	<!-- Top Header -->
	<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
		<div class="flex flex-col gap-1">
			<h1 class="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
				<KeyRoundIcon class="size-6 text-primary" />
				Chaves de Autenticação & API
			</h1>
			<p class="text-xs text-muted-foreground">
				Gerencie tokens de acesso de longa duração (Bearer API Tokens) para integrações, scripts de automação e clientes remotos.
			</p>
		</div>

		<div class="flex items-center gap-2 self-start sm:self-center">
			<Button
				variant="outline"
				size="sm"
				class="rounded-xl cursor-pointer text-xs"
				onclick={() => loadTokens(true)}
				disabled={isRefreshing}
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={isRefreshing ? "animate-spin" : ""}
				/>
				Atualizar
			</Button>

			<Button
				size="sm"
				class="rounded-xl cursor-pointer text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
				onclick={openCreateDialog}
			>
				<PlusIcon data-icon="inline-start" />
				Nova Chave de API
			</Button>
		</div>
	</div>

	<!-- KPI Summary Cards -->
	<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
		<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
			<Card.Header class="pb-2">
				<Card.Description class="text-xs font-medium">Total de Chaves</Card.Description>
				<Card.Title class="text-2xl font-bold text-foreground">
					{#if isLoading}
						<Skeleton class="h-8 w-12 rounded-lg" />
					{:else}
						{totalCount}
					{/if}
				</Card.Title>
			</Card.Header>
			<Card.Content class="pt-0 text-[11px] text-muted-foreground flex items-center gap-1.5">
				<KeyIcon class="size-3.5 text-primary" />
				<span>Tokens registrados na base</span>
			</Card.Content>
		</Card.Root>

		<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
			<Card.Header class="pb-2">
				<Card.Description class="text-xs font-medium">Tokens Ativos</Card.Description>
				<Card.Title class="text-2xl font-bold text-emerald-600 dark:text-emerald-400">
					{#if isLoading}
						<Skeleton class="h-8 w-12 rounded-lg" />
					{:else}
						{activeCount}
					{/if}
				</Card.Title>
			</Card.Header>
			<Card.Content class="pt-0 text-[11px] text-muted-foreground flex items-center gap-1.5">
				<CheckCircle2Icon class="size-3.5 text-emerald-500" />
				<span>Dentro do prazo de validade</span>
			</Card.Content>
		</Card.Root>

		<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
			<Card.Header class="pb-2">
				<Card.Description class="text-xs font-medium">Tokens Expirados</Card.Description>
				<Card.Title class="text-2xl font-bold {expiredCount > 0 ? 'text-amber-500' : 'text-muted-foreground'}">
					{#if isLoading}
						<Skeleton class="h-8 w-12 rounded-lg" />
					{:else}
						{expiredCount}
					{/if}
				</Card.Title>
			</Card.Header>
			<Card.Content class="pt-0 text-[11px] text-muted-foreground flex items-center gap-1.5">
				<ClockIcon class="size-3.5 text-amber-500" />
				<span>Necessitam renovação</span>
			</Card.Content>
		</Card.Root>

		<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
			<Card.Header class="pb-2">
				<Card.Description class="text-xs font-medium">Acesso Administrador</Card.Description>
				<Card.Title class="text-2xl font-bold text-foreground">
					{#if isLoading}
						<Skeleton class="h-8 w-12 rounded-lg" />
					{:else}
						{adminCount}
					{/if}
				</Card.Title>
			</Card.Header>
			<Card.Content class="pt-0 text-[11px] text-muted-foreground flex items-center gap-1.5">
				<ShieldCheckIcon class="size-3.5 text-primary" />
				<span>Escopo total de permissões</span>
			</Card.Content>
		</Card.Root>
	</div>

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
								onclick={openCreateDialog}
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
													onclick={() => {
														copyToClipboard(String(token.id), "ID do Token");
														copiedTokenId = token.id;
														setTimeout(() => (copiedTokenId = null), 2000);
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

	<!-- Quick Integration Guides & Token Validator -->
	<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
		<!-- Integration Quick Guide -->
		<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
			<Card.Header class="pb-3">
				<Card.Title class="text-sm font-bold flex items-center gap-2 text-foreground">
					<TerminalIcon class="size-4 text-primary" />
					Como Utilizar na Prática
				</Card.Title>
				<Card.Description class="text-xs">
					Exemplos de autenticação para automações com cURL ou na CLI do Lanforge.
				</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col gap-3">
				<div class="flex flex-col gap-1">
					<span class="text-[11px] font-semibold text-muted-foreground">Exemplo cURL HTTP:</span>
					<div class="p-2.5 rounded-xl bg-muted/40 border border-border/60 font-mono text-[11px] text-foreground break-all select-all">
						curl -H "Authorization: Bearer lf_ak_..." \
						<br />&nbsp;&nbsp;http://&lt;ip-lanforge&gt;:3000/api/v1/status
					</div>
				</div>

				<div class="flex flex-col gap-1">
					<span class="text-[11px] font-semibold text-muted-foreground">Exemplo CLI Lanforge:</span>
					<div class="p-2.5 rounded-xl bg-muted/40 border border-border/60 font-mono text-[11px] text-foreground break-all select-all">
						lanforge --token lf_ak_... status
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Token Tester / Validator -->
		<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
			<Card.Header class="pb-3">
				<Card.Title class="text-sm font-bold flex items-center gap-2 text-foreground">
					<ShieldCheckIcon class="size-4 text-primary" />
					Validador de Token
				</Card.Title>
				<Card.Description class="text-xs">
					Teste se um token específico é reconhecido e está atualmente ativo no daemon.
				</Card.Description>
			</Card.Header>
			<Card.Content class="flex flex-col gap-3">
				<div class="flex flex-col gap-1.5">
					<Input
						placeholder="Cole o token (lf_ak_... ou JWT) para testar..."
						bind:value={testTokenInput}
						class="text-xs font-mono rounded-xl h-9 bg-background"
					/>
				</div>

				<div class="flex items-center justify-between gap-2">
					<Button
						variant="outline"
						size="sm"
						class="rounded-xl cursor-pointer text-xs"
						onclick={handleValidateToken}
						disabled={isValidating || !testTokenInput.trim()}
					>
						{#if isValidating}
							<Loader2Icon data-icon="inline-start" class="animate-spin" />
							Validando...
						{:else}
							<ShieldCheckIcon data-icon="inline-start" />
							Checar Token
						{/if}
					</Button>

					{#if validationResult?.checked}
						{#if validationResult.valid}
							<Badge variant="outline" class="text-xs text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
								<CheckCircle2Icon class="size-3.5 mr-1" />
								Token Válido
							</Badge>
						{:else}
							<Badge variant="destructive" class="text-xs">
								<XCircleIcon class="size-3.5 mr-1" />
								Token Inválido ou Expirado
							</Badge>
						{/if}
					{/if}
				</div>
			</Card.Content>
		</Card.Root>
	</div>
</div>

<!-- Modal de Criação de Novo Token -->
<Dialog.Root bind:open={isCreateOpen}>
	<Dialog.Content class="sm:max-w-lg rounded-2xl">
		<Dialog.Header>
			<Dialog.Title class="text-base font-bold flex items-center gap-2">
				<KeyRoundIcon class="size-5 text-primary" />
				Nova Chave de API
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Gere uma chave de autenticação para seu aplicativo ou serviço. O segredo será exibido somente uma vez.
			</Dialog.Description>
		</Dialog.Header>

		<form
			onsubmit={(e) => {
				e.preventDefault();
				handleCreateToken();
			}}
			class="flex flex-col gap-4 py-2"
		>
			<Field.FieldGroup class="flex flex-col gap-3">
				<!-- Nome -->
				<Field.Field>
					<Field.FieldLabel for="token-name" class="text-xs font-semibold">
						Nome / Identificador *
					</Field.FieldLabel>
					<Input
						id="token-name"
						placeholder="Ex: Home Assistant, Prometheus, Backup Script"
						bind:value={formName}
						class="text-xs rounded-xl h-9 bg-background"
					/>
					<Field.FieldDescription class="text-[11px] text-muted-foreground">
						Um rótulo descritivo para reconhecer onde esta chave está configurada.
					</Field.FieldDescription>
				</Field.Field>

				<!-- Validade -->
				<Field.Field>
					<Field.FieldLabel for="token-expiry" class="text-xs font-semibold">
						Tempo de Validade
					</Field.FieldLabel>
					<select
						id="token-expiry"
						bind:value={formExpiryPreset}
						class="w-full h-9 text-xs rounded-xl bg-background border border-input px-3 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
					>
						<option value="7d">7 dias</option>
						<option value="30d">30 dias (Recomendado)</option>
						<option value="90d">90 dias</option>
						<option value="1y">1 ano</option>
						<option value="never">Nunca expira (Uso permanente)</option>
					</select>
				</Field.Field>

				<!-- Escopos -->
				<Field.FieldSet class="flex flex-col gap-2 pt-1">
					<Field.FieldLegend class="text-xs font-semibold">
						Permissões & Escopos
					</Field.FieldLegend>
					<div class="flex flex-col gap-2 rounded-xl border border-border/60 p-3 bg-muted/20">
						{#each availableScopes as sc}
							<div class="flex items-start justify-between gap-3 py-1">
								<div class="flex flex-col gap-0.5">
									<span class="text-xs font-semibold text-foreground flex items-center gap-1.5">
										{sc.label}
										{#if sc.id === 'admin'}
											<Badge variant="default" class="text-[9px] px-1 py-0">Recomendado</Badge>
										{/if}
									</span>
									<span class="text-[11px] text-muted-foreground leading-tight">
										{sc.desc}
									</span>
								</div>

								{#if sc.id === 'admin'}
									<Switch
										id="scope-admin"
										checked={formScopes.admin}
										onCheckedChange={toggleAdminScope}
									/>
								{:else}
									<Switch
										id="scope-{sc.id}"
										checked={formScopes.admin || formScopes[sc.id]}
										disabled={formScopes.admin}
										onCheckedChange={(c) => (formScopes[sc.id] = c)}
									/>
								{/if}
							</div>
							{#if sc.id === 'admin'}
								<Separator class="my-1" />
							{/if}
						{/each}
					</div>
				</Field.FieldSet>
			</Field.FieldGroup>

			<Dialog.Footer class="pt-2">
				<Button
					type="button"
					variant="outline"
					class="rounded-xl cursor-pointer text-xs"
					onclick={() => (isCreateOpen = false)}
				>
					Cancelar
				</Button>

				<Button
					type="submit"
					class="rounded-xl cursor-pointer text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
					disabled={isSubmitting || !formName.trim()}
				>
					{#if isSubmitting}
						<Loader2Icon data-icon="inline-start" class="animate-spin" />
						Gerando Chave...
					{:else}
						<SparklesIcon data-icon="inline-start" />
						Gerar Chave de API
					{/if}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>

<!-- Modal de Exibição Única do Segredo Gerado -->
<Dialog.Root bind:open={isSecretModalOpen}>
	<Dialog.Content class="sm:max-w-lg rounded-2xl">
		<Dialog.Header>
			<Dialog.Title class="text-base font-bold text-foreground flex items-center gap-2">
				<CheckCircle2Icon class="size-5 text-emerald-500" />
				Chave de API Gerada com Sucesso!
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Copie sua chave agora. Por segurança, este segredo não poderá ser visualizado novamente.
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex flex-col gap-4 py-2">
			<!-- Alert Callout -->
			<Alert.Root class="rounded-xl border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200">
				<AlertTriangleIcon class="size-4 text-amber-600 dark:text-amber-400" />
				<Alert.Title class="text-xs font-bold">Atenção!</Alert.Title>
				<Alert.Description class="text-[11px] leading-relaxed mt-0.5">
					Guarde esta chave em um local seguro (como cofre de senhas ou arquivo de ambiente). Caso você a perca, será necessário revogá-la e gerar uma nova.
				</Alert.Description>
			</Alert.Root>

			<!-- Token Display Box -->
			<div class="flex flex-col gap-1.5">
				<span class="text-xs font-semibold text-foreground">Segredo da Chave (Token):</span>
				<div class="flex items-center gap-2 p-3 rounded-xl bg-muted/60 border border-border/80">
					<span class="font-mono text-xs font-bold text-foreground break-all flex-1 select-all">
						{newlyCreatedToken?.token ?? ""}
					</span>
					<Button
						variant="secondary"
						size="sm"
						class="rounded-xl cursor-pointer shrink-0 text-xs"
						onclick={() => {
							if (newlyCreatedToken?.token) {
								copyToClipboard(newlyCreatedToken.token, "Chave de API");
								hasCopiedSecret = true;
							}
						}}
					>
						{#if hasCopiedSecret}
							<CheckIcon data-icon="inline-start" class="text-emerald-500" />
							Copiado
						{:else}
							<CopyIcon data-icon="inline-start" />
							Copiar
						{/if}
					</Button>
				</div>
			</div>

			<!-- Quick Usage Snippet -->
			<div class="flex flex-col gap-1.5">
				<span class="text-[11px] font-semibold text-muted-foreground">Como autenticar requisições:</span>
				<div class="p-2.5 rounded-xl bg-muted/30 border border-border/60 font-mono text-[11px] text-foreground break-all select-all">
					Authorization: Bearer {newlyCreatedToken?.token ?? "lf_ak_..."}
				</div>
			</div>
		</div>

		<Dialog.Footer class="pt-2">
			<Button
				class="rounded-xl cursor-pointer text-xs w-full sm:w-auto"
				onclick={() => (isSecretModalOpen = false)}
			>
				Concluído
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>

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
