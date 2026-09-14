<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import UsersIcon from "@lucide/svelte/icons/users";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	import { listTokens } from "$lib/api/client";
	import type { AuthToken } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";

	import TokenStatsCards from "./components/TokenStatsCards.svelte";
	import TokenTable from "./components/TokenTable.svelte";
	import TokenValidatorCard from "./components/TokenValidatorCard.svelte";
	import TokenCreateDialog from "./components/TokenCreateDialog.svelte";
	import TokenSecretModal from "./components/TokenSecretModal.svelte";

	let tokens = $state<AuthToken[]>([]);
	let isLoading = $state(true);
	let isRefreshing = $state(false);

	let isCreateOpen = $state(false);
	let isSecretModalOpen = $state(false);
	let newlyCreatedToken = $state<AuthToken | null>(null);

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

	function handleTokenCreatedOrRenewed(token: AuthToken) {
		newlyCreatedToken = token;
		isSecretModalOpen = true;
	}
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
			<a href="/system/users">
				<Button
					variant="ghost"
					size="sm"
					class="rounded-xl cursor-pointer text-xs"
				>
					<UsersIcon data-icon="inline-start" />
					Usuários
				</Button>
			</a>

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
				onclick={() => (isCreateOpen = true)}
			>
				<PlusIcon data-icon="inline-start" />
				Nova Chave de API
			</Button>
		</div>
	</div>

	<!-- KPI Summary Cards -->
	<TokenStatsCards {tokens} {isLoading} />

	<!-- Main List Section -->
	<TokenTable
		{tokens}
		{isLoading}
		onRefresh={() => loadTokens(false)}
		onOpenCreate={() => (isCreateOpen = true)}
		onRenewed={handleTokenCreatedOrRenewed}
	/>

	<!-- Quick Integration Guides & Token Validator -->
	<TokenValidatorCard />
</div>

<!-- Modal de Criação de Novo Token -->
<TokenCreateDialog
	bind:open={isCreateOpen}
	onCreated={(token) => {
		handleTokenCreatedOrRenewed(token);
		loadTokens(false);
	}}
/>

<!-- Modal de Exibição Única do Segredo Gerado -->
<TokenSecretModal
	bind:open={isSecretModalOpen}
	token={newlyCreatedToken}
/>
