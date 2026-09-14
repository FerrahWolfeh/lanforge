<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import * as Empty from "$lib/components/ui/empty";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import UsersIcon from "@lucide/svelte/icons/users";
	import SearchIcon from "@lucide/svelte/icons/search";
	import UserPlusIcon from "@lucide/svelte/icons/user-plus";
	import KeyIcon from "@lucide/svelte/icons/key";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import UserIcon from "@lucide/svelte/icons/user";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { userDelete } from "$lib/api/client";
	import type { UserInfo } from "$lib/api/types";
	import { toast } from "svelte-sonner";

	let {
		users = [],
		isLoading = false,
		currentUsername = null,
		onOpenCreate,
		onRefresh,
		onChangePassword
	}: {
		users: UserInfo[];
		isLoading: boolean;
		currentUsername: string | null;
		onOpenCreate: () => void;
		onRefresh: () => Promise<void> | void;
		onChangePassword: (user: UserInfo) => void;
	} = $props();

	let searchQuery = $state("");
	let roleFilter = $state<string>("all");

	// Delete confirmation
	let isDeleteOpen = $state(false);
	let userToDelete = $state<UserInfo | null>(null);
	let isDeleting = $state(false);

	function formatDate(ts: number | null | undefined): string {
		if (!ts) return "—";
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
		if (!ts) return "Nunca acessou";
		const ms = ts > 1e11 ? ts : ts * 1000;
		const diffSecs = Math.round((Date.now() - ms) / 1000);
		if (diffSecs < 60) return "Agora mesmo";
		if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m atrás`;
		if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h atrás`;
		return `${Math.floor(diffSecs / 86400)}d atrás`;
	}

	function confirmDelete(u: UserInfo) {
		userToDelete = u;
		isDeleteOpen = true;
	}

	async function handleDeleteUser() {
		if (!userToDelete) return;
		isDeleting = true;
		try {
			await userDelete(userToDelete.username);
			toast.success(`Usuário '${userToDelete.username}' excluído.`);
			isDeleteOpen = false;
			userToDelete = null;
			await onRefresh();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Falha ao excluir usuário.";
			toast.error(msg);
		} finally {
			isDeleting = false;
		}
	}

	const filteredUsers = $derived(
		users.filter((u) => {
			const query = searchQuery.trim().toLowerCase();
			const matchesSearch = !query || u.username.toLowerCase().includes(query);
			const matchesRole = roleFilter === "all" || u.role === roleFilter;
			return matchesSearch && matchesRole;
		})
	);
</script>

<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/60">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div class="flex flex-col gap-0.5">
				<Card.Title class="text-base font-bold text-foreground">
					Usuários Cadastrados
				</Card.Title>
				<Card.Description class="text-xs">
					Contas que possuem permissão de login no painel web ou nas APIs protegidas.
				</Card.Description>
			</div>

			<!-- Search & Filter Controls -->
			<div class="flex flex-wrap items-center gap-2">
				<div class="relative w-full sm:w-56">
					<SearchIcon class="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
					<Input
						placeholder="Buscar por nome de usuário..."
						bind:value={searchQuery}
						class="text-xs pl-8 rounded-xl h-8.5 bg-background"
					/>
				</div>

				<select
					bind:value={roleFilter}
					class="h-8.5 text-xs rounded-xl bg-background border border-input px-2.5 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring"
					aria-label="Filtrar por perfil"
				>
					<option value="all">Todos os Perfis</option>
					<option value="admin">Administrador</option>
					<option value="operator">Operador</option>
					<option value="viewer">Visualizador</option>
				</select>
			</div>
		</div>
	</Card.Header>

	<Card.Content class="p-0">
		{#if isLoading}
			<div class="p-4 flex flex-col gap-3">
				<Skeleton class="h-14 w-full rounded-xl" />
				<Skeleton class="h-14 w-full rounded-xl" />
			</div>
		{:else if filteredUsers.length === 0}
			<Empty.Root class="py-12">
				<Empty.Header>
					<Empty.Media>
						<div class="size-12 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
							<UsersIcon class="size-6" />
						</div>
					</Empty.Media>
					<Empty.Title>Nenhum usuário encontrado</Empty.Title>
					<Empty.Description class="text-xs max-w-sm">
						{#if searchQuery.trim() || roleFilter !== 'all'}
							Nenhum usuário corresponde aos filtros informados.
						{:else}
							Nenhuma conta adicional cadastrada no sistema.
						{/if}
					</Empty.Description>
				</Empty.Header>
				<Empty.Content>
					{#if !searchQuery.trim() && roleFilter === 'all'}
						<Button
							size="sm"
							class="rounded-xl cursor-pointer text-xs"
							onclick={onOpenCreate}
						>
							<UserPlusIcon data-icon="inline-start" />
							Criar Usuário
						</Button>
					{:else}
						<Button
							variant="outline"
							size="sm"
							class="rounded-xl cursor-pointer text-xs"
							onclick={() => {
								searchQuery = "";
								roleFilter = "all";
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
						<Table.Head class="text-xs font-semibold">Usuário</Table.Head>
						<Table.Head class="text-xs font-semibold">Perfil / Nível</Table.Head>
						<Table.Head class="text-xs font-semibold">Criado Em</Table.Head>
						<Table.Head class="text-xs font-semibold">Último Acesso</Table.Head>
						<Table.Head class="text-xs font-semibold text-right">Ações</Table.Head>
					</Table.Row>
				</Table.Header>
				<Table.Body>
					{#each filteredUsers as user (user.username)}
						{@const isSelf = Boolean(currentUsername && user.username.toLowerCase() === currentUsername.toLowerCase())}
						<Table.Row class="border-b border-border/50 hover:bg-muted/30 transition-colors">
							<!-- Usuário -->
							<Table.Cell class="py-3.5">
								<div class="flex items-center gap-2.5">
									<div class="size-8 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
										<UserIcon class="size-4" />
									</div>
									<div class="flex flex-col gap-0.5">
										<div class="flex items-center gap-1.5">
											<span class="text-xs font-bold text-foreground">{user.username}</span>
											{#if isSelf}
												<Badge variant="outline" class="text-[10px] px-1.5 py-0 border-primary/30 text-primary bg-primary/10">
													Você
												</Badge>
											{/if}
										</div>
										<span class="text-[11px] font-mono text-muted-foreground">
											ID: #{user.id}
										</span>
									</div>
								</div>
							</Table.Cell>

							<!-- Perfil -->
							<Table.Cell class="py-3.5">
								{#if user.role === "admin"}
									<Badge variant="default" class="text-[10px] px-2 py-0.5">
										Administrador
									</Badge>
								{:else if user.role === "operator"}
									<Badge variant="secondary" class="text-[10px] px-2 py-0.5">
										Operador
									</Badge>
								{:else}
									<Badge variant="outline" class="text-[10px] px-2 py-0.5 text-muted-foreground">
										Visualizador
									</Badge>
								{/if}
							</Table.Cell>

							<!-- Criado Em -->
							<Table.Cell class="py-3.5 text-xs text-muted-foreground whitespace-nowrap">
								{formatDate(user.created_at)}
							</Table.Cell>

							<!-- Último Acesso -->
							<Table.Cell class="py-3.5 whitespace-nowrap">
								<span class="text-xs text-muted-foreground" title={formatDate(user.last_login)}>
									{formatRelative(user.last_login)}
								</span>
							</Table.Cell>

							<!-- Ações -->
							<Table.Cell class="py-3.5 text-right whitespace-nowrap">
								<div class="flex items-center justify-end gap-1.5">
									<Button
										variant="outline"
										size="sm"
										class="rounded-xl cursor-pointer text-xs h-8 px-2.5"
										title="Redefinir senha do usuário"
										onclick={() => onChangePassword(user)}
									>
										<KeyIcon data-icon="inline-start" />
										Senha
									</Button>

									<Button
										variant="outline"
										size="sm"
										class="rounded-xl cursor-pointer text-xs h-8 px-2.5 text-destructive hover:bg-destructive/10 border-destructive/30"
										title={isSelf ? "Você não pode excluir sua própria conta" : "Excluir usuário"}
										disabled={isSelf}
										onclick={() => confirmDelete(user)}
									>
										<Trash2Icon data-icon="inline-start" />
										Excluir
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

<!-- AlertDialog para Exclusão de Usuário -->
<AlertDialog.Root bind:open={isDeleteOpen}>
	<AlertDialog.Content class="rounded-2xl">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold text-foreground">
				Excluir Usuário?
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Tem certeza que deseja excluir permanentemente o usuário <strong>{userToDelete?.username}</strong>? Esta ação não pode ser desfeita e o usuário perderá o acesso imediatamente.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="rounded-xl cursor-pointer text-xs">
				Cancelar
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="rounded-xl cursor-pointer text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={handleDeleteUser}
				disabled={isDeleting}
			>
				{#if isDeleting}
					<Loader2Icon data-icon="inline-start" class="animate-spin" />
					Excluindo...
				{:else}
					Sim, Excluir Usuário
				{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
