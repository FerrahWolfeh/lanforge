<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import UsersIcon from "@lucide/svelte/icons/users";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import WrenchIcon from "@lucide/svelte/icons/wrench";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import type { UserInfo } from "$lib/api/types";

	let {
		users = [],
		isLoading = false
	}: {
		users: UserInfo[];
		isLoading: boolean;
	} = $props();

	const totalCount = $derived(users.length);
	const adminCount = $derived(users.filter((u) => u.role === "admin").length);
	const operatorCount = $derived(users.filter((u) => u.role === "operator").length);
	const viewerCount = $derived(users.filter((u) => u.role === "viewer").length);
</script>

<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
	<!-- Total Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Total de Usuários</Card.Description>
			<Card.Title class="text-2xl font-bold text-foreground">
				{#if isLoading}
					<Skeleton class="h-8 w-12 rounded-lg" />
				{:else}
					{totalCount}
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="pt-0 text-[11px] text-muted-foreground flex items-center gap-1.5">
			<UsersIcon class="size-3.5 text-primary" />
			<span>Contas locais ativas</span>
		</Card.Content>
	</Card.Root>

	<!-- Admin Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Administradores</Card.Description>
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
			<span>Controle total do sistema</span>
		</Card.Content>
	</Card.Root>

	<!-- Operator Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Operadores</Card.Description>
			<Card.Title class="text-2xl font-bold text-foreground">
				{#if isLoading}
					<Skeleton class="h-8 w-12 rounded-lg" />
				{:else}
					{operatorCount}
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="pt-0 text-[11px] text-muted-foreground flex items-center gap-1.5">
			<WrenchIcon class="size-3.5 text-sky-500" />
			<span>Operações diárias de rede</span>
		</Card.Content>
	</Card.Root>

	<!-- Viewer Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Visualizadores</Card.Description>
			<Card.Title class="text-2xl font-bold text-foreground">
				{#if isLoading}
					<Skeleton class="h-8 w-12 rounded-lg" />
				{:else}
					{viewerCount}
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="pt-0 text-[11px] text-muted-foreground flex items-center gap-1.5">
			<EyeIcon class="size-3.5 text-muted-foreground" />
			<span>Acesso somente leitura</span>
		</Card.Content>
	</Card.Root>
</div>
