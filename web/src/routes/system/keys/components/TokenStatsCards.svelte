<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import KeyIcon from "@lucide/svelte/icons/key";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import type { AuthToken } from "$lib/api/types";

	let {
		tokens = [],
		isLoading = false
	}: {
		tokens: AuthToken[];
		isLoading: boolean;
	} = $props();

	function isExpired(t: AuthToken): boolean {
		if (!t.expires_at) return false;
		const nowSecs = Math.floor(Date.now() / 1000);
		const expSecs = t.expires_at > 1e11 ? Math.floor(t.expires_at / 1000) : t.expires_at;
		return expSecs < nowSecs;
	}

	const totalCount = $derived(tokens.length);
	const activeCount = $derived(tokens.filter((t) => !isExpired(t)).length);
	const expiredCount = $derived(tokens.filter((t) => isExpired(t)).length);
	const adminCount = $derived(tokens.filter((t) => t.scopes.includes("admin")).length);
</script>

<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
	<!-- Total Tokens -->
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

	<!-- Active Tokens -->
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

	<!-- Expired Tokens -->
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

	<!-- Admin Scope -->
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
