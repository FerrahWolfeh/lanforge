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

	const safeUsers = $derived(Array.isArray(users) ? users : []);
	const totalCount = $derived(safeUsers.length);
	const adminCount = $derived(safeUsers.filter((u) => u.role === "admin").length);
	const operatorCount = $derived(safeUsers.filter((u) => u.role === "operator").length);
	const viewerCount = $derived(safeUsers.filter((u) => u.role === "viewer").length);
</script>

<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
	<!-- Total Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Total Users</Card.Description>
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
			<span>Active local accounts</span>
		</Card.Content>
	</Card.Root>

	<!-- Admin Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Administrators</Card.Description>
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
			<span>Full system control</span>
		</Card.Content>
	</Card.Root>

	<!-- Operator Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Operators</Card.Description>
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
			<span>Daily network operations</span>
		</Card.Content>
	</Card.Root>

	<!-- Viewer Users -->
	<Card.Root class="rounded-2xl border-border/70 bg-card shadow-xs">
		<Card.Header class="pb-2">
			<Card.Description class="text-xs font-medium">Viewers</Card.Description>
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
			<span>Read-only access</span>
		</Card.Content>
	</Card.Root>
</div>
