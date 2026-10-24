<script lang="ts">
	import UsersIcon from "@lucide/svelte/icons/users";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import WrenchIcon from "@lucide/svelte/icons/wrench";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
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

<StatCardGrid cols={2}>
	<!-- Card 1: Total Users -->
	<StatCard
		label="Configured Accounts"
		value={totalCount}
		icon={UsersIcon}
		color="primary"
		subtext="Local authentication identities"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Password Hash" value="Argon2id" />
			<StatCardFooterItem label="Access Policy" value="Role-Based (RBAC)" />
		{/snippet}
	</StatCard>

	<!-- Card 2: Privileged Roles -->
	<StatCard
		label="Administrative Access"
		value={adminCount}
		icon={ShieldCheckIcon}
		color="emerald"
		badge={{
			text: `${adminCount} Superuser${adminCount === 1 ? '' : 's'}`,
			variant: adminCount > 0 ? "online" : "warning",
			showDot: true
		}}
		subtext="Full system configuration privileges"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Operators" value={`${operatorCount} maintenance`} />
			<StatCardFooterItem label="Viewers" value={`${viewerCount} read-only`} />
		{/snippet}
	</StatCard>
</StatCardGrid>
