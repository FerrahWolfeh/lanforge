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

<StatCardGrid cols={4}>
	<!-- Total Users -->
	<StatCard
		label="Total Users"
		value={totalCount}
		icon={UsersIcon}
		color="primary"
		subtext="Active local accounts"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Security Model" value="Argon2id" />
			<StatCardFooterItem label="Access Policy" value="RBAC" />
		{/snippet}
	</StatCard>

	<!-- Admin Users -->
	<StatCard
		label="Administrators"
		value={adminCount}
		icon={ShieldCheckIcon}
		color="emerald"
		badge={{
			text: "Superuser",
			variant: "online",
			showDot: true
		}}
		subtext="Full system configuration"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Privilege"
				value="Unrestricted"
				color="text-emerald-500"
			/>
			<StatCardFooterItem label="Accounts" value={`${adminCount} admin`} />
		{/snippet}
	</StatCard>

	<!-- Operator Users -->
	<StatCard
		label="Operators"
		value={operatorCount}
		icon={WrenchIcon}
		color="sky"
		subtext="Network operations & telemetry"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Privilege" value="Maintenance" />
			<StatCardFooterItem label="Accounts" value={`${operatorCount} op`} />
		{/snippet}
	</StatCard>

	<!-- Viewer Users -->
	<StatCard
		label="Viewers"
		value={viewerCount}
		icon={EyeIcon}
		color="zinc"
		subtext="Read-only telemetry access"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Privilege" value="Read-Only" />
			<StatCardFooterItem label="Accounts" value={`${viewerCount} view`} />
		{/snippet}
	</StatCard>
</StatCardGrid>
