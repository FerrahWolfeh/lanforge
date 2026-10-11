<script lang="ts">
	import { onMount } from "svelte";
	import { Button } from "$lib/components/ui/button";
	import UsersIcon from "@lucide/svelte/icons/users";
	import UserPlusIcon from "@lucide/svelte/icons/user-plus";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import { userList } from "$lib/api/client";
	import type { UserInfo } from "$lib/api/types";
	import { auth } from "$lib/stores/auth.svelte";
	import { toast } from "svelte-sonner";

	import UserStatsCards from "./components/UserStatsCards.svelte";
	import UserTable from "./components/UserTable.svelte";
	import UserCreateDialog from "./components/UserCreateDialog.svelte";
	import UserPasswordDialog from "./components/UserPasswordDialog.svelte";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";

	const accessTabs: NavTabItem[] = [
		{ label: "Users & Access", href: "/system/users", icon: UsersIcon },
		{ label: "API & Auth Keys", href: "/system/keys", icon: KeyRoundIcon },
	];

	let users = $state<UserInfo[]>([]);
	let isLoading = $state(true);
	let isRefreshing = $state(false);

	let isCreateOpen = $state(false);
	let isPasswordOpen = $state(false);
	let selectedUserForPassword = $state<UserInfo | null>(null);

	async function loadUsers(showSpinner = true) {
		if (showSpinner) isRefreshing = true;
		try {
			users = await userList();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to load users.";
			toast.error(msg);
			users = [];
		} finally {
			isLoading = false;
			if (showSpinner) isRefreshing = false;
		}
	}

	onMount(() => {
		loadUsers(false);
	});

	function handleOpenPassword(user: UserInfo) {
		selectedUserForPassword = user;
		isPasswordOpen = true;
	}
</script>

<svelte:head>
	<title>Users & Access — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 max-w-6xl mx-auto w-full pb-12">
	<!-- Top Header -->
	<PageHeader
		title="Users & Access"
		description="Manage local user accounts for web authentication and permission controls in Lanforge."
		icon={UsersIcon}
	>
		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				class="rounded-xl cursor-pointer text-xs"
				onclick={() => loadUsers(true)}
				disabled={isRefreshing}
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={isRefreshing ? "animate-spin" : ""}
				/>
				Refresh
			</Button>

			<Button
				size="sm"
				class="rounded-xl cursor-pointer text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90 shadow-sm"
				onclick={() => (isCreateOpen = true)}
			>
				<UserPlusIcon data-icon="inline-start" />
				New User
			</Button>
		{/snippet}
	</PageHeader>

	<!-- Access Control Sub-Navigation Tabs -->
	<NavTabs tabs={accessTabs} ariaLabel="Access and authentication navigation" />

	<!-- KPI Summary Cards -->
	<UserStatsCards {users} {isLoading} />

	<!-- User Table -->
	<UserTable
		{users}
		{isLoading}
		currentUsername={auth.user?.username ?? null}
		onRefresh={() => loadUsers(false)}
		onOpenCreate={() => (isCreateOpen = true)}
		onChangePassword={handleOpenPassword}
	/>
</div>

<!-- User Creation Dialog -->
<UserCreateDialog
	bind:open={isCreateOpen}
	onCreated={() => loadUsers(false)}
/>

<!-- Password Change Dialog -->
<UserPasswordDialog
	bind:open={isPasswordOpen}
	user={selectedUserForPassword}
	onUpdated={() => loadUsers(false)}
/>
