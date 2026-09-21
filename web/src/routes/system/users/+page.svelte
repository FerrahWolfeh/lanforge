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

	let users = $state<UserInfo[]>([]);
	let isLoading = $state(true);
	let isRefreshing = $state(false);

	let isCreateOpen = $state(false);
	let isPasswordOpen = $state(false);
	let selectedUserForPassword = $state<UserInfo | null>(null);

	async function loadUsers(showSpinner = true) {
		if (showSpinner) isRefreshing = true;
		try {
			const res = await userList();
			users = Array.isArray(res) ? res : [];
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
	<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
		<div class="flex flex-col gap-1">
			<h1 class="text-2xl font-bold tracking-tight text-foreground flex items-center gap-2.5">
				<UsersIcon class="size-6 text-primary" />
				Users & Access
			</h1>
			<p class="text-xs text-muted-foreground">
				Manage local user accounts for web authentication and permission controls in Lanforge.
			</p>
		</div>

		<div class="flex items-center gap-2 self-start sm:self-center">
			<a href="/system/keys">
				<Button
					variant="ghost"
					size="sm"
					class="rounded-xl cursor-pointer text-xs"
				>
					<KeyRoundIcon data-icon="inline-start" />
					API Keys
				</Button>
			</a>

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
		</div>
	</div>

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
