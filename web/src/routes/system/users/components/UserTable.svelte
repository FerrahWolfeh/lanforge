<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import UsersIcon from "@lucide/svelte/icons/users";
	import UserPlusIcon from "@lucide/svelte/icons/user-plus";
	import KeyIcon from "@lucide/svelte/icons/key";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import UserIcon from "@lucide/svelte/icons/user";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { userDelete } from "$lib/api/client";
	import type { UserInfo } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

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
		if (!ts) return "Never logged in";
		const ms = ts > 1e11 ? ts : ts * 1000;
		const diffSecs = Math.round((Date.now() - ms) / 1000);
		if (diffSecs < 60) return "Just now";
		if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
		if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
		return `${Math.floor(diffSecs / 86400)}d ago`;
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
			toast.success(`User '${userToDelete.username}' deleted successfully.`);
			isDeleteOpen = false;
			userToDelete = null;
			await onRefresh();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to delete user.";
			toast.error(msg);
		} finally {
			isDeleting = false;
		}
	}

	const safeUsers = $derived(Array.isArray(users) ? users : []);
	const filteredUsers = $derived(
		safeUsers.filter((u) => {
			const query = searchQuery.trim().toLowerCase();
			const matchesSearch = !query || u.username.toLowerCase().includes(query);
			const matchesRole = roleFilter === "all" || u.role === roleFilter;
			return matchesSearch && matchesRole;
		})
	);
</script>

<DataTableCard
	title="System Users"
	icon={UsersIcon}
	description="Accounts authorized to access the WebUI and protected management APIs."
	total={filteredUsers.length}
	itemName="users"
	searchPlaceholder="Search username..."
	bind:searchQuery
	showPagination={false}
	containerHeight="h-auto"
	minTableWidth="min-w-[650px]"
	columns={5}
	loading={isLoading}
	isEmpty={filteredUsers.length === 0}
	emptyMessage="No system users found. Create an account to grant WebUI or API access."
	emptyFilteredMessage="No users match the search and role criteria."
>
	{#snippet filters()}
		<select
			bind:value={roleFilter}
			class="h-9 text-xs rounded-md bg-background border border-input px-2.5 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring cursor-pointer"
			aria-label="Filter by role"
		>
			<option value="all">All Roles</option>
			<option value="admin">Administrator</option>
			<option value="operator">Operator</option>
			<option value="viewer">Viewer</option>
		</select>
	{/snippet}

	{#snippet actions()}
		<Button
			size="sm"
			class="h-8 text-xs gap-1.5 cursor-pointer"
			onclick={onOpenCreate}
		>
			<UserPlusIcon class="size-3.5" />
			<span>Create User</span>
		</Button>
	{/snippet}

	{#snippet emptyAction()}
		<Button
			size="sm"
			class="h-8 text-xs gap-1.5 cursor-pointer"
			onclick={onOpenCreate}
		>
			<UserPlusIcon class="size-3.5" />
			<span>Create User</span>
		</Button>
	{/snippet}

	{#snippet header()}
		<Table.Head>User</Table.Head>
		<Table.Head>Role / Privilege</Table.Head>
		<Table.Head>Created</Table.Head>
		<Table.Head>Last Login</Table.Head>
		<Table.Head class="text-right w-[160px]">Actions</Table.Head>
	{/snippet}

	{#each filteredUsers as user (user.username)}
		{@const isSelf = Boolean(currentUsername && user.username.toLowerCase() === currentUsername.toLowerCase())}
		<Table.Row class="hover:bg-muted/30 transition-colors font-mono text-xs">
			<!-- User -->
			<Table.Cell class="py-3 font-sans">
				<div class="flex items-center gap-2.5">
					<div class="size-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
						<UserIcon class="size-4" />
					</div>
					<div class="flex flex-col gap-0.5">
						<div class="flex items-center gap-1.5">
							<span class="text-xs font-bold text-foreground">{user.username}</span>
							{#if isSelf}
								<Badge variant="outline" class="text-[10px] px-1.5 py-0 border-primary/30 text-primary bg-primary/10">
									You
								</Badge>
							{/if}
						</div>
						<span class="text-[11px] font-mono text-muted-foreground">
							ID: #{user.id}
						</span>
					</div>
				</div>
			</Table.Cell>

			<!-- Role -->
			<Table.Cell class="py-3 font-sans">
				{#if user.role === "admin"}
					<Badge variant="default" class="text-[10px] px-2 py-0.5">
						Administrator
					</Badge>
				{:else if user.role === "operator"}
					<Badge variant="secondary" class="text-[10px] px-2 py-0.5">
						Operator
					</Badge>
				{:else}
					<Badge variant="outline" class="text-[10px] px-2 py-0.5 text-muted-foreground">
						Viewer
					</Badge>
				{/if}
			</Table.Cell>

			<!-- Created At -->
			<Table.Cell class="py-3 font-sans text-xs text-muted-foreground whitespace-nowrap">
				{formatDate(user.created_at)}
			</Table.Cell>

			<!-- Last Access -->
			<Table.Cell class="py-3 font-sans whitespace-nowrap">
				<span class="text-xs text-muted-foreground" title={formatDate(user.last_login)}>
					{formatRelative(user.last_login)}
				</span>
			</Table.Cell>

			<!-- Actions -->
			<Table.Cell class="py-3 text-right whitespace-nowrap font-sans">
				<div class="flex items-center justify-end gap-1.5">
					<Button
						variant="outline"
						size="sm"
						class="cursor-pointer text-xs h-8 px-2.5"
						title="Reset user password"
						onclick={() => onChangePassword(user)}
					>
						<KeyIcon class="size-3.5 mr-1" />
						Password
					</Button>

					<Button
						variant="outline"
						size="sm"
						class="cursor-pointer text-xs h-8 px-2.5 text-destructive hover:bg-destructive/10 border-destructive/30"
						title={isSelf ? "You cannot delete your own account" : "Delete user"}
						disabled={isSelf}
						onclick={() => confirmDelete(user)}
					>
						<Trash2Icon class="size-3.5 mr-1" />
						Delete
					</Button>
				</div>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>

<!-- AlertDialog for User Deletion -->
<AlertDialog.Root bind:open={isDeleteOpen}>
	<AlertDialog.Content class="rounded-xl">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold text-foreground">
				Delete User?
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Are you sure you want to permanently delete user <strong>{userToDelete?.username}</strong>? This action cannot be undone and the user will lose access immediately.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="cursor-pointer text-xs">
				Cancel
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="cursor-pointer text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={handleDeleteUser}
				disabled={isDeleting}
			>
				{#if isDeleting}
					<Loader2Icon class="size-3.5 mr-1 animate-spin" />
					Deleting...
				{:else}
					Yes, Delete User
				{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
