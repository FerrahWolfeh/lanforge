<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import { logout, changePassword } from "$lib/api/client";
	import { goto } from "$app/navigation";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { toast } from "svelte-sonner";
	import ServerIcon from "@lucide/svelte/icons/server";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import UsersIcon from "@lucide/svelte/icons/users";
	import LockIcon from "@lucide/svelte/icons/lock";
	import LogOutIcon from "@lucide/svelte/icons/log-out";
	import ChevronsUpDownIcon from "@lucide/svelte/icons/chevrons-up-down";

	interface Props {
		onNavigate?: () => void;
	}

	let { onNavigate }: Props = $props();

	const user = $derived(auth.user);
	const username = $derived(user?.username ?? "admin");
	const role = $derived(user?.role ?? "Admin");
	const initials = $derived((user?.username ?? "AD").slice(0, 2).toUpperCase());

	async function handleLogout() {
		try {
			await logout();
		} catch {
			// daemon may be unreachable
		}
		auth.clear();
		onNavigate?.();
		goto("/login");
	}

	let isPasswdOpen = $state(false);
	let currentPassword = $state("");
	let newPassword = $state("");
	let confirmPassword = $state("");
	let changingPassword = $state(false);

	async function handleChangePassword(e: SubmitEvent) {
		e.preventDefault();
		if (!currentPassword) {
			toast.error("Informe a senha atual");
			return;
		}
		if (newPassword.length < 4) {
			toast.error("A nova senha deve ter pelo menos 4 caracteres");
			return;
		}
		if (newPassword !== confirmPassword) {
			toast.error("As novas senhas não coincidem");
			return;
		}
		changingPassword = true;
		try {
			await changePassword(currentPassword, newPassword);
			toast.success("Senha alterada com sucesso!");
			currentPassword = "";
			newPassword = "";
			confirmPassword = "";
			isPasswdOpen = false;
		} catch (err: any) {
			toast.error(err?.message || "Falha ao alterar senha");
		} finally {
			changingPassword = false;
		}
	}
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger
		class="flex items-center h-10 w-full rounded-xl text-left text-sm transition-[background-color,color] duration-150 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring overflow-hidden cursor-pointer"
		title={sidebarState.isCollapsed ? `${username} (${role})` : undefined}
	>
		<div class="size-10 shrink-0 flex items-center justify-center">
			<div
				class="size-8 rounded-lg bg-primary/10 text-primary border border-primary/20 flex items-center justify-center font-bold text-xs"
			>
				{initials}
			</div>
		</div>

		<div
			class="grid flex-1 text-left text-sm leading-tight truncate overflow-hidden whitespace-nowrap transition-[opacity,max-width,transform] duration-300 ease-in-out {sidebarState.isCollapsed
				? 'opacity-0 max-w-0 pointer-events-none -translate-x-2'
				: 'opacity-100 max-w-[140px] translate-x-0'}"
		>
			<span class="truncate font-semibold tracking-tight text-foreground">{username}</span>
			<span class="truncate text-[10px] text-muted-foreground uppercase font-mono">{role}</span>
		</div>

		<div
			class="size-6 shrink-0 flex items-center justify-center transition-[opacity,max-width] duration-300 {sidebarState.isCollapsed
				? 'opacity-0 max-w-0 pointer-events-none'
				: 'opacity-100 max-w-6 ml-auto'}"
		>
			<ChevronsUpDownIcon class="size-4 text-muted-foreground" />
		</div>
	</DropdownMenu.Trigger>

	<DropdownMenu.Content class="w-56 rounded-xl shadow-lg border border-border/80" side="right" align="end" sideOffset={8}>
		<DropdownMenu.Label class="p-0 font-normal">
			<div class="flex items-center gap-2 px-2.5 py-2 text-left text-sm">
				<div
					class="size-8 rounded-lg bg-primary/10 text-primary border border-primary/20 flex items-center justify-center font-bold text-xs shrink-0"
				>
					{initials}
				</div>
				<div class="grid flex-1 text-left text-sm leading-tight">
					<span class="truncate font-semibold text-foreground">{username}</span>
					<div class="flex items-center gap-1.5 mt-0.5">
						<Badge variant="secondary" class="text-[10px] px-1.5 py-0 font-mono">
							{role}
						</Badge>
					</div>
				</div>
			</div>
		</DropdownMenu.Label>

		<DropdownMenu.Separator />

		<DropdownMenu.Group>
			<DropdownMenu.Item
				class="cursor-pointer text-xs"
				onclick={() => {
					onNavigate?.();
					goto("/system");
				}}
			>
				<ServerIcon class="size-4 mr-2 text-muted-foreground" />
				<span>System Status</span>
			</DropdownMenu.Item>
			<DropdownMenu.Item
				class="cursor-pointer text-xs"
				onclick={() => {
					onNavigate?.();
					goto("/system/services");
				}}
			>
				<LayersIcon class="size-4 mr-2 text-muted-foreground" />
				<span>System Services</span>
			</DropdownMenu.Item>
			<DropdownMenu.Item
				class="cursor-pointer text-xs"
				onclick={() => {
					onNavigate?.();
					goto("/system/database");
				}}
			>
				<DatabaseIcon class="size-4 mr-2 text-muted-foreground" />
				<span>Database & Persistence</span>
			</DropdownMenu.Item>
			<DropdownMenu.Item
				class="cursor-pointer text-xs"
				onclick={() => {
					onNavigate?.();
					goto("/system/users");
				}}
			>
				<UsersIcon class="size-4 mr-2 text-muted-foreground" />
				<span>User Accounts</span>
			</DropdownMenu.Item>
			<DropdownMenu.Item
				class="cursor-pointer text-xs"
				onclick={() => {
					onNavigate?.();
					goto("/system/keys");
				}}
			>
				<KeyRoundIcon class="size-4 mr-2 text-muted-foreground" />
				<span>Auth & API Keys</span>
			</DropdownMenu.Item>
		</DropdownMenu.Group>

		<DropdownMenu.Separator />

		<DropdownMenu.Item
			class="cursor-pointer text-xs"
			onclick={() => (isPasswdOpen = true)}
		>
			<LockIcon class="size-4 mr-2 text-muted-foreground" />
			<span>Change Password</span>
		</DropdownMenu.Item>

		<DropdownMenu.Item
			class="text-destructive focus:text-destructive focus:bg-destructive/10 cursor-pointer text-xs"
			onclick={handleLogout}
		>
			<LogOutIcon class="size-4 mr-2" />
			<span>Log Out</span>
		</DropdownMenu.Item>
	</DropdownMenu.Content>
</DropdownMenu.Root>

<!-- Change Password Dialog -->
<Dialog.Root bind:open={isPasswdOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<LockIcon class="size-4 text-primary" />
				<span>Change Account Password</span>
			</Dialog.Title>
			<Dialog.Description>
				Update the authentication password for user <strong class="text-foreground">{username}</strong>.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleChangePassword} class="flex flex-col gap-3.5 py-2">
			<div class="flex flex-col gap-1.5">
				<Label for="navuser-current-pwd" class="text-xs">Current Password</Label>
				<Input
					id="navuser-current-pwd"
					type="password"
					bind:value={currentPassword}
					placeholder="••••••••"
					class="text-xs h-9"
					required
				/>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="navuser-new-pwd" class="text-xs">New Password</Label>
				<Input
					id="navuser-new-pwd"
					type="password"
					bind:value={newPassword}
					placeholder="••••••••"
					class="text-xs h-9"
					required
				/>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="navuser-confirm-pwd" class="text-xs">Confirm New Password</Label>
				<Input
					id="navuser-confirm-pwd"
					type="password"
					bind:value={confirmPassword}
					placeholder="••••••••"
					class="text-xs h-9"
					required
				/>
			</div>

			<Dialog.Footer class="mt-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					class="text-xs"
					onclick={() => (isPasswdOpen = false)}
				>
					Cancel
				</Button>
				<Button
					type="submit"
					size="sm"
					class="text-xs"
					disabled={changingPassword}
				>
					{changingPassword ? "Updating..." : "Update Password"}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
