<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import { logout } from "$lib/api/client";
	import { goto } from "$app/navigation";
	import { Badge } from "$lib/components/ui/badge";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import ServerIcon from "@lucide/svelte/icons/server";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import DatabaseIcon from "@lucide/svelte/icons/database";
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
		</DropdownMenu.Group>

		<DropdownMenu.Separator />

		<DropdownMenu.Item
			class="text-destructive focus:text-destructive focus:bg-destructive/10 cursor-pointer text-xs"
			onclick={handleLogout}
		>
			<LogOutIcon class="size-4 mr-2" />
			<span>Log Out</span>
		</DropdownMenu.Item>
	</DropdownMenu.Content>
</DropdownMenu.Root>
