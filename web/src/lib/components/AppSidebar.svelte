<script lang="ts">
	import { page } from "$app/state";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import NavUser from "./NavUser.svelte";
	import type { Component } from "svelte";

	import LayoutDashboardIcon from "@lucide/svelte/icons/layout-dashboard";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import PlugZapIcon from "@lucide/svelte/icons/plug-zap";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ServerIcon from "@lucide/svelte/icons/server";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import UsersIcon from "@lucide/svelte/icons/users";

	interface Props {
		onNavigate?: () => void;
	}

	interface NavItem {
		title: string;
		href: string;
		icon: Component<Record<string, unknown>>;
	}

	interface NavGroup {
		header: string;
		items: NavItem[];
	}

	let { onNavigate }: Props = $props();

	const currentPath = $derived(page.url.pathname as string);
	const isCollapsed = $derived(onNavigate ? false : sidebarState.isCollapsed);

	const navGroups: NavGroup[] = [
		{
			header: "OVERVIEW",
			items: [
				{ title: "Dashboard", href: "/", icon: LayoutDashboardIcon },
			],
		},
		{
			header: "NETWORK",
			items: [
				{ title: "Devices", href: "/network/devices", icon: MonitorIcon },
				{ title: "Static Hosts", href: "/network/hosts", icon: BookmarkIcon },
				{ title: "Discovery & Monitor", href: "/network/discovery", icon: RadioIcon },
				{ title: "IPv6 RA", href: "/network/ra", icon: WifiIcon },
				{ title: "PPPoE WAN", href: "/network/pppoe", icon: PlugZapIcon },
			],
		},
		{
			header: "DNS & SECURITY",
			items: [
				{ title: "DNS Resolver", href: "/dns/resolver", icon: GlobeIcon },
				{ title: "Query Log", href: "/dns/log", icon: ActivityIcon },
				{ title: "Custom Rewrites", href: "/dns/rewrites", icon: BookmarkIcon },
				{ title: "DNS Cache", href: "/dns/cache", icon: DatabaseIcon },
				{ title: "Adblock", href: "/dns/adblock", icon: ShieldIcon },
				{ title: "Firewall", href: "/firewall", icon: ShieldIcon },
			],
		},
		{
			header: "DHCP & BOOT",
			items: [
				{ title: "DHCP Server", href: "/dhcp/leases", icon: ServerIcon },
				{ title: "TFTP Server", href: "/tftp", icon: HardDriveDownloadIcon },
			],
		},
		{
			header: "SYSTEM",
			items: [
				{ title: "System Status", href: "/system", icon: ServerIcon },
				{ title: "Services", href: "/system/services", icon: LayersIcon },
				{ title: "Database", href: "/system/database", icon: DatabaseIcon },
				{ title: "Users", href: "/system/users", icon: UsersIcon },
				{ title: "Auth Keys", href: "/system/keys", icon: KeyRoundIcon },
			],
		},
	];

	function isActive(href: string): boolean {
		if (href === "/") return currentPath === "/";
		if (href === "/system") return currentPath === "/system" || currentPath === "/system/";
		if (href.startsWith("/dhcp")) return currentPath.startsWith("/dhcp");
		if (href.startsWith("/dns/adblock")) return currentPath.startsWith("/dns/adblock");
		if (href === "/dns/resolver") return currentPath === "/dns" || currentPath.startsWith("/dns/resolver");
		return currentPath === href || currentPath.startsWith(href + "/");
	}
</script>

<aside
	class="sidebar-compositor flex h-full flex-col bg-sidebar text-sidebar-foreground transition-[width] duration-300 ease-in-out overflow-hidden select-none {isCollapsed ? 'w-16' : 'w-64'}"
>
	<!-- Brand Header -->
	<div class="flex h-16 shrink-0 items-center border-b border-sidebar-border/80 px-3 overflow-hidden">
		<a
			href="/"
			class="flex items-center transition-opacity hover:opacity-90 overflow-hidden w-full"
			onclick={onNavigate}
			aria-label="Lanforge Home"
		>
			<div class="size-10 shrink-0 flex items-center justify-center">
				<div class="size-8 rounded-xl bg-primary flex items-center justify-center text-primary-foreground shadow-xs">
					<WifiIcon class="size-4.5" />
				</div>
			</div>
			<div
				class="flex flex-col leading-tight overflow-hidden whitespace-nowrap transition-[opacity,max-width,transform] duration-300 ease-in-out {isCollapsed
					? 'opacity-0 max-w-0 pointer-events-none -translate-x-2'
					: 'opacity-100 max-w-[170px] translate-x-0'}"
			>
				<span class="text-sm font-bold tracking-tight text-foreground flex items-center font-sans">
					Lanforge
				</span>
				<span class="text-[10px] text-muted-foreground font-normal">
					Network Orchestrator
				</span>
			</div>
		</a>
	</div>

	<!-- Navigation Groups -->
	<div class="flex-1 overflow-y-auto px-3 py-4 space-y-4">
		{#each navGroups as group, groupIdx}
			<div>
				<!-- Group Header with smooth collapse animation -->
				<div
					class="overflow-hidden transition-[opacity,max-height,margin] duration-300 ease-in-out {isCollapsed
						? 'opacity-0 max-h-0 mb-0 pointer-events-none'
						: 'opacity-100 max-h-8 mb-1.5 px-2'}"
				>
					<div class="text-[11px] font-semibold tracking-wider text-muted-foreground uppercase whitespace-nowrap font-mono">
						{group.header}
					</div>
				</div>

				{#if groupIdx > 0}
					<div
						class="transition-[opacity,border-color,margin] duration-300 ease-in-out {isCollapsed
							? 'my-2 border-t border-sidebar-border/60 mx-1 opacity-100'
							: 'opacity-0 h-0 border-0 m-0'}"
					></div>
				{/if}

				<nav class="space-y-1">
					{#each group.items as item}
						{@const active = isActive(item.href)}
						{@const Icon = item.icon}

						<a
							href={item.href}
							onclick={onNavigate}
							title={isCollapsed ? item.title : undefined}
							class="flex items-center h-10 w-full rounded-xl text-xs font-medium overflow-hidden transition-[background-color,color,box-shadow] duration-150 ease-out transform-gpu will-change-[background-color,color] {active
								? 'bg-primary text-primary-foreground font-semibold shadow-xs'
								: 'text-sidebar-foreground/80 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'}"
							aria-label={item.title}
						>
							<div class="size-10 shrink-0 flex items-center justify-center">
								<Icon
									class="size-4 shrink-0 transition-colors duration-150 ease-out {active
										? 'text-primary-foreground'
										: 'text-muted-foreground'}"
								/>
							</div>
							<span
								class="truncate whitespace-nowrap transition-[opacity,max-width,transform] duration-300 ease-in-out {isCollapsed
									? 'opacity-0 max-w-0 pointer-events-none -translate-x-2'
									: 'opacity-100 max-w-[170px] translate-x-0'}"
							>
								{item.title}
							</span>
						</a>
					{/each}
				</nav>
			</div>
		{/each}
	</div>

	<!-- Footer: NavUser with User/Daemon status and Logout -->
	<div class="border-t border-sidebar-border/80 px-3 py-2 shrink-0 overflow-hidden">
		<NavUser {onNavigate} />
	</div>
</aside>
