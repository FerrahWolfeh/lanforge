<script lang="ts">
	import { page } from "$app/state";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";
	import NavUser from "./NavUser.svelte";
	import type { Component } from "svelte";

	import LayoutDashboardIcon from "@lucide/svelte/icons/layout-dashboard";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import PlugZapIcon from "@lucide/svelte/icons/plug-zap";
	import SlidersHorizontalIcon from "@lucide/svelte/icons/sliders-horizontal";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ServerIcon from "@lucide/svelte/icons/server";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import UsersIcon from "@lucide/svelte/icons/users";

	interface Props {
		onNavigate?: () => void;
	}

	interface NavItem {
		title: string;
		href: string;
		icon: Component<Record<string, unknown>>;
		cap?: string | string[];
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
				{ title: "Firewall", href: "/firewall", icon: ShieldIcon, cap: "firewall" },
				{ title: "Traffic & SQM", href: "/network/traffic", icon: SlidersHorizontalIcon, cap: "traffic" },
				{ title: "PPPoE WAN", href: "/network/pppoe", icon: PlugZapIcon, cap: "pppoe" },
				{ title: "IPv6 RA", href: "/network/ra", icon: WifiIcon, cap: "ra" },
			],
		},
		{
			header: "DNS",
			items: [
				{ title: "DNS Resolver", href: "/dns/resolver", icon: GlobeIcon, cap: "dns" },
				{ title: "Query Log", href: "/dns/log", icon: ActivityIcon, cap: "dns" },
				{ title: "Adblock", href: "/dns/adblock", icon: ShieldIcon, cap: "adblock" },
			],
		},
		{
			header: "DHCP & BOOT",
			items: [
				{ title: "DHCP Server", href: "/dhcp/leases", icon: ServerIcon, cap: ["dhcp_v4", "dhcp_v6"] },
				{ title: "TFTP Server", href: "/tftp", icon: HardDriveDownloadIcon, cap: "tftp" },
			],
		},
		{
			header: "SYSTEM",
			items: [
				{ title: "System Status", href: "/system", icon: ServerIcon },
				{ title: "Database", href: "/system/database", icon: DatabaseIcon },
				{ title: "Users & Access", href: "/system/users", icon: UsersIcon },
			],
		},
	];

	const visibleNavGroups = $derived(
		navGroups
			.map((group) => ({
				...group,
				items: group.items.filter((item) => {
					if (!item.cap) return true;
					if (Array.isArray(item.cap)) {
						return item.cap.some((c) => capabilitiesState.isEnabled(c));
					}
					return capabilitiesState.isEnabled(item.cap);
				}),
			}))
			.filter((group) => group.items.length > 0)
	);

	function isActive(href: string): boolean {
		if (href === "/") return currentPath === "/";
		if (href === "/system") {
			return (
				currentPath === "/system" ||
				currentPath === "/system/" ||
				currentPath.startsWith("/system/services") ||
				currentPath.startsWith("/system/events")
			);
		}
		if (href === "/system/users") {
			return currentPath.startsWith("/system/users") || currentPath.startsWith("/system/keys");
		}
		if (href === "/network/devices") {
			return currentPath.startsWith("/network/devices") || currentPath.startsWith("/network/hosts");
		}
		if (href === "/dns/resolver") {
			return (
				currentPath === "/dns" ||
				currentPath.startsWith("/dns/resolver") ||
				currentPath.startsWith("/dns/cache") ||
				currentPath.startsWith("/dns/rewrites")
			);
		}
		if (href.startsWith("/dhcp")) return currentPath.startsWith("/dhcp");
		if (href.startsWith("/dns/adblock")) return currentPath.startsWith("/dns/adblock");
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
		{#each visibleNavGroups as group, groupIdx}
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
						{@const isDbgOnly = capabilitiesState.debugMode && item.cap && (
							Array.isArray(item.cap)
								? !capabilitiesState.isAnyActualEnabled(item.cap)
								: !capabilitiesState.isActualEnabled(item.cap)
						)}

						<a
							href={item.href}
							onclick={onNavigate}
							title={isCollapsed ? (isDbgOnly ? `${item.title} (Debug: Disabled on daemon)` : item.title) : undefined}
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
							{#if isDbgOnly && !isCollapsed}
								<span
									class="ml-auto mr-2.5 rounded bg-amber-500/15 px-1 py-0.5 text-[9px] font-mono font-medium text-amber-500 border border-amber-500/30 shrink-0"
									title="Disabled on daemon, visible due to dev capabilities override"
								>
									dbg
								</span>
							{/if}
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
