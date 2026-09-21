<script lang="ts">
	import { page } from "$app/state";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import * as Sheet from "$lib/components/ui/sheet";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import { formatUptime } from "$lib/utils";
	import AppSidebar from "./AppSidebar.svelte";
	import ModeToggle from "./ModeToggle.svelte";
	import MenuIcon from "@lucide/svelte/icons/menu";
	import PanelLeftIcon from "@lucide/svelte/icons/panel-left";
	import SearchIcon from "@lucide/svelte/icons/search";
	import { commandState } from "$lib/stores/command.svelte";

	let { uptime = $bindable(0) }: { uptime?: number } = $props();
	let isMobileOpen = $state(false);

	const titleMap: Record<string, string> = {
		"/": "Dashboard",
		"/network/devices": "Network Devices",
		"/network/hosts": "Static Host Reservations",
		"/network/discovery": "Network Discovery & Monitor",
		"/network/traffic": "Traffic & SQM",
		"/network/traffic/sqm": "Bufferbloat (CAKE)",
		"/network/traffic/tuning": "Hardware NIC Tuning",
		"/firewall": "Firewall & Security",
		"/network/ra": "IPv6 Router Advertisements",
		"/network/pppoe": "PPPoE WAN Client",
		"/dns/resolver": "DNS Resolver",
		"/dns/log": "DNS Query Log",
		"/dns/rewrites": "Custom DNS Rewrites",
		"/dns/cache": "DNS Cache Entries",
		"/dns/adblock": "Adblock & Domain Filtering",
		"/dns/adblock/lists": "Adblock Lists",
		"/dns/adblock/rules": "Adblock Custom Rules",
		"/dns/adblock/services": "Blocked Services",
		"/dns/adblock/settings": "Adblock Settings",
		"/dhcp": "DHCP Server",
		"/dhcp/leases": "DHCP Active Leases",
		"/dhcp/pools": "DHCP Scopes & Pools",
		"/dhcp/server": "DHCP Server Options",
		"/tftp": "TFTP Server",
		"/system": "System Status",
		"/system/services": "System Services",
		"/system/database": "Database & Persistence",
		"/system/database/settings": "Database Storage Settings",
		"/system/database/maintenance": "Database Maintenance",
		"/system/database/backup": "Database Backup & Restore",
		"/system/users": "User Accounts",
		"/system/keys": "API & Auth Keys",
	};

	const currentTitle = $derived(
		titleMap[page.url.pathname] ??
		(page.url.pathname.startsWith("/dhcp")
			? "DHCP Server"
			: page.url.pathname.startsWith("/dns")
			? "DNS & Security"
			: page.url.pathname.startsWith("/network")
			? "Network"
			: page.url.pathname.startsWith("/system")
			? "System"
			: "Lanforge")
	);
</script>

<header
	class="gpu-accelerated sticky top-0 z-30 flex h-16 w-full shrink-0 items-center justify-between border-b border-border/70 bg-background/95 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/60 lg:px-6 lg:rounded-t-2xl"
>
	<div class="flex items-center gap-3 min-w-0">
		<!-- Desktop Sidebar Toggle Button -->
		<div class="hidden lg:flex">
			<Tooltip.Provider>
				<Tooltip.Root>
					<Tooltip.Trigger
						class="inline-flex items-center justify-center rounded-lg p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring transition-colors"
						onclick={() => sidebarState.toggle()}
						aria-label="Toggle sidebar"
					>
						<PanelLeftIcon class="size-5" />
					</Tooltip.Trigger>
					<Tooltip.Content side="bottom" sideOffset={6} class="text-xs font-medium">
						{sidebarState.isCollapsed ? "Expand sidebar (Ctrl+B)" : "Collapse sidebar (Ctrl+B)"}
					</Tooltip.Content>
				</Tooltip.Root>
			</Tooltip.Provider>
		</div>

		<!-- Mobile Menu Sheet -->
		<div class="lg:hidden">
			<Sheet.Root bind:open={isMobileOpen}>
				<Sheet.Trigger
					class="inline-flex items-center justify-center rounded-lg p-2 text-muted-foreground hover:bg-accent hover:text-accent-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
					aria-label="Open navigation menu"
				>
					<MenuIcon class="size-5" />
				</Sheet.Trigger>
				<Sheet.Content side="left" class="p-0 w-64 bg-sidebar border-r border-sidebar-border text-sidebar-foreground">
					<Sheet.Header class="sr-only">
						<Sheet.Title>Navigation Menu</Sheet.Title>
					</Sheet.Header>
					<AppSidebar onNavigate={() => (isMobileOpen = false)} />
				</Sheet.Content>
			</Sheet.Root>
		</div>

		<!-- Visual Separator for Desktop -->
		<div class="hidden lg:block h-4 w-px bg-border/70"></div>

		<!-- Current Page Title -->
		<h1 class="text-base font-semibold tracking-tight text-foreground lg:text-lg font-sans truncate">
			{currentTitle}
		</h1>
	</div>

	<!-- Right Controls: Status indicator, Uptime, ModeToggle -->
	<div class="flex items-center gap-2.5 shrink-0">
		<!-- Daemon Status Tooltip -->
		<Tooltip.Provider>
			<Tooltip.Root>
				<Tooltip.Trigger
					class="flex items-center gap-2 px-2.5 py-1 rounded-lg hover:bg-accent/60 transition-colors border border-border/40"
				>
					<span
						class={[
							"size-2 rounded-full transition-all",
							uptime > 0
								? "bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)] animate-pulse"
								: "bg-zinc-500",
						].join(" ")}
					></span>
					<span class="text-xs font-medium text-muted-foreground hidden sm:inline">
						{uptime > 0 ? "Live" : "Offline"}
					</span>
				</Tooltip.Trigger>
				<Tooltip.Content side="bottom" sideOffset={6} class="text-xs font-medium">
					{uptime > 0 ? "Daemon active & connected" : "Daemon offline or unreachable"}
				</Tooltip.Content>
			</Tooltip.Root>
		</Tooltip.Provider>

		<!-- Uptime Badge -->
		{#if uptime > 0}
			<span
				class="text-muted-foreground hidden md:inline text-xs font-mono bg-muted/60 px-2 py-0.5 rounded-md border border-border/40"
			>
				up {formatUptime(uptime)}
			</span>
		{/if}

		<!-- Quick Search / Command Palette trigger -->
		<button
			type="button"
			class="hidden md:flex items-center gap-2 h-8 px-2.5 rounded-xl border border-border/70 bg-muted/40 hover:bg-muted/80 text-muted-foreground hover:text-foreground text-xs transition-colors cursor-pointer"
			onclick={() => commandState.open()}
			aria-label="Buscar ou executar comando (Ctrl+K)"
		>
			<SearchIcon class="size-3.5" />
			<span>Buscar...</span>
			<kbd class="pointer-events-none inline-flex h-4.5 select-none items-center gap-0.5 rounded border border-border/80 bg-background px-1.5 font-mono text-[10px] font-medium text-muted-foreground">
				<span>⌘</span>K
			</kbd>
		</button>

		<!-- Mobile Search Icon Button -->
		<button
			type="button"
			class="flex md:hidden items-center justify-center size-8 rounded-xl border border-border/70 text-muted-foreground hover:text-foreground hover:bg-muted/50 cursor-pointer"
			onclick={() => commandState.open()}
			aria-label="Buscar (Ctrl+K)"
		>
			<SearchIcon class="size-4" />
		</button>

		<!-- Theme Toggle -->
		<ModeToggle />
	</div>
</header>
