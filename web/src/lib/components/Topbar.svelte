<script lang="ts">
	import { page } from "$app/state";
	import { dev } from "$app/environment";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import * as Sheet from "$lib/components/ui/sheet";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import { formatUptime } from "$lib/utils";
	import AppSidebar from "./AppSidebar.svelte";
	import ModeToggle from "./ModeToggle.svelte";
	import MenuIcon from "@lucide/svelte/icons/menu";
	import PanelLeftIcon from "@lucide/svelte/icons/panel-left";
	import SearchIcon from "@lucide/svelte/icons/search";
	import BugIcon from "@lucide/svelte/icons/bug";
	import { commandState } from "$lib/stores/command.svelte";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";

	let { uptime = $bindable(0) }: { uptime?: number } = $props();
	let isMobileOpen = $state(false);

	const titleMap: Record<string, string> = {
		"/": "Dashboard",
		"/network/devices": "Network Devices",
		"/network/hosts": "Static Host Reservations",
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

		<!-- Capabilities Debug Mode Controls -->
		{#if dev}
			<!-- Vite Dev Mode Dedicated Toggle Button -->
			<Tooltip.Provider>
				<Tooltip.Root>
					<Tooltip.Trigger
						class={[
							"flex items-center gap-1.5 h-8 px-2.5 rounded-xl border text-xs font-mono font-medium transition-colors cursor-pointer select-none",
							capabilitiesState.debugMode
								? "bg-amber-500/15 border-amber-500/40 text-amber-500 hover:bg-amber-500/25 shadow-xs"
								: "bg-muted/40 border-border/70 text-muted-foreground hover:text-foreground hover:bg-muted/80",
						].join(" ")}
						onclick={() => capabilitiesState.toggleDebugMode()}
						aria-label="Toggle capabilities debug override (Vite Dev only)"
					>
						<BugIcon class="size-3.5 shrink-0 {capabilitiesState.debugMode ? 'text-amber-500' : 'text-muted-foreground'}" />
						<span class="hidden sm:inline">Caps:</span>
						<span class="font-semibold">{capabilitiesState.debugMode ? "All" : "Live"}</span>
					</Tooltip.Trigger>
					<Tooltip.Content side="bottom" sideOffset={6} class="text-xs font-normal max-w-xs">
						<p class="font-medium text-foreground mb-1">Vite Dev: Capabilities Override</p>
						{#if capabilitiesState.debugMode}
							Currently forcing <strong>all</strong> pages and modules visible, ignoring live daemon capabilities. Click to filter by connected daemon.
						{:else}
							Currently filtering pages according to the <strong>live connected daemon</strong>. Click to force all pages visible for local development.
						{/if}
					</Tooltip.Content>
				</Tooltip.Root>
			</Tooltip.Provider>
		{/if}

		<!-- Quick Search / Command Palette trigger -->
		<button
			type="button"
			class="hidden md:flex items-center gap-2 h-8 px-2.5 rounded-xl border border-border/70 bg-muted/40 hover:bg-muted/80 text-muted-foreground hover:text-foreground text-xs transition-colors cursor-pointer"
			onclick={() => commandState.open()}
			aria-label="Search or execute command (Ctrl+K)"
		>
			<SearchIcon class="size-3.5" />
			<span>Search...</span>
			<kbd class="pointer-events-none inline-flex h-4.5 select-none items-center gap-0.5 rounded border border-border/80 bg-background px-1.5 font-mono text-[10px] font-medium text-muted-foreground">
				<span>⌘</span>K
			</kbd>
		</button>

		<!-- Mobile Search Icon Button -->
		<button
			type="button"
			class="flex md:hidden items-center justify-center size-8 rounded-xl border border-border/70 text-muted-foreground hover:text-foreground hover:bg-muted/50 cursor-pointer"
			onclick={() => commandState.open()}
			aria-label="Search (Ctrl+K)"
		>
			<SearchIcon class="size-4" />
		</button>

		<!-- Theme Toggle -->
		<ModeToggle />
	</div>
</header>
