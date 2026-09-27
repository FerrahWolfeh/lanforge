<script lang="ts">
	import { goto } from "$app/navigation";
	import { dev } from "$app/environment";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { toggleMode } from "mode-watcher";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import { auth } from "$lib/stores/auth.svelte";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";
	import { logout } from "$lib/api/client";
	import type { Component } from "svelte";

	import SearchIcon from "@lucide/svelte/icons/search";
	import LayoutDashboardIcon from "@lucide/svelte/icons/layout-dashboard";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import PlugZapIcon from "@lucide/svelte/icons/plug-zap";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ServerIcon from "@lucide/svelte/icons/server";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import UsersIcon from "@lucide/svelte/icons/users";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import SunMoonIcon from "@lucide/svelte/icons/sun-moon";
	import PanelLeftIcon from "@lucide/svelte/icons/panel-left";
	import LogOutIcon from "@lucide/svelte/icons/log-out";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import SlidersHorizontalIcon from "@lucide/svelte/icons/sliders-horizontal";
	import BugIcon from "@lucide/svelte/icons/bug";
	import { commandState } from "$lib/stores/command.svelte";

	interface CommandItem {
		id: string;
		title: string;
		subtitle?: string;
		keywords?: string[];
		category: "Pages & Navigation" | "Quick Actions";
		icon: Component<Record<string, unknown>>;
		action: () => void;
		cap?: string | string[];
	}

	let search = $state("");
	let selectedIndex = $state(0);
	let inputEl = $state<HTMLInputElement | null>(null);

	const items: CommandItem[] = [
		// Quick Actions
		...(dev
			? [
					{
						id: "action-dev-cdbg",
						title: "Toggle Capabilities Debug Mode",
						subtitle: "Vite Dev: Switch between live daemon capabilities and all pages",
						keywords: ["caps", "capabilities", "debug", "cdbg", "dev", "override", "vite"],
						category: "Quick Actions" as const,
						icon: BugIcon,
						action: () => capabilitiesState.toggleDebugMode(),
					},
			  ]
			: []),
		{
			id: "action-theme",
			title: "Toggle Light / Dark Theme",
			subtitle: "Switch visual interface mode",
			keywords: ["theme", "dark", "light", "mode", "colors"],
			category: "Quick Actions",
			icon: SunMoonIcon,
			action: () => toggleMode()
		},
		{
			id: "action-sidebar",
			title: "Toggle Sidebar",
			subtitle: "Expand or collapse navigation menu",
			keywords: ["sidebar", "menu", "collapse", "expand"],
			category: "Quick Actions",
			icon: PanelLeftIcon,
			action: () => sidebarState.toggle()
		},
		{
			id: "action-logout",
			title: "Sign Out (Log Out)",
			subtitle: "Disconnect from session",
			keywords: ["sign out", "logout", "disconnect", "exit"],
			category: "Quick Actions",
			icon: LogOutIcon,
			action: async () => {
				try {
					await logout();
				} finally {
					auth.clear();
					goto("/login");
				}
			}
		},

		// Navigation Pages
		{
			id: "page-dashboard",
			title: "Dashboard Overview",
			subtitle: "/",
			keywords: ["dashboard", "home", "overview", "metrics", "summary"],
			category: "Pages & Navigation",
			icon: LayoutDashboardIcon,
			action: () => goto("/")
		},
		{
			id: "page-devices",
			title: "Network Devices",
			subtitle: "/network/devices",
			keywords: ["devices", "computers", "clients", "mac", "ip"],
			category: "Pages & Navigation",
			icon: MonitorIcon,
			action: () => goto("/network/devices")
		},
		{
			id: "page-hosts",
			title: "Static Host Reservations",
			subtitle: "/network/hosts",
			keywords: ["hosts", "static", "reservations", "mac", "dhcp", "ip"],
			category: "Pages & Navigation",
			icon: BookmarkIcon,
			action: () => goto("/network/hosts")
		},
		{
			id: "page-ra",
			title: "IPv6 Router Advertisements (RA)",
			subtitle: "/network/ra",
			keywords: ["ipv6", "router", "advertisements", "slaac", "prefixes"],
			category: "Pages & Navigation",
			icon: WifiIcon,
			action: () => goto("/network/ra"),
			cap: "ra"
		},
		{
			id: "page-pppoe",
			title: "PPPoE WAN Client",
			subtitle: "/network/pppoe",
			keywords: ["pppoe", "wan", "internet", "isp", "fiber", "broadband"],
			category: "Pages & Navigation",
			icon: PlugZapIcon,
			action: () => goto("/network/pppoe"),
			cap: "pppoe"
		},
		{
			id: "page-firewall",
			title: "Firewall & Security",
			subtitle: "/firewall",
			keywords: ["firewall", "nftables", "port forward", "dmz", "pinhole", "rules", "zones"],
			category: "Pages & Navigation",
			icon: ShieldIcon,
			action: () => goto("/firewall"),
			cap: "firewall"
		},
		{
			id: "page-traffic",
			title: "Traffic & SQM Shaping",
			subtitle: "/network/traffic",
			keywords: ["traffic", "sqm", "cake", "qos", "bandwidth", "tuning", "bufferbloat", "speed"],
			category: "Pages & Navigation",
			icon: SlidersHorizontalIcon,
			action: () => goto("/network/traffic"),
			cap: "traffic"
		},
		{
			id: "page-resolver",
			title: "DNS Resolver & Upstreams",
			subtitle: "/dns/resolver",
			keywords: ["dns", "resolver", "cloudflare", "google", "quad9", "recursive", "upstream"],
			category: "Pages & Navigation",
			icon: GlobeIcon,
			action: () => goto("/dns/resolver"),
			cap: "dns"
		},
		{
			id: "page-query-log",
			title: "DNS Query Log",
			subtitle: "/dns/log",
			keywords: ["queries", "query", "log", "history", "requests"],
			category: "Pages & Navigation",
			icon: ActivityIcon,
			action: () => goto("/dns/log"),
			cap: "dns"
		},
		{
			id: "page-rewrites",
			title: "Custom DNS Rewrites",
			subtitle: "/dns/rewrites",
			keywords: ["rewrites", "domains", "records", "local"],
			category: "Pages & Navigation",
			icon: BookmarkIcon,
			action: () => goto("/dns/rewrites"),
			cap: "dns"
		},
		{
			id: "page-dns-cache",
			title: "DNS Query Cache",
			subtitle: "/dns/cache",
			keywords: ["cache", "dns", "ttl", "memory", "flush", "entries"],
			category: "Pages & Navigation",
			icon: DatabaseIcon,
			action: () => goto("/dns/cache"),
			cap: "dns"
		},
		{
			id: "page-adblock",
			title: "Adblock Filter Lists",
			subtitle: "/dns/adblock",
			keywords: ["adblock", "ads", "trackers", "lists", "rules", "blocking"],
			category: "Pages & Navigation",
			icon: ShieldIcon,
			action: () => goto("/dns/adblock"),
			cap: "adblock"
		},
		{
			id: "page-dhcp-leases",
			title: "Active DHCP Leases",
			subtitle: "/dhcp/leases",
			keywords: ["dhcp", "leases", "ips", "addresses", "clients"],
			category: "Pages & Navigation",
			icon: ServerIcon,
			action: () => goto("/dhcp/leases"),
			cap: ["dhcp_v4", "dhcp_v6"]
		},
		{
			id: "page-dhcp-pools",
			title: "DHCP Pools & Scopes",
			subtitle: "/dhcp/pools",
			keywords: ["pools", "ranges", "subnets", "netmask", "gateway"],
			category: "Pages & Navigation",
			icon: ServerIcon,
			action: () => goto("/dhcp/pools"),
			cap: ["dhcp_v4", "dhcp_v6"]
		},
		{
			id: "page-dhcp-server",
			title: "DHCP Server Options",
			subtitle: "/dhcp/server",
			keywords: ["dhcp", "configuration", "parameters", "options"],
			category: "Pages & Navigation",
			icon: ServerIcon,
			action: () => goto("/dhcp/server"),
			cap: ["dhcp_v4", "dhcp_v6"]
		},
		{
			id: "page-tftp",
			title: "TFTP Server & PXE Netboot",
			subtitle: "/tftp",
			keywords: ["tftp", "pxe", "netboot", "boot", "uefi", "bios", "ipxe"],
			category: "Pages & Navigation",
			icon: HardDriveDownloadIcon,
			action: () => goto("/tftp"),
			cap: "tftp"
		},
		{
			id: "page-system",
			title: "System Status & Telemetry",
			subtitle: "/system",
			keywords: ["status", "cpu", "memory", "uptime", "system", "hardware"],
			category: "Pages & Navigation",
			icon: ServerIcon,
			action: () => goto("/system")
		},
		{
			id: "page-services",
			title: "Lanforge Daemon Services",
			subtitle: "/system/services",
			keywords: ["services", "daemon", "lifecycle", "restart", "stop"],
			category: "Pages & Navigation",
			icon: LayersIcon,
			action: () => goto("/system/services")
		},
		{
			id: "page-events",
			title: "System Events & Audit Log",
			subtitle: "/system/events",
			keywords: ["events", "logs", "audit", "stream", "sse", "activity", "feed", "bus"],
			category: "Pages & Navigation",
			icon: ActivityIcon,
			action: () => goto("/system/events")
		},
		{
			id: "page-database",
			title: "Database & Backups",
			subtitle: "/system/database",
			keywords: ["database", "redb", "backup", "restore", "prune", "tables"],
			category: "Pages & Navigation",
			icon: DatabaseIcon,
			action: () => goto("/system/database")
		},
		{
			id: "page-users",
			title: "Local Users & Access",
			subtitle: "/system/users",
			keywords: ["users", "accounts", "login", "passwords", "permissions", "admin"],
			category: "Pages & Navigation",
			icon: UsersIcon,
			action: () => goto("/system/users")
		},
		{
			id: "page-keys",
			title: "API Keys & Authentication",
			subtitle: "/system/keys",
			keywords: ["api", "keys", "tokens", "bearer", "scripts", "secrets"],
			category: "Pages & Navigation",
			icon: KeyRoundIcon,
			action: () => goto("/system/keys")
		}
	];

	const availableItems = $derived(
		items.filter((item) => {
			if (!item.cap) return true;
			if (Array.isArray(item.cap)) {
				return item.cap.some((c) => capabilitiesState.isEnabled(c));
			}
			return capabilitiesState.isEnabled(item.cap);
		})
	);

	const filteredItems = $derived.by(() => {
		const q = search.trim().toLowerCase();
		if (!q) return availableItems;
		return availableItems.filter((item) => {
			if (item.title.toLowerCase().includes(q)) return true;
			if (item.subtitle?.toLowerCase().includes(q)) return true;
			if (item.keywords?.some((k) => k.toLowerCase().includes(q))) return true;
			return false;
		});
	});

	$effect(() => {
		if (commandState.isOpen) {
			search = "";
			selectedIndex = 0;
			setTimeout(() => inputEl?.focus(), 50);
		}
	});

	$effect(() => {
		// Reset selected index when search query changes
		if (search) {
			selectedIndex = 0;
		}
	});

	function executeItem(item: CommandItem) {
		commandState.close();
		item.action();
	}

	function handleKeydown(e: KeyboardEvent) {
		if (!commandState.isOpen) return;

		if (e.key === "ArrowDown") {
			e.preventDefault();
			if (filteredItems.length > 0) {
				selectedIndex = (selectedIndex + 1) % filteredItems.length;
			}
		} else if (e.key === "ArrowUp") {
			e.preventDefault();
			if (filteredItems.length > 0) {
				selectedIndex = (selectedIndex - 1 + filteredItems.length) % filteredItems.length;
			}
		} else if (e.key === "Enter") {
			e.preventDefault();
			const selected = filteredItems[selectedIndex];
			if (selected) {
				executeItem(selected);
			}
		}
	}
</script>

<svelte:window onkeydown={handleKeydown} />

<Dialog.Root bind:open={commandState.isOpen}>
	<Dialog.Content
		showCloseButton={false}
		class="p-0 overflow-hidden sm:max-w-xl rounded-2xl shadow-2xl border border-border/80 bg-card gap-0 top-[20%] sm:top-[25%]"
	>
		<Dialog.Header class="sr-only">
			<Dialog.Title>Command Palette</Dialog.Title>
			<Dialog.Description>Quickly navigate pages and execute system actions</Dialog.Description>
		</Dialog.Header>

		<!-- Input Box -->
		<div class="flex items-center gap-3 px-4 py-3 border-b border-border/60 bg-background/50">
			<SearchIcon class="size-4 text-muted-foreground shrink-0" />
			<input
				bind:this={inputEl}
				bind:value={search}
				placeholder="Type a command or search for a page..."
				class="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground outline-none"
			/>
			<Badge variant="outline" class="font-mono text-[10px] text-muted-foreground px-1.5 py-0">
				ESC
			</Badge>
		</div>

		<!-- Results List -->
		<div class="max-h-80 overflow-y-auto p-2 space-y-1">
			{#if filteredItems.length === 0}
				<div class="py-10 text-center text-xs text-muted-foreground">
					No results found for "<span class="font-semibold text-foreground">{search}</span>".
				</div>
			{:else}
				{#each filteredItems as item, idx (item.id)}
					{@const isSelected = idx === selectedIndex}
					{@const Icon = item.icon}
					{@const isDbgOnly = capabilitiesState.debugMode && item.cap && (
						Array.isArray(item.cap)
							? !capabilitiesState.isAnyActualEnabled(item.cap)
							: !capabilitiesState.isActualEnabled(item.cap)
					)}
					<button
						type="button"
						class="w-full flex items-center justify-between gap-3 px-3 py-2.5 rounded-xl text-left transition-colors cursor-pointer {isSelected
							? 'bg-primary text-primary-foreground'
							: 'hover:bg-muted/60 text-foreground'}"
						onclick={() => executeItem(item)}
						onmouseenter={() => (selectedIndex = idx)}
					>
						<div class="flex items-center gap-2.5 min-w-0">
							<div
								class="size-7 rounded-lg flex items-center justify-center shrink-0 {isSelected
									? 'bg-primary-foreground/20 text-primary-foreground'
									: 'bg-muted text-muted-foreground'}"
							>
								<Icon class="size-3.5" />
							</div>
							<div class="flex flex-col min-w-0">
								<span class="text-xs font-semibold truncate">
									{item.title}
								</span>
								{#if item.subtitle}
									<span
										class="text-[11px] truncate font-mono {isSelected
											? 'text-primary-foreground/80'
											: 'text-muted-foreground'}"
									>
										{item.subtitle}
									</span>
								{/if}
							</div>
						</div>

						<div class="flex items-center gap-1.5 shrink-0">
							{#if isDbgOnly}
								<span
									class="text-[9px] font-mono font-medium px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-500 border border-amber-500/30"
									title="Disabled on daemon (visible in dev mode)"
								>
									DBG
								</span>
							{/if}
							<span
								class="text-[10px] uppercase tracking-wider font-mono px-1.5 py-0.5 rounded {isSelected
									? 'bg-primary-foreground/20 text-primary-foreground'
									: 'bg-muted/60 text-muted-foreground'}"
							>
								{item.category === 'Quick Actions' ? 'Action' : 'Page'}
							</span>
							{#if isSelected}
								<ArrowRightIcon class="size-3.5 opacity-80" />
							{/if}
						</div>
					</button>
				{/each}
			{/if}
		</div>

		<!-- Footer Help -->
		<div class="flex items-center justify-between px-4 py-2 border-t border-border/50 bg-muted/20 text-[11px] text-muted-foreground">
			<div class="flex items-center gap-3">
				<span class="flex items-center gap-1">
					<kbd class="rounded border border-border/80 bg-background px-1 py-0.5 font-mono text-[10px]">↑</kbd>
					<kbd class="rounded border border-border/80 bg-background px-1 py-0.5 font-mono text-[10px]">↓</kbd>
					navigate
				</span>
				<span class="flex items-center gap-1">
					<kbd class="rounded border border-border/80 bg-background px-1 py-0.5 font-mono text-[10px]">↵</kbd>
					execute
				</span>
			</div>
			<span>
				Lanforge Quick Navigator
			</span>
		</div>
	</Dialog.Content>
</Dialog.Root>
