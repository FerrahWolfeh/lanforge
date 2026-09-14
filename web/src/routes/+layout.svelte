<script lang="ts">
	import "./layout.css";
	import favicon from "$lib/assets/favicon.svg";
	import { page } from "$app/state";
	import { fly } from "svelte/transition";
	import { cubicOut } from "svelte/easing";
	import { ModeWatcher } from "mode-watcher";
	import { Toaster } from "$lib/components/ui/sonner";
	import { auth } from "$lib/stores/auth.svelte";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import { status } from "$lib/api/client";
	import AppSidebar from "$lib/components/AppSidebar.svelte";
	import Topbar from "$lib/components/Topbar.svelte";
	import CommandPalette from "$lib/components/CommandPalette.svelte";
	import { commandState } from "$lib/stores/command.svelte";

	let { children } = $props();
	let uptime = $state(0);

	const isAuthPage = $derived(page.url.pathname === "/login" || page.url.pathname === "/setup");

	const tabTitleMap: Record<string, string> = {
		"/": "Dashboard",
		"/network/devices": "Devices",
		"/network/hosts": "Static Hosts",
		"/network/discovery": "Discovery & Monitor",
		"/network/ra": "IPv6 RA",
		"/network/pppoe": "PPPoE",
		"/dns/resolver": "DNS Resolver",
		"/dns/log": "Query Log",
		"/dns/rewrites": "DNS Rewrites",
		"/dns/cache": "DNS Cache",
		"/dns/adblock": "Adblock",
		"/dns/adblock/lists": "Adblock Lists",
		"/dns/adblock/rules": "Adblock Rules",
		"/dns/adblock/services": "Blocked Services",
		"/dns/adblock/settings": "Adblock Settings",
		"/dhcp": "DHCP Server",
		"/dhcp/leases": "DHCP Leases",
		"/dhcp/pools": "DHCP Pools",
		"/dhcp/server": "DHCP Server",
		"/tftp": "TFTP Server",
		"/system": "System Status",
		"/system/services": "Services",
		"/system/database": "Database",
		"/system/database/settings": "Storage Settings",
		"/system/database/maintenance": "Maintenance",
		"/system/database/backup": "Backups",
		"/system/users": "Users",
		"/system/keys": "Auth Keys",
		"/login": "Login",
		"/setup": "Setup",
	};

	const currentTabTitle = $derived(
		tabTitleMap[page.url.pathname]
			? `${tabTitleMap[page.url.pathname]} — Lanforge`
			: "Lanforge"
	);

	function handleKeydown(event: KeyboardEvent) {
		const target = event.target as HTMLElement;
		const isInputActive = target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable);

		// Ctrl+K / Cmd+K: Toggle Command Palette
		if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
			event.preventDefault();
			commandState.toggle();
			return;
		}

		// Ctrl+B / Cmd+B: Toggle Sidebar
		if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "b") {
			if (isInputActive) return;
			event.preventDefault();
			sidebarState.toggle();
			return;
		}

		// /: Focus search input on the current page if not already typing
		if (event.key === "/" && !isInputActive && !event.ctrlKey && !event.metaKey && !event.altKey && !commandState.isOpen) {
			const searchInput = document.querySelector<HTMLInputElement>(
				'input[type="search"], input[placeholder*="Buscar"], input[placeholder*="Search"], input[placeholder*="Filtrar"], input[placeholder*="Filter"]'
			);
			if (searchInput) {
				event.preventDefault();
				searchInput.focus();
				searchInput.select?.();
			}
		}
	}

	$effect(() => {
		if (isAuthPage) return;

		let active = true;
		async function pollStatus() {
			try {
				const s = await status();
				if (active) uptime = s.uptime_secs;
			} catch {
				// daemon unreachable — leave uptime as-is
			}
		}

		pollStatus();
		const interval = setInterval(pollStatus, 30_000);
		return () => {
			active = false;
			clearInterval(interval);
		};
	});
</script>

<svelte:window onkeydown={handleKeydown} />

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>{currentTabTitle}</title>
</svelte:head>

<ModeWatcher defaultMode="system" />

{#if isAuthPage}
	<main class="min-h-screen w-full bg-background text-foreground">
		{@render children()}
	</main>
{:else}
	<!-- Main Application Shell (Sidebar Inset Layout) -->
	<div id="app-shell" class="flex h-screen w-full overflow-hidden bg-sidebar text-sidebar-foreground">
		<!-- Desktop Sidebar (Permanently mounted and static) -->
		<div class="hidden lg:flex lg:shrink-0">
			<AppSidebar />
		</div>

		<!-- Main Inset Content Area (Floating Elevated Panel Card) -->
		<div
			class="flex flex-1 flex-col overflow-hidden min-h-0 lg:my-2.5 lg:mr-2.5 lg:rounded-2xl lg:border lg:border-sidebar-border/80 bg-background text-foreground lg:shadow-xs transition-all duration-300"
		>
			<Topbar {uptime} />
			<main class="flex-1 overflow-y-auto p-3 sm:p-6 flex flex-col min-h-0">
				{#key page.url.pathname}
					<div
						in:fly={{ y: 8, duration: 200, easing: cubicOut }}
						class="page-content-compositor w-full flex-1 flex flex-col min-h-0"
					>
						{@render children()}
					</div>
				{/key}
			</main>
		</div>
	</div>
{/if}

<Toaster richColors />
<CommandPalette />
