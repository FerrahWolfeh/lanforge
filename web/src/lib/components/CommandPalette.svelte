<script lang="ts">
	import { goto } from "$app/navigation";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { toggleMode } from "mode-watcher";
	import { sidebarState } from "$lib/stores/sidebar.svelte";
	import { auth } from "$lib/stores/auth.svelte";
	import { logout } from "$lib/api/client";
	import type { Component } from "svelte";

	import SearchIcon from "@lucide/svelte/icons/search";
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
	import UsersIcon from "@lucide/svelte/icons/users";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import SunMoonIcon from "@lucide/svelte/icons/sun-moon";
	import PanelLeftIcon from "@lucide/svelte/icons/panel-left";
	import LogOutIcon from "@lucide/svelte/icons/log-out";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import { commandState } from "$lib/stores/command.svelte";

	interface CommandItem {
		id: string;
		title: string;
		subtitle?: string;
		keywords?: string[];
		category: "Páginas & Navegação" | "Ações Rápidas";
		icon: Component<Record<string, unknown>>;
		action: () => void;
	}

	let search = $state("");
	let selectedIndex = $state(0);
	let inputEl = $state<HTMLInputElement | null>(null);

	const items: CommandItem[] = [
		// Quick Actions
		{
			id: "action-theme",
			title: "Alternar Tema Claro / Escuro",
			subtitle: "Modo visual da interface",
			keywords: ["tema", "escuro", "claro", "dark", "light", "mode", "cores"],
			category: "Ações Rápidas",
			icon: SunMoonIcon,
			action: () => toggleMode()
		},
		{
			id: "action-sidebar",
			title: "Alternar Barra Lateral",
			subtitle: "Expandir ou recolher menu",
			keywords: ["sidebar", "menu", "lateral", "recolher", "expandir"],
			category: "Ações Rápidas",
			icon: PanelLeftIcon,
			action: () => sidebarState.toggle()
		},
		{
			id: "action-logout",
			title: "Encerrar Sessão (Log Out)",
			subtitle: "Desconectar do painel",
			keywords: ["sair", "logout", "desconectar", "fechar"],
			category: "Ações Rápidas",
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
			title: "Dashboard Geral",
			subtitle: "/",
			keywords: ["inicio", "home", "painel", "resumo", "metricas"],
			category: "Páginas & Navegação",
			icon: LayoutDashboardIcon,
			action: () => goto("/")
		},
		{
			id: "page-devices",
			title: "Dispositivos de Rede",
			subtitle: "/network/devices",
			keywords: ["aparelhos", "devices", "computadores", "mac", "ip", "clientes"],
			category: "Páginas & Navegação",
			icon: MonitorIcon,
			action: () => goto("/network/devices")
		},
		{
			id: "page-hosts",
			title: "Reservas Estáticas de Host",
			subtitle: "/network/hosts",
			keywords: ["hosts", "estatico", "fixo", "reservas", "mac", "dhcp"],
			category: "Páginas & Navegação",
			icon: BookmarkIcon,
			action: () => goto("/network/hosts")
		},
		{
			id: "page-discovery",
			title: "Descoberta de Rede & Monitor",
			subtitle: "/network/discovery",
			keywords: ["scan", "discovery", "monitor", "vizinhos", "arp", "sondagem"],
			category: "Páginas & Navegação",
			icon: RadioIcon,
			action: () => goto("/network/discovery")
		},
		{
			id: "page-ra",
			title: "Anúncios de Roteador IPv6 (RA)",
			subtitle: "/network/ra",
			keywords: ["ipv6", "router", "advertisements", "slaac", "prefixos"],
			category: "Páginas & Navegação",
			icon: WifiIcon,
			action: () => goto("/network/ra")
		},
		{
			id: "page-pppoe",
			title: "Cliente WAN PPPoE",
			subtitle: "/network/pppoe",
			keywords: ["pppoe", "wan", "internet", "provedor", "fibra", "banda larga"],
			category: "Páginas & Navegação",
			icon: PlugZapIcon,
			action: () => goto("/network/pppoe")
		},
		{
			id: "page-resolver",
			title: "Resolvedor DNS & Upstreams",
			subtitle: "/dns/resolver",
			keywords: ["dns", "resolver", "cloudflare", "google", "quad9", "recursivo"],
			category: "Páginas & Navegação",
			icon: GlobeIcon,
			action: () => goto("/dns/resolver")
		},
		{
			id: "page-query-log",
			title: "Log de Consultas DNS",
			subtitle: "/dns/log",
			keywords: ["consultas", "query", "log", "historico", "requisicoes"],
			category: "Páginas & Navegação",
			icon: ActivityIcon,
			action: () => goto("/dns/log")
		},
		{
			id: "page-rewrites",
			title: "Reescritas Customizadas DNS",
			subtitle: "/dns/rewrites",
			keywords: ["rewrites", "dominios", "redirecionamentos", "locais"],
			category: "Páginas & Navegação",
			icon: BookmarkIcon,
			action: () => goto("/dns/rewrites")
		},
		{
			id: "page-dns-cache",
			title: "Cache de Consultas DNS",
			subtitle: "/dns/cache",
			keywords: ["cache", "dns", "ttl", "memoria", "limpeza", "entradas"],
			category: "Páginas & Navegação",
			icon: DatabaseIcon,
			action: () => goto("/dns/cache")
		},
		{
			id: "page-adblock",
			title: "Bloqueador de Anúncios (Adblock)",
			subtitle: "/dns/adblock",
			keywords: ["adblock", "anuncios", "rastreadores", "listas", "regras", "bloqueio"],
			category: "Páginas & Navegação",
			icon: ShieldIcon,
			action: () => goto("/dns/adblock")
		},
		{
			id: "page-dhcp-leases",
			title: "Leases Ativos DHCP",
			subtitle: "/dhcp/leases",
			keywords: ["dhcp", "leases", "concessoes", "ips", "enderecos"],
			category: "Páginas & Navegação",
			icon: ServerIcon,
			action: () => goto("/dhcp/leases")
		},
		{
			id: "page-dhcp-pools",
			title: "Pools & Escopos DHCP",
			subtitle: "/dhcp/pools",
			keywords: ["pools", "faixas", "subredes", "mascara", "gateway"],
			category: "Páginas & Navegação",
			icon: ServerIcon,
			action: () => goto("/dhcp/pools")
		},
		{
			id: "page-dhcp-server",
			title: "Opções Gerais do Servidor DHCP",
			subtitle: "/dhcp/server",
			keywords: ["dhcp", "configuracao", "parametros", "options"],
			category: "Páginas & Navegação",
			icon: ServerIcon,
			action: () => goto("/dhcp/server")
		},
		{
			id: "page-tftp",
			title: "Servidor TFTP & Netboot PXE",
			subtitle: "/tftp",
			keywords: ["tftp", "pxe", "netboot", "boot", "uefi", "bios", "ipxe"],
			category: "Páginas & Navegação",
			icon: HardDriveDownloadIcon,
			action: () => goto("/tftp")
		},
		{
			id: "page-system",
			title: "Status & Telemetria do Sistema",
			subtitle: "/system",
			keywords: ["status", "cpu", "memoria", "uptime", "sistema", "hardware"],
			category: "Páginas & Navegação",
			icon: ServerIcon,
			action: () => goto("/system")
		},
		{
			id: "page-services",
			title: "Serviços do Daemon Lanforge",
			subtitle: "/system/services",
			keywords: ["servicos", "daemon", "lifecycle", "reiniciar", "parar"],
			category: "Páginas & Navegação",
			icon: LayersIcon,
			action: () => goto("/system/services")
		},
		{
			id: "page-database",
			title: "Banco de Dados & Backups",
			subtitle: "/system/database",
			keywords: ["banco", "redb", "backup", "restaurar", "limpeza", "tabelas"],
			category: "Páginas & Navegação",
			icon: DatabaseIcon,
			action: () => goto("/system/database")
		},
		{
			id: "page-users",
			title: "Usuários & Acessos Locais",
			subtitle: "/system/users",
			keywords: ["usuarios", "contas", "login", "senhas", "permissoes", "admin"],
			category: "Páginas & Navegação",
			icon: UsersIcon,
			action: () => goto("/system/users")
		},
		{
			id: "page-keys",
			title: "Chaves de API & Autenticação",
			subtitle: "/system/keys",
			keywords: ["api", "keys", "tokens", "bearer", "tokens", "scripts", "segredos"],
			category: "Páginas & Navegação",
			icon: KeyRoundIcon,
			action: () => goto("/system/keys")
		}
	];

	const filteredItems = $derived.by(() => {
		const q = search.trim().toLowerCase();
		if (!q) return items;
		return items.filter((item) => {
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
			<Dialog.Title>Paleta de Comandos</Dialog.Title>
			<Dialog.Description>Navegue rapidamente por páginas e execute ações do sistema</Dialog.Description>
		</Dialog.Header>

		<!-- Input Box -->
		<div class="flex items-center gap-3 px-4 py-3 border-b border-border/60 bg-background/50">
			<SearchIcon class="size-4 text-muted-foreground shrink-0" />
			<input
				bind:this={inputEl}
				bind:value={search}
				placeholder="Digite um comando ou busque uma página..."
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
					Nenhum resultado encontrado para "<span class="font-semibold text-foreground">{search}</span>".
				</div>
			{:else}
				{#each filteredItems as item, idx (item.id)}
					{@const isSelected = idx === selectedIndex}
					{@const Icon = item.icon}
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
							<span
								class="text-[10px] uppercase tracking-wider font-mono px-1.5 py-0.5 rounded {isSelected
									? 'bg-primary-foreground/20 text-primary-foreground'
									: 'bg-muted/60 text-muted-foreground'}"
							>
								{item.category === 'Ações Rápidas' ? 'Ação' : 'Página'}
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
					navegar
				</span>
				<span class="flex items-center gap-1">
					<kbd class="rounded border border-border/80 bg-background px-1 py-0.5 font-mono text-[10px]">↵</kbd>
					executar
				</span>
			</div>
			<span>
				Lanforge Quick Navigator
			</span>
		</div>
	</Dialog.Content>
</Dialog.Root>
