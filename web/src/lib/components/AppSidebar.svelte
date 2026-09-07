<script lang="ts">
	import * as Sidebar from "$lib/components/ui/sidebar";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import * as Collapsible from "$lib/components/ui/collapsible";
	import { page } from "$app/stores";
	import LayoutDashboardIcon from "@lucide/svelte/icons/layout-dashboard";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import ServerIcon from "@lucide/svelte/icons/server";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ListIcon from "@lucide/svelte/icons/list";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import PlugZapIcon from "@lucide/svelte/icons/plug-zap";
	import LockIcon from "@lucide/svelte/icons/lock";
	import KeyIcon from "@lucide/svelte/icons/key";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ChevronRightIcon from "@lucide/svelte/icons/chevron-right";
	import CpuIcon from "@lucide/svelte/icons/cpu";

	interface NavItemChild {
		label: string;
		href: string;
	}

	interface NavItem {
		label: string;
		href: string;
		icon: any;
		children?: NavItemChild[];
	}

	interface NavGroup {
		label: string;
		items: NavItem[];
	}

	const navGroups: NavGroup[] = [
		{
			label: "Overview",
			items: [
				{ label: "Dashboard", href: "/", icon: LayoutDashboardIcon },
			],
		},
		{
			label: "Network",
			items: [
				{
					label: "Devices",
					href: "/network/devices",
					icon: MonitorIcon,
				},
				{
					label: "Static Hosts",
					href: "/network/hosts",
					icon: BookmarkIcon,
				},
				{
					label: "PPPoE WAN",
					href: "/network/pppoe",
					icon: PlugZapIcon,
				},
				{
					label: "IPv6 RA",
					href: "/network/ra",
					icon: RadioIcon,
				},
			],
		},

		{
			label: "DNS & Security",
			items: [
				{
					label: "DNS Server",
					href: "/dns/resolver",
					icon: GlobeIcon,
					children: [
						{ label: "Overview", href: "/dns/resolver" },
						{ label: "Settings", href: "/dns/settings" },
						{ label: "Custom Rewrites", href: "/dns/rewrites" },
						{ label: "Cache", href: "/dns/cache" },
						{ label: "Query Log", href: "/dns/log" },
					],
				},
				{
					label: "Adblock",
					href: "/dns/adblock",
					icon: ShieldIcon,
					children: [
						{ label: "Overview", href: "/dns/adblock" },
						{ label: "Blocklists", href: "/dns/adblock/lists" },
						{ label: "Custom Rules", href: "/dns/adblock/rules" },
						{ label: "Blocked Services", href: "/dns/adblock/services" },
						{ label: "Settings", href: "/dns/adblock/settings" },
					],
				},
			],
		},
		{
			label: "DHCP",
			items: [
				{ label: "Leases", href: "/dhcp/leases", icon: NetworkIcon },
				{ label: "Pools", href: "/dhcp/pools", icon: ActivityIcon },
				{ label: "Scopes", href: "/dhcp/scopes", icon: LayersIcon },
				{
					label: "Server Options",
					href: "/dhcp/server",
					icon: SlidersIcon,
				},
			],
		},
		{
			label: "System",
			items: [
				{ label: "Status", href: "/system", icon: ServerIcon },
				{ label: "Services", href: "/system/services", icon: CpuIcon },
				{
					label: "Database",
					href: "/system/database",
					icon: DatabaseIcon,
				},
				{ label: "Auth & Tokens", href: "/system/auth", icon: KeyIcon },
			],
		},
	];

	function isActive(href: string) {
		const p = $page.url.pathname;
		if (href === "/") return p === "/";
		if (href === "/system") return p === "/system" || p === "/system/";
		return p === href || p.startsWith(href + "/");
	}

	function isSubActive(href: string) {
		const p = $page.url.pathname;
		if (href === "/dns/resolver") return p === "/dns/resolver" || p === "/dns/resolver/";
		if (href === "/dns/adblock") return p === "/dns/adblock" || p === "/dns/adblock/";
		return p === href || p.startsWith(href + "/");
	}
</script>

<Sidebar.Root collapsible="icon">
	<Sidebar.Header>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<Sidebar.MenuButton size="lg" tooltipContent="Lanforge">
					{#snippet child({ props })}
						<a
							href="/"
							{...props}
							class={[props.class, "gap-3"].join(" ")}
						>
							<WifiIcon class="text-primary" />
							<span class="font-semibold tracking-tight"
								>Lanforge</span
							>
						</a>
					{/snippet}
				</Sidebar.MenuButton>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Header>

	<Sidebar.Content>
		{#each navGroups as group (group.label)}
			<Sidebar.Group>
				<Sidebar.GroupLabel>{group.label}</Sidebar.GroupLabel>
				<Sidebar.GroupContent>
					<Sidebar.Menu>
						{#each group.items as item (item.href)}
							{#if item.children}
								{@const isChildActive = item.children.some((c: NavItemChild) => isSubActive(c.href))}
								<Collapsible.Root open={isChildActive} class="group/collapsible">
									<Sidebar.MenuItem>
										<Collapsible.Trigger class="w-full">
											{#snippet child({ props })}
												<Sidebar.MenuButton
													{...props}
													isActive={isChildActive}
													tooltipContent={item.label}
												>
													<item.icon />
													<span>{item.label}</span>
													<ChevronRightIcon
														class="ml-auto transition-transform duration-200 group-data-[state=open]/collapsible:rotate-90"
													/>
												</Sidebar.MenuButton>
											{/snippet}
										</Collapsible.Trigger>
										<Collapsible.Content>
											<Sidebar.MenuSub>
												{#each item.children as sub (sub.href)}
													<Sidebar.MenuSubItem>
														<Sidebar.MenuSubButton isActive={isSubActive(sub.href)}>
															{#snippet child({ props })}
																<a href={sub.href} {...props}>
																	<span>{sub.label}</span>
																</a>
															{/snippet}
														</Sidebar.MenuSubButton>
													</Sidebar.MenuSubItem>
												{/each}
											</Sidebar.MenuSub>
										</Collapsible.Content>
									</Sidebar.MenuItem>
								</Collapsible.Root>
							{:else}
								<Sidebar.MenuItem>
									<Sidebar.MenuButton
										isActive={isActive(item.href)}
										tooltipContent={item.label}
									>
										{#snippet child({ props })}
											<a href={item.href} {...props}>
												<item.icon />
												<span>{item.label}</span>
											</a>
										{/snippet}
									</Sidebar.MenuButton>
								</Sidebar.MenuItem>
							{/if}
						{/each}
					</Sidebar.Menu>
				</Sidebar.GroupContent>
			</Sidebar.Group>
		{/each}
	</Sidebar.Content>

	<Sidebar.Footer>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<Sidebar.MenuButton size="sm">
					<WifiIcon class="text-muted-foreground" />
					<span class="text-muted-foreground text-xs">lanforged</span>
				</Sidebar.MenuButton>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Footer>

	<Sidebar.Rail />
</Sidebar.Root>
