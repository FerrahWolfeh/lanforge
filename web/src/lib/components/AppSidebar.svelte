<script lang="ts">
	import * as Sidebar from "$lib/components/ui/sidebar";
	import * as Tooltip from "$lib/components/ui/tooltip";
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

	const navGroups = [
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
			label: "DNS",
			items: [
				{ label: "Resolver", href: "/dns/resolver", icon: GlobeIcon },
				{ label: "Query Log", href: "/dns/log", icon: ListIcon },
				{ label: "Cache", href: "/dns/cache", icon: DatabaseIcon },
				{ label: "Adblock", href: "/dns/adblock", icon: ShieldIcon },
				{
					label: "Custom Rewrites",
					href: "/dns/rewrites",
					icon: RotateCcwIcon,
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
