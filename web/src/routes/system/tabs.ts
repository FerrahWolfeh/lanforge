import ActivityIcon from "@lucide/svelte/icons/activity";
import KeyRoundIcon from "@lucide/svelte/icons/key-round";
import LayersIcon from "@lucide/svelte/icons/layers";
import ServerIcon from "@lucide/svelte/icons/server";
import UsersIcon from "@lucide/svelte/icons/users";
import type { NavTabItem } from "$lib/components/NavTabs.svelte";

export const systemTabs: NavTabItem[] = [
	{ label: "System Status", href: "/system", icon: ServerIcon },
	{ label: "Services & Daemons", href: "/system/services", icon: LayersIcon },
	{ label: "Event Stream", href: "/system/events", icon: ActivityIcon },
];

export const accessTabs: NavTabItem[] = [
	{ label: "Users", href: "/system/users", icon: UsersIcon },
	{ label: "API & Auth Keys", href: "/system/keys", icon: KeyRoundIcon },
];
