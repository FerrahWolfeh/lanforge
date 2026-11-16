import BookmarkIcon from "@lucide/svelte/icons/bookmark";
import MonitorIcon from "@lucide/svelte/icons/monitor";
import type { NavTabItem } from "$lib/components/NavTabs.svelte";

export const lanTabs: NavTabItem[] = [
	{ label: "Discovered Devices", href: "/network/devices", icon: MonitorIcon },
	{ label: "Static Hosts", href: "/network/hosts", icon: BookmarkIcon },
];
