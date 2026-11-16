import BookmarkIcon from "@lucide/svelte/icons/bookmark";
import DatabaseIcon from "@lucide/svelte/icons/database";
import GlobeIcon from "@lucide/svelte/icons/globe";
import type { NavTabItem } from "$lib/components/NavTabs.svelte";

export const dnsTabs: NavTabItem[] = [
	{ label: "Resolver & Analytics", href: "/dns/resolver", icon: GlobeIcon },
	{ label: "Cache Inspection", href: "/dns/cache", icon: DatabaseIcon },
	{ label: "Custom Rewrites", href: "/dns/rewrites", icon: BookmarkIcon },
];
