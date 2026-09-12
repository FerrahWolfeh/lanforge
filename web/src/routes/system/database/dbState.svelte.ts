import {
	status,
	dbStats,
	exportSystemConfig,
} from "$lib/api/client";
import type {
	StatusResponse,
	DbMetrics,
	SystemConfigExport,
} from "$lib/api/types";
import ServerIcon from "@lucide/svelte/icons/server";
import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
import NetworkIcon from "@lucide/svelte/icons/network";
import GlobeIcon from "@lucide/svelte/icons/globe";
import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
import LockIcon from "@lucide/svelte/icons/lock";

export function formatBytes(bytes: number): string {
	if (!bytes || bytes === 0) return "0 B";
	const k = 1024;
	const sizes = ["B", "KB", "MB", "GB", "TB"];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

export function formatTimeAgo(secs: number | null | undefined): string {
	if (secs === null || secs === undefined) return "Never";
	if (secs < 60) return `${secs}s ago`;
	if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
	return `${Math.floor(secs / 3600)}h ago`;
}

class DbStateManager {
	systemStatus = $state<StatusResponse | null>(null);
	metrics = $state<DbMetrics | null>(null);
	configExport = $state<SystemConfigExport | null>(null);
	loading = $state(true);
	refreshing = $state(false);

	// Derived helpers
	isInMemory = $derived.by(() => {
		const path = this.systemStatus?.db?.path?.toLowerCase() || "";
		return (
			!path ||
			path === "memory" ||
			path === "none" ||
			path === "mock" ||
			path.startsWith("/tmp") ||
			path.startsWith("/run") ||
			path.includes(":memory:")
		);
	});

	engineLabel = $derived(
		this.isInMemory ? "Volatile / In-Memory" : "Persistent (redb)",
	);

	isHealthy = $derived.by(() => {
		if (!this.metrics) return true;
		if (typeof this.metrics.last_error === "boolean") {
			return !this.metrics.last_error;
		}
		return this.metrics.last_error === 0;
	});

	inventoryItems = $derived.by(() => {
		const cfg = this.configExport;
		const devCount = this.metrics?.devices_written ?? 0;
		const staticHostCount = cfg?.hosts?.length ?? 0;
		const dhcpv4Pools = cfg?.dhcp_v4_pools?.length ?? 0;
		const dhcpv6Pools = cfg?.dhcp_v6_pools?.length ?? 0;
		const dnsRewrites = cfg?.dns_rewrites?.length ?? 0;
		const dnsUpstreams = cfg?.dns_upstreams?.length ?? 0;
		const dnsReverseResolvers = cfg?.dns_reverse_resolvers?.length ?? 0;
		const adblockSources = cfg?.dns_adblock_urls?.length ?? 0;
		const allowlistRules = cfg?.dns_allowlist?.length ?? 0;
		const apiTokens = cfg?.api_tokens?.length ?? 0;

		return [
			{
				id: "devices",
				title: "Discovered Devices",
				category: "Network Inventory",
				icon: ServerIcon,
				count: devCount,
				unit: "devices",
				route: "/network/devices",
				description:
					"Discovered dynamic and active host records with IP, MAC, and lease associations",
			},
			{
				id: "hosts",
				title: "Static Hosts & Reservations",
				category: "Network Inventory",
				icon: HardDriveIcon,
				count: staticHostCount,
				unit: "static bindings",
				route: "/network/hosts",
				description:
					"Persistent hostnames and fixed IP address bindings",
			},
			{
				id: "dhcp_pools",
				title: "DHCP Scopes & Pools",
				category: "DHCP Orchestration",
				icon: NetworkIcon,
				count: dhcpv4Pools + dhcpv6Pools,
				unit: "pools",
				route: "/dhcp/pools",
				description: `Managed allocation pools (${dhcpv4Pools} IPv4 pools, ${dhcpv6Pools} IPv6 pools)`,
			},
			{
				id: "dns_rewrites",
				title: "Custom DNS Rewrites",
				category: "DNS Engine",
				icon: GlobeIcon,
				count: dnsRewrites,
				unit: "records",
				route: "/dns/rewrites",
				description:
					"Authoritative A, AAAA, CNAME, and TXT internal domain overrides",
			},
			{
				id: "dns_upstreams",
				title: "DNS Forwarders & Resolvers",
				category: "DNS Engine",
				icon: GlobeIcon,
				count: dnsUpstreams + dnsReverseResolvers,
				unit: "resolvers",
				route: "/dns/resolver",
				description: `Upstream targets (${dnsUpstreams} general upstreams, ${dnsReverseResolvers} reverse zones)`,
			},
			{
				id: "adblock",
				title: "Adblock Sources & Rules",
				category: "Content Filtering",
				icon: ShieldCheckIcon,
				count: adblockSources + allowlistRules,
				unit: "sources & rules",
				route: "/dns/adblock",
				description: `Filter feeds (${adblockSources} blocklists, ${allowlistRules} allowlist exceptions)`,
			},
			{
				id: "api_tokens",
				title: "API Access Tokens",
				category: "Security & Auth",
				icon: LockIcon,
				count: apiTokens,
				unit: "active tokens",
				route: "/system/auth",
				description:
					"Programmatic bearer tokens for CLI and external integration access",
			},
		];
	});

	totalStoredEntities = $derived(
		this.inventoryItems.reduce((acc, item) => acc + item.count, 0),
	);

	async loadAll(silent = false) {
		if (!silent) this.refreshing = true;
		try {
			const [s, m, cfg] = await Promise.all([
				status().catch(() => null),
				dbStats().catch(() => null),
				exportSystemConfig().catch(() => null),
			]);
			if (s) this.systemStatus = s;
			if (m) this.metrics = m;
			if (cfg) this.configExport = cfg;
		} finally {
			if (!silent) {
				this.loading = false;
				this.refreshing = false;
			}
		}
	}
}

export const dbState = new DbStateManager();
