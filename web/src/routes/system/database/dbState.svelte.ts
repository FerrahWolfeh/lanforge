import { status, dbStats, leases, userList, listTokens } from "$lib/api/client";
import type { StatusResponse, DbMetrics } from "$lib/api/types";
import ServerIcon from "@lucide/svelte/icons/server";
import NetworkIcon from "@lucide/svelte/icons/network";
import UsersIcon from "@lucide/svelte/icons/users";
import KeyIcon from "@lucide/svelte/icons/key-round";

export { formatBytes, formatTimeAgo } from "$lib/utils";

class DbStateManager {
	systemStatus = $state<StatusResponse | null>(null);
	metrics = $state<DbMetrics | null>(null);
	/** null = not readable for this session (users and tokens are admin-only). */
	leaseCount = $state<number | null>(null);
	userCount = $state<number | null>(null);
	tokenCount = $state<number | null>(null);
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

	isHealthy = $derived.by(() => {
		if (!this.metrics) return true;
		if (typeof this.metrics.last_error === "boolean") {
			return !this.metrics.last_error;
		}
		return this.metrics.last_error === 0;
	});

	// What redb holds is state, not configuration (that is lanforge.toml): only state is listed.
	inventoryItems = $derived.by(() => [
		{
			id: "devices",
			title: "Devices",
			icon: ServerIcon,
			count: this.systemStatus?.devices?.total ?? null,
			unit: "devices",
			route: "/network/devices",
			description: "Every device seen on the LAN, with its addresses, names and settings",
		},
		{
			id: "leases",
			title: "DHCP Leases",
			icon: NetworkIcon,
			count: this.leaseCount,
			unit: "leases",
			route: "/dhcp/leases",
			description: "Addresses handed out, kept across restarts",
		},
		{
			id: "users",
			title: "Users",
			icon: UsersIcon,
			count: this.userCount,
			unit: "accounts",
			route: "/system/users",
			description: "Accounts that can sign in to this WebUI",
		},
		{
			id: "tokens",
			title: "API Tokens",
			icon: KeyIcon,
			count: this.tokenCount,
			unit: "tokens",
			route: "/system/keys",
			description: "Long-lived tokens for scripts and other programs",
		},
	]);

	/** No endpoint returns these counts, so they cost three full list fetches: poll them slowly. */
	private countsAt = 0;

	async loadAll(silent = false) {
		if (!silent) this.refreshing = true;
		try {
			const withCounts = !silent || Date.now() - this.countsAt >= COUNTS_REFRESH_MS;
			const [s, m, l, u, t] = await Promise.all([
				status().catch(() => null),
				dbStats().catch(() => null),
				withCounts ? leases().catch(() => null) : undefined,
				withCounts ? userList().catch(() => null) : undefined,
				withCounts ? listTokens().catch(() => null) : undefined,
			]);
			if (s) this.systemStatus = s;
			if (m) this.metrics = m;
			if (withCounts) {
				this.countsAt = Date.now();
				this.leaseCount = l ? l.length : null;
				this.userCount = u ? u.length : null;
				this.tokenCount = t ? t.length : null;
			}
		} finally {
			if (!silent) {
				this.loading = false;
				this.refreshing = false;
			}
		}
	}
}

const COUNTS_REFRESH_MS = 30_000;

export const dbState = new DbStateManager();
