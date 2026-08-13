/**
 * Lanforge API client — thin typed fetch wrapper.
 * Method names mirror API.md 1:1 for easy cross-reference.
 * All calls are proxied through Vite's `/api` proxy in dev,
 * or hit the same origin in production (served by axum).
 */

import type {
	AllowlistEntry,
	AuthStatusResponse,
	AuthToken,
	DeviceEntry,
	DevicesResponse,
	DhcpLease,
	DhcpPoolStats,
	DnsAdblockStatusResponse,
	DnsAdblockUrlEntry,
	DnsAnalyticsResponse,
	DnsCacheEntry,
	DnsCacheStatsResponse,
	DnsQueryLogEntry,
	DnsStatsResponse,
	DnsUpstreamEntry,
	DnsUpstreamsResponse,
	HostConfigEntry,
	LeaseTarget,
	LoginRequest,
	LoginResponse,
	ReverseResolverEntry,
	RewriteRule,
	StatusResponse,
	UserInfo
} from './types';

// ---------------------------------------------------------------------------
// Core transport
// ---------------------------------------------------------------------------

export class ApiError extends Error {
	constructor(
		public readonly status: number,
		message: string
	) {
		super(message);
		this.name = 'ApiError';
	}
}

function getToken(): string | null {
	if (typeof localStorage === 'undefined') return null;
	return localStorage.getItem('lf_session');
}

async function request<T>(
	method: string,
	path: string,
	body?: unknown,
	extraHeaders?: Record<string, string>
): Promise<T> {
	const token = getToken();
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		...extraHeaders
	};
	if (token) headers['Authorization'] = `Bearer ${token}`;

	const res = await fetch(`/api/v1${path}`, {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});

	if (res.status === 204) return undefined as T;

	const json = await res.json();

	if (!res.ok) {
		throw new ApiError(res.status, json?.error ?? `HTTP ${res.status}`);
	}

	// Unwrap { "data": ... } envelope
	return ('data' in json ? json.data : json) as T;
}

async function requestRaw<T>(
	method: string,
	path: string,
	body?: unknown,
	extraHeaders?: Record<string, string>
): Promise<T> {
	const token = getToken();
	const headers: Record<string, string> = {
		'Content-Type': 'application/json',
		...extraHeaders
	};
	if (token) headers['Authorization'] = `Bearer ${token}`;

	const res = await fetch(`/api/v1${path}`, {
		method,
		headers,
		body: body !== undefined ? JSON.stringify(body) : undefined
	});

	if (res.status === 204) return undefined as T;

	const json = await res.json();

	if (!res.ok) {
		throw new ApiError(res.status, json?.error ?? `HTTP ${res.status}`);
	}

	return json as T;
}

const get = <T>(path: string, params?: Record<string, string | number | boolean | undefined>) => {
	const url = new URL(path, 'http://x');
	if (params) {
		for (const [k, v] of Object.entries(params)) {
			if (v !== undefined) url.searchParams.set(k, String(v));
		}
	}
	return request<T>('GET', url.pathname + url.search);
};

const getRaw = <T>(
	path: string,
	params?: Record<string, string | number | boolean | undefined>
) => {
	const url = new URL(path, 'http://x');
	if (params) {
		for (const [k, v] of Object.entries(params)) {
			if (v !== undefined) url.searchParams.set(k, String(v));
		}
	}
	return requestRaw<T>('GET', url.pathname + url.search);
};
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body);
const put = <T>(path: string, body?: unknown) => request<T>('PUT', path, body);
const patch = <T>(path: string, body?: unknown) => request<T>('PATCH', path, body);
const del = <T>(path: string, body?: unknown) => request<T>('DELETE', path, body);

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const authStatus = () => get<AuthStatusResponse>('/auth/status');
export const login = (req: LoginRequest) => post<LoginResponse>('/auth/login', req);
export const me = () => get<UserInfo>('/auth/me');
export const changePassword = (current_password: string, new_password: string) =>
	post<void>('/auth/change-password', { current_password, new_password });
export const listTokens = () => get<AuthToken[]>('/auth/tokens');
export const validateToken = (token: string) =>
	post<{ valid: boolean }>('/auth/validate', { token });

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

export const status = () => get<StatusResponse>('/status');
export const scan = () => post<void>('/scan');
export const reload = () => post<void>('/reload');
export const shutdown = () => post<void>('/shutdown');

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export const listDevices = (params?: {
	filter?: string;
	sort?: string;
	limit?: number;
	offset?: number;
}) => get<DevicesResponse>('/devices', params);

export const whois = (target: string) => get<DeviceEntry>(`/devices/${encodeURIComponent(target)}`);
export const purge = (target: string) => del<void>(`/devices/${encodeURIComponent(target)}`);
export const wol = (target: string) =>
	post<void>(`/devices/${encodeURIComponent(target)}/wol`);

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

export const hostList = () => get<HostConfigEntry[]>('/hosts');
export const hostAdd = (entry: HostConfigEntry) => post<void>('/hosts', entry);
export const hostSet = (mac: string, field: string, value: string) =>
	patch<void>(`/hosts/${mac}`, { field, value });
export const hostRemove = (mac: string) => del<void>(`/hosts/${mac}`);
export const hostExport = () => get<HostConfigEntry[]>('/hosts/export');
export const hostImport = (entries: HostConfigEntry[]) => post<void>('/hosts/import', entries);

// ---------------------------------------------------------------------------
// DNS — resolver
// ---------------------------------------------------------------------------

export const dnsStats = () => get<DnsStatsResponse>('/dns/stats');
export const dnsAnalytics = (limit?: number, client?: string) =>
	get<DnsAnalyticsResponse>('/dns/analytics', {
		...(limit !== undefined && { limit }),
		...(client && { client })
	});
export const dnsQuery = (name: string, type?: string) =>
	get<unknown>('/dns/query', { name, type });
export const dnsQueryLog = async (params?: {
	client?: string;
	limit?: number;
	offset?: number;
}): Promise<{ entries: DnsQueryLogEntry[]; total: number }> => {
	const res = await getRaw<any>('/dns/log', params);
	if (!res) return { entries: [], total: 0 };
	const list: DnsQueryLogEntry[] = Array.isArray(res)
		? res
		: Array.isArray(res.data)
			? res.data
			: Array.isArray(res.entries)
				? res.entries
				: [];
	const totalCount =
		typeof res.meta?.total === 'number'
			? res.meta.total
			: typeof res.total === 'number'
				? res.total
				: list.length;
	return { entries: list, total: totalCount };
};
export const dnsUpstreams = () => get<DnsUpstreamsResponse | DnsUpstreamEntry[]>('/dns/upstreams');
export const dnsUpstreamAdd = (entry: { addr: string; protocol: string; domain?: string }) =>
	post<void>('/dns/upstreams', entry);
export const dnsUpstreamRemove = (entry: { addr: string; protocol: string }) =>
	del<void>('/dns/upstreams', entry);

export const dnsReverseResolverList = async (): Promise<ReverseResolverEntry[]> => {
	const res = await get<any>('/dns/reverse-resolvers');
	if (!res) return [];
	if (Array.isArray(res)) return res;
	if (Array.isArray(res.resolvers)) return res.resolvers;
	if (Array.isArray(res.data)) return res.data;
	return [];
};
export const dnsReverseResolverAdd = (subnet: string, resolver_uri: string) =>
	post<void>('/dns/reverse-resolvers', { subnet, resolver_uri });
export const dnsReverseResolverRemove = (subnet: string) =>
	del<void>('/dns/reverse-resolvers', { subnet });

// ---------------------------------------------------------------------------
// DNS — cache
// ---------------------------------------------------------------------------

export const dnsCacheDump = async (params?: {
	limit?: number;
	offset?: number;
	q?: string;
	kind?: string;
}): Promise<{ entries: DnsCacheEntry[]; total: number }> => {
	const res = await getRaw<any>('/dns/cache', params);
	if (!res) return { entries: [], total: 0 };
	const list: DnsCacheEntry[] = Array.isArray(res)
		? res
		: Array.isArray(res.data)
			? res.data
			: Array.isArray(res.entries)
				? res.entries
				: [];
	const totalCount =
		typeof res.meta?.total === 'number'
			? res.meta.total
			: typeof res.total === 'number'
				? res.total
				: list.length;
	return { entries: list, total: totalCount };
};
export const dnsCacheFlush = () => del<void>('/dns/cache');
export const dnsCacheStatsExt = () => get<DnsCacheStatsResponse>('/dns/cache/stats');

// ---------------------------------------------------------------------------
// DNS — adblock
// ---------------------------------------------------------------------------

export const dnsAdblockStatus = () => get<DnsAdblockStatusResponse>('/dns/adblock');
export const dnsAdblockSet = (enabled: boolean, duration_secs?: number) =>
	put<void>('/dns/adblock', { enabled, duration_secs: duration_secs ?? null });
export const dnsAdblockReload = () => post<void>('/dns/adblock/reload');
export const dnsAdblockAllowlist = () => get<AllowlistEntry[]>('/dns/adblock/allowlist');
export const dnsBlock = (domain: string) => post<void>('/dns/adblock/block', { domain });
export const dnsAllow = (domain: string) => post<void>('/dns/adblock/allow', { domain });
export const dnsUnallow = (target: string) =>
	del<void>(`/dns/adblock/allow/${encodeURIComponent(target)}`);
export const dnsAdblockUrls = () => get<DnsAdblockUrlEntry[]>('/dns/adblock/sources');
export const dnsAdblockUrlAdd = (entry: DnsAdblockUrlEntry) =>
	post<void>('/dns/adblock/sources', entry);
export const dnsAdblockUrlRemove = (entry: DnsAdblockUrlEntry) =>
	del<void>('/dns/adblock/sources', entry);

// ---------------------------------------------------------------------------
// DNS — rewrites
// ---------------------------------------------------------------------------

export const dnsRewriteList = () => get<RewriteRule[]>('/dns/rewrites');
export const dnsRewriteAdd = (rule: Omit<RewriteRule, 'id'>) => post<void>('/dns/rewrites', rule);
export const dnsRewriteRemove = (id: number) => del<void>(`/dns/rewrites/${id}`);
export const dnsRewriteClear = () => del<void>('/dns/rewrites');
export const dnsRewriteExport = () => get<RewriteRule[]>('/dns/rewrites/export');
export const dnsRewriteImport = (rules: RewriteRule[]) => post<void>('/dns/rewrites/import', rules);

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

export const leases = () => get<DhcpLease[]>('/dhcp/leases');
export const dhcpPools = () => get<DhcpPoolStats[]>('/dhcp/pools');
export const leaseRenew = (mac: string, target?: LeaseTarget) =>
	post<void>(`/dhcp/leases/${mac}/renew`, target ? { target } : undefined);
export const leaseRelease = (mac: string, target?: LeaseTarget) =>
	post<void>(`/dhcp/leases/${mac}/release`, target ? { target } : undefined);

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

export const dbVacuum = () => post<void>('/db/vacuum');
export const dbPrune = () => post<void>('/db/prune');
export const dbLogClean = () => post<void>('/db/log-clean');
export const dbReset = () => del<void>('/db', undefined);

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export const userList = () => get<UserInfo[]>('/users');
export const userCreate = (username: string, password: string, role?: string) =>
	post<UserInfo>('/users', { username, password, role });
export const userDelete = (username: string) => del<void>(`/users/${encodeURIComponent(username)}`);
export const userPasswd = (username: string, new_password: string) =>
	put<void>(`/users/${encodeURIComponent(username)}/password`, { new_password });

// ---------------------------------------------------------------------------
// SSE helpers
// ---------------------------------------------------------------------------

/**
 * Build the URL for the global event SSE stream.
 * The caller is responsible for creating the EventSource and managing it.
 */
export function eventsUrl(params?: { filter?: string; initial?: number }): string {
	const url = new URL('/api/v1/events', window.location.origin);
	if (params?.filter) url.searchParams.set('filter', params.filter);
	if (params?.initial) url.searchParams.set('initial', String(params.initial));
	return url.toString();
}

/**
 * Build the URL for the DNS log SSE stream.
 */
export function dnsLogSseUrl(params?: { client?: string; limit?: number }): string {
	const url = new URL('/api/v1/dns/log', window.location.origin);
	url.searchParams.set('follow', 'true');
	if (params?.client) url.searchParams.set('client', params.client);
	if (params?.limit) url.searchParams.set('limit', String(params.limit));
	return url.toString();
}
