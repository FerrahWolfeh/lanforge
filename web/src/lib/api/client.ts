/**
 * Lanforge API client — thin typed fetch wrapper.
 * Method names mirror API.md 1:1 for easy cross-reference.
 * All calls are proxied through Vite's `/api` proxy in dev,
 * or hit the same origin in production (served by axum).
 */

import type {
	AdblockRuleEntry,
	AllowlistEntry,
	AuthStatusResponse,
	AuthToken,
	BlockingMode,
	DeviceEntry,
	DevicesResponse,
	DhcpLease,
	DhcpOptionsConfig,
	DhcpPoolEntry,
	DhcpPoolsConfigResponse,
	DhcpPoolsResponse,
	DhcpReconcileResponse,
	Dhcpv4PoolConfig,
	Dhcpv6PoolConfig,
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
	SetupPayload,
	SetupResponse,
	SetupStatusResponse,
	StatusResponse,
	UserInfo,
	PppoeConfig,
	PppoeStatusResponse,
	RaServerConfig,
	RaStatusResponse,
	DbMetrics,
	SystemConfigExport,
	SystemConfigImportResponse,
	DbEngineSwitchRequest
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
		if (res.status === 401 && path !== '/auth/login' && path !== '/auth/status') {
			if (typeof localStorage !== 'undefined') {
				localStorage.removeItem('lf_session');
			}
			if (typeof window !== 'undefined' && window.location.pathname !== '/login' && window.location.pathname !== '/setup') {
				window.location.href = '/login';
			}
		}
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
		if (res.status === 401 && path !== '/auth/login' && path !== '/auth/status') {
			if (typeof localStorage !== 'undefined') {
				localStorage.removeItem('lf_session');
			}
			if (typeof window !== 'undefined' && window.location.pathname !== '/login' && window.location.pathname !== '/setup') {
				window.location.href = '/login';
			}
		}
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

async function requestText(
	path: string,
	params?: Record<string, string | number | boolean | undefined>
): Promise<string> {
	const token = getToken();
	const headers: Record<string, string> = {};
	if (token) headers['Authorization'] = `Bearer ${token}`;

	const url = new URL(path, 'http://x');
	if (params) {
		for (const [k, v] of Object.entries(params)) {
			if (v !== undefined) url.searchParams.set(k, String(v));
		}
	}

	const res = await fetch(`/api/v1${url.pathname + url.search}`, {
		method: 'GET',
		headers
	});

	if (!res.ok) {
		if (res.status === 401 && path !== '/auth/login' && path !== '/auth/status') {
			if (typeof localStorage !== 'undefined') {
				localStorage.removeItem('lf_session');
			}
			if (
				typeof window !== 'undefined' &&
				window.location.pathname !== '/login' &&
				window.location.pathname !== '/setup'
			) {
				window.location.href = '/login';
			}
		}
		const text = await res.text();
		throw new ApiError(res.status, text || `HTTP ${res.status}`);
	}

	return res.text();
}

const getText = (
	path: string,
	params?: Record<string, string | number | boolean | undefined>
) => requestText(path, params);

const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body);
const put = <T>(path: string, body?: unknown) => request<T>('PUT', path, body);
const patch = <T>(path: string, body?: unknown) => request<T>('PATCH', path, body);
const del = <T>(path: string, body?: unknown, extraHeaders?: Record<string, string>) =>
	request<T>('DELETE', path, body, extraHeaders);

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const authStatus = () => get<AuthStatusResponse>('/auth/status');
export const login = (req: LoginRequest) => post<LoginResponse>('/auth/login', req);
export const logout = () => post<void>('/auth/logout');
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
	const res = await getRaw<any>('/dns/logs', params);
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
export const dnsAdblockConfigSet = (config: {
	blocking_mode?: BlockingMode;
	blocking_ip_v4?: string | null;
	blocking_ip_v6?: string | null;
}) => post<void>('/dns/adblock/config', config);
export const dnsAdblockRules = async (): Promise<AdblockRuleEntry[]> => {
	const res = await get<any>('/dns/adblock/rules');
	if (!res) return [];
	if (Array.isArray(res)) return res;
	if (Array.isArray(res.rules)) return res.rules;
	if (Array.isArray(res.data)) return res.data;
	return [];
};
export const dnsAdblockRuleAdd = (domain: string, action: 'block' | 'allow') =>
	post<void>('/dns/adblock/rules', { domain, action });
export const dnsAdblockRuleRemove = (id: number) =>
	del<void>(`/dns/adblock/rules/${id}`);
export const dnsAdblockRuleStatus = (id: number, enabled: boolean) =>
	put<void>(`/dns/adblock/rules/${id}/status`, { enabled });

// ---------------------------------------------------------------------------
// DNS — rewrites
// ---------------------------------------------------------------------------

export const dnsRewriteList = async (): Promise<RewriteRule[]> => {
	const res = await get<any>('/dns/rewrites');
	if (!res) return [];
	if (Array.isArray(res)) return res;
	if (Array.isArray(res.rewrites)) return res.rewrites;
	if (Array.isArray(res.data)) return res.data;
	return [];
};
export const dnsRewriteAdd = (rule: Omit<RewriteRule, 'id'>) => post<void>('/dns/rewrites', rule);
export const dnsRewriteRemove = (id: number) => del<void>(`/dns/rewrites/${id}`);
export const dnsRewriteClear = () => del<void>('/dns/rewrites');
export const dnsRewriteExport = async (): Promise<RewriteRule[]> => {
	const res = await get<any>('/dns/rewrites/export');
	if (!res) return [];
	if (Array.isArray(res)) return res;
	if (Array.isArray(res.rewrites)) return res.rewrites;
	if (Array.isArray(res.data)) return res.data;
	return [];
};
export const dnsRewriteImport = (rules: RewriteRule[]) => post<void>('/dns/rewrites/import', rules);

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

export const leases = async (): Promise<DhcpLease[]> => {
	const res = await get<any>('/dhcp/leases');
	if (!res) return [];
	if (Array.isArray(res)) return res;
	if (Array.isArray(res.leases)) return res.leases;
	if (Array.isArray(res.data)) return res.data;
	return [];
};

export const dhcpPools = async (): Promise<DhcpPoolsResponse> => {
	const res = await get<any>('/dhcp/pools');
	if (!res) return { v4_pools: [], v6_pools: [] };
	const data = res.data ?? res;
	return {
		v4_pools: Array.isArray(data.v4_pools) ? data.v4_pools : [],
		v6_pools: Array.isArray(data.v6_pools) ? data.v6_pools : []
	};
};

export const dhcpOptionsGet = async (): Promise<DhcpOptionsConfig> => {
	const res = await get<any>('/dhcp/options');
	const data = res?.data ?? res;
	return data?.options ?? data;
};

export const dhcpOptionsUpdate = (options: DhcpOptionsConfig) =>
	put<void>('/dhcp/options', options);

export const dhcpPoolsConfigGet = async (): Promise<DhcpPoolsConfigResponse> => {
	const res = await get<any>('/dhcp/pools/config');
	const data = res?.data ?? res;
	return {
		v4_pools: Array.isArray(data?.v4_pools) ? data.v4_pools : [],
		v6_pools: Array.isArray(data?.v6_pools) ? data.v6_pools : [],
		active_ula_prefix: data?.active_ula_prefix ?? null,
		active_gua_prefix: data?.active_gua_prefix ?? null,
	};
};

export const dhcpPoolsConfigUpdate = (v4_pools: Dhcpv4PoolConfig[], v6_pools: Dhcpv6PoolConfig[]) => {
	const sanitizedV4 = v4_pools.map((p) => ({
		...p,
		name: p.name?.trim() || null,
		router: p.router?.trim() || null,
		subnet_mask: p.subnet_mask?.trim() || null,
		domain_name: p.domain_name?.trim() || null,
		boot_file: p.boot_file?.trim() || null,
		tftp_server: p.tftp_server?.trim() || null,
		lease_time: p.lease_time ? Number(p.lease_time) : null,
	}));
	const sanitizedV6 = v6_pools.map((p) => ({
		...p,
		name: p.name?.trim() || null,
		address: p.address?.trim() || null,
		boot_file: p.boot_file?.trim() || null,
		lease_time: p.lease_time ? Number(p.lease_time) : null,
	}));
	return put<void>('/dhcp/pools/config', { v4_pools: sanitizedV4, v6_pools: sanitizedV6 });
};

export const leaseRenew = (mac: string, target?: LeaseTarget) =>
	post<void>(`/dhcp/leases/${encodeURIComponent(mac)}/renew`, target !== undefined ? { target } : {});

export const leaseRelease = (mac: string, target?: LeaseTarget) =>
	post<void>(`/dhcp/leases/${encodeURIComponent(mac)}/release`, target !== undefined ? { target } : {});

export const dhcpReconcile = async (): Promise<DhcpReconcileResponse> => {
	const res = await post<any>('/dhcp/reconcile', {});
	return res?.data ?? res;
};

// ---------------------------------------------------------------------------
// Database & Configuration
// ---------------------------------------------------------------------------

export const dbStats = () => get<DbMetrics>('/db/stats');
export const dbVacuum = () => post<void>('/db/vacuum');
export const dbPrune = () => post<void>('/db/prune');
export const dbLogClean = () => post<void>('/db/log-clean');
export const dbReset = () => del<void>('/db', undefined, { 'x-confirm': 'wipe' });
export const exportSystemConfig = () => get<SystemConfigExport>('/system/config');
export const exportSystemConfigToml = () => getText('/system/config', { format: 'toml' });
export const importSystemConfig = (config: SystemConfigExport) =>
	post<SystemConfigImportResponse>('/system/config', config);
export const switchDbEngine = (req: DbEngineSwitchRequest) =>
	post<void>('/db/engine', req);

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
// PPPoE WAN & Fast-Path
// ---------------------------------------------------------------------------

export const pppoeStatus = () => get<PppoeStatusResponse>('/pppoe/status');
export const pppoeConfig = () => get<PppoeConfig>('/pppoe/config');
export const pppoeUpdateConfig = (cfg: PppoeConfig) => post<void>('/pppoe/config', cfg);
export const pppoeReconnect = () => post<void>('/pppoe/reconnect');
export const pppoeDisconnect = () => post<void>('/pppoe/disconnect');

// ---------------------------------------------------------------------------
// Router Advertisement (RA)
// ---------------------------------------------------------------------------

export const raStatus = () => get<RaStatusResponse>('/ra/status');
export const raConfig = () => get<RaServerConfig>('/ra/config');
export const raUpdateConfig = (cfg: RaServerConfig) => post<void>('/ra/config', cfg);
export const raTrigger = () => post<void>('/ra/trigger');

// ---------------------------------------------------------------------------
// Setup & Onboarding
// ---------------------------------------------------------------------------


export const getSetupStatus = () => get<SetupStatusResponse>('/system/setup-status');
export const submitSetup = (payload: SetupPayload) => post<SetupResponse>('/system/setup', payload);

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
	const url = new URL('/api/v1/dns/logs', window.location.origin);
	url.searchParams.set('follow', 'true');
	if (params?.client) url.searchParams.set('client', params.client);
	if (params?.limit) url.searchParams.set('limit', String(params.limit));
	return url.toString();
}
