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
	DevicesMeta,
	DevicesResponse,
	DhcpLease,
	DhcpOptionsConfig,
	DhcpPoolEntry,
	DhcpPoolsConfigResponse,
	DhcpPoolsResponse,
	DhcpReconcileResponse,
	Dhcpv4PoolConfig,
	Dhcpv6PoolConfig,
	AdblockCheckResponse,
	DnsAdblockSourcesResponse,
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
	ServiceBanner,
	TransientHostEntry,
	UserInfo,
	WhoisResponse,
	PppoeConfig,
	PppoeStatusResponse,
	RaServerConfig,
	RaStatusResponse,
	DbMetrics,
	SystemConfigExport,
	SystemConfigImportResponse,
	DbEngineSwitchRequest,
	GenerateTokenRequest,
	FirewallConfig,
	FirewallStatus,
	FirewallValidationReport,
	FirewallCommitRequest,
	FirewallCommitResponse,
	TrafficConfig,
	TrafficStatusResponse,
	TrafficTelemetryResponse,
	SseEvent,
	TimeOfDay
} from './types';
import { parseTimedEvent } from './types';


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

let memoryToken: string | null = null;
let memoryTokenLoaded = false;

export function getToken(): string | null {
	if (!memoryTokenLoaded) {
		memoryTokenLoaded = true;
		if (typeof localStorage !== 'undefined') {
			memoryToken = localStorage.getItem('lf_session');
		}
	}
	return memoryToken;
}

export function setClientToken(token: string | null) {
	memoryToken = token;
	memoryTokenLoaded = true;
	if (typeof localStorage !== 'undefined') {
		if (token) {
			localStorage.setItem('lf_session', token);
		} else {
			localStorage.removeItem('lf_session');
		}
	}
}

function handleUnauthorized(path: string) {
	if (path !== '/auth/login' && path !== '/auth/status') {
		setClientToken(null);
		if (
			typeof window !== 'undefined' &&
			window.location.pathname !== '/login' &&
			window.location.pathname !== '/setup'
		) {
			window.location.href = '/login';
		}
	}
}

function buildPath(
	path: string,
	params?: Record<string, string | number | boolean | undefined>
): string {
	if (!params) return path;
	const url = new URL(path, 'http://x');
	for (const [k, v] of Object.entries(params)) {
		if (v !== undefined) url.searchParams.set(k, String(v));
	}
	return url.pathname + url.search;
}

function extractList<T>(res: any, key?: string): T[] {
	if (!res) return [];
	if (Array.isArray(res)) return res;
	if (key && Array.isArray(res[key])) return res[key];
	if (Array.isArray(res.data)) return res.data;
	if (key && Array.isArray(res.data?.[key])) return res.data[key];
	return [];
}

function extractPaginated<T>(res: any, key: string): { entries: T[]; total: number } {
	if (!res) return { entries: [], total: 0 };
	const list: T[] = Array.isArray(res)
		? res
		: Array.isArray(res.data)
			? res.data
			: Array.isArray(res[key])
				? res[key]
				: [];
	const total =
		typeof res.meta?.total === 'number'
			? res.meta.total
			: typeof res.total === 'number'
				? res.total
				: list.length;
	return { entries: list, total };
}

async function requestCore<T>(
	method: string,
	path: string,
	body?: unknown,
	extraHeaders?: Record<string, string>,
	raw: boolean = false
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

	const text = await res.text();
	let json: any = null;
	if (text) {
		try {
			json = JSON.parse(text);
		} catch {
			// not valid json
		}
	}

	if (!res.ok) {
		if (res.status === 401) handleUnauthorized(path);
		const errorMsg =
			json?.error ?? (typeof json === 'string' ? json : null) ?? text ?? `HTTP ${res.status}`;
		throw new ApiError(res.status, errorMsg);
	}

	if (raw) {
		return (json !== null ? json : text) as T;
	}

	if (!json && text) {
		return text as unknown as T;
	}

	// Unwrap { "data": ... } envelope
	return (json && 'data' in json ? json.data : json) as T;
}

const request = <T>(
	method: string,
	path: string,
	body?: unknown,
	extraHeaders?: Record<string, string>
) => requestCore<T>(method, path, body, extraHeaders, false);

const requestRaw = <T>(
	method: string,
	path: string,
	body?: unknown,
	extraHeaders?: Record<string, string>
) => requestCore<T>(method, path, body, extraHeaders, true);

async function requestText(
	path: string,
	params?: Record<string, string | number | boolean | undefined>
): Promise<string> {
	const token = getToken();
	const headers: Record<string, string> = {};
	if (token) headers['Authorization'] = `Bearer ${token}`;

	const fullPath = buildPath(path, params);
	const res = await fetch(`/api/v1${fullPath}`, {
		method: 'GET',
		headers
	});

	if (!res.ok) {
		if (res.status === 401) handleUnauthorized(path);
		const text = await res.text();
		throw new ApiError(res.status, text || `HTTP ${res.status}`);
	}

	return res.text();
}

const get = <T>(path: string, params?: Record<string, string | number | boolean | undefined>) =>
	request<T>('GET', buildPath(path, params));

const getRaw = <T>(path: string, params?: Record<string, string | number | boolean | undefined>) =>
	requestRaw<T>('GET', buildPath(path, params));

const getText = (path: string, params?: Record<string, string | number | boolean | undefined>) =>
	requestText(path, params);

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
export const me = async (): Promise<UserInfo> => {
	const res = await get<any>('/auth/me');
	if (res?.data) return res.data as UserInfo;
	return res as UserInfo;
};
export const changePassword = (current_password: string, new_password: string) =>
	post<void>('/auth/change-password', { current_password, new_password });
export const listTokens = async (): Promise<AuthToken[]> =>
	extractList<AuthToken>(await get<any>('/auth/tokens'), 'tokens');

export const generateToken = async (req: GenerateTokenRequest): Promise<AuthToken> => {
	const res = await post<any>('/auth/tokens', req);
	return (res?.data ?? res) as AuthToken;
};

export const deleteToken = (idOrName: string | number) =>
	del<void>(`/auth/tokens/${encodeURIComponent(String(idOrName))}`);

export const renewToken = async (idOrName: string | number): Promise<AuthToken> => {
	const res = await post<any>(`/auth/tokens/${encodeURIComponent(String(idOrName))}/renew`, {});
	return (res?.data ?? res) as AuthToken;
};

export const validateToken = (token: string) =>
	post<{ valid: boolean }>('/auth/validate', { token });

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

export const status = () => get<StatusResponse>('/status');
export const scan = async (): Promise<void> => {
	try {
		await post<void>('/scan');
	} catch (e: any) {
		// When daemon does not expose /scan (discovery is autonomous via Netlink),
		// silently swallow 404 so caller refresh workflows succeed smoothly.
		if (e?.status !== 404) throw e;
	}
};
export const reload = () => post<void>('/reload');
export const shutdown = () => post<void>('/shutdown');

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export const listDevices = async (params?: {
	filter?: string;
	sort?: string;
	limit?: number;
	offset?: number;
	grouped?: boolean;
}): Promise<DevicesResponse> => {
	const raw = await getRaw<any>('/devices', params);
	if (!raw) {
		return { devices: [], meta: { total: 0, online: 0, last_scan_secs_ago: 0 } };
	}
	const devList = extractList<DeviceEntry>(raw, 'devices');
	const onlineCount = devList.filter((d) => d.online).length;
	const meta: DevicesMeta = {
		total: typeof raw.meta?.total === 'number' ? raw.meta.total : devList.length,
		online: typeof raw.meta?.online === 'number' ? raw.meta.online : onlineCount,
		last_scan_secs_ago:
			typeof raw.meta?.last_scan_secs_ago === 'number' ? raw.meta.last_scan_secs_ago : 0,
	};
	return { devices: devList, meta };
};

export const whois = async (target: string): Promise<WhoisResponse> => {
	const res = await get<any>(`/devices/${encodeURIComponent(target)}`);
	if (res && typeof res === 'object') {
		const entry = (res.entry ?? res.data?.entry ?? res) as DeviceEntry;
		return { entry };
	}
	throw new ApiError(404, `Device not found: ${target}`);
};

export const purge = (target: string) => del<void>(`/devices/${encodeURIComponent(target)}`);
export const wol = (target: string) =>
	post<void>(`/devices/${encodeURIComponent(target)}/wol`);
export const transientHostList = async (): Promise<TransientHostEntry[]> =>
	extractList<TransientHostEntry>(await get<any>('/devices/transient'), 'hosts');

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

export const hostList = async (): Promise<HostConfigEntry[]> =>
	extractList<HostConfigEntry>(await get<any>('/hosts'), 'hosts');

export const hostAdd = (entry: HostConfigEntry) => post<void>('/hosts', entry);
export const hostSet = (mac: string, field: string, value: string) =>
	patch<void>(`/hosts/${mac}`, { field, value });
export const hostRemove = (mac: string) => del<void>(`/hosts/${mac}`);

export const hostExport = async (): Promise<HostConfigEntry[]> =>
	extractList<HostConfigEntry>(await get<any>('/hosts/export'), 'hosts');

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
	get<unknown>('/dns/query', { name, ...(type && { record_type: type }) });
export const dnsQueryLog = async (params?: {
	client?: string;
	domain?: string;
	qtype?: string;
	result?: string;
	limit?: number;
	offset?: number;
}): Promise<{ entries: DnsQueryLogEntry[]; total: number }> =>
	extractPaginated<DnsQueryLogEntry>(await getRaw<any>('/dns/logs', params), 'entries');

export function formatDnsAddr(addr: string): string {
	const trimmed = addr.trim();
	if (!trimmed) return trimmed;
	// Already formatted with port?
	if (trimmed.startsWith('[') && trimmed.includes(']:')) return trimmed;
	if (trimmed.includes(':') && !trimmed.includes('::') && trimmed.split(':').length === 2 && trimmed.includes('.')) {
		return trimmed;
	}
	// IPv6 address without port
	if (trimmed.includes(':')) {
		const cleanIp = trimmed.replace(/^\[/, '').replace(/\]$/, '');
		return `[${cleanIp}]:53`;
	}
	// IPv4 address without port
	if (trimmed.includes('.')) {
		return `${trimmed}:53`;
	}
	return trimmed;
}

export const dnsUpstreams = async (): Promise<DnsUpstreamEntry[]> =>
	extractList<DnsUpstreamEntry>(await get<any>('/dns/upstreams'), 'upstreams');
export const dnsUpstreamAdd = (entry: { addr: string; protocol: string; domain?: string }) => {
	const formattedAddr = formatDnsAddr(entry.addr);
	const proto = (entry.protocol || 'udp').toLowerCase();
	const params = new URLSearchParams({ addr: formattedAddr, protocol: proto });
	if (entry.domain) params.set('domain', entry.domain);
	return post<void>(`/dns/upstreams?${params.toString()}`, {
		addr: formattedAddr,
		protocol: proto,
		domain: entry.domain
	});
};
export const dnsUpstreamRemove = (entry: { addr: string; protocol: string; domain?: string }) => {
	const formattedAddr = formatDnsAddr(entry.addr);
	const proto = (entry.protocol || 'udp').toLowerCase();
	const params = new URLSearchParams({ addr: formattedAddr, protocol: proto });
	if (entry.domain) params.set('domain', entry.domain);
	return del<void>(`/dns/upstreams?${params.toString()}`, {
		addr: formattedAddr,
		protocol: proto,
		domain: entry.domain
	});
};
export const dnsUpstreamClear = () => del<void>('/dns/upstreams/clear');
export const dnsUpstreamModeGet = () => get<{ mode: string }>('/dns/upstreams/mode');
export const dnsUpstreamModeSet = (mode: string) => put<{ mode: string }>('/dns/upstreams/mode', { mode });

export const dnsReverseResolverList = async (): Promise<ReverseResolverEntry[]> =>
	extractList<ReverseResolverEntry>(await get<any>('/dns/reverse-resolvers'), 'resolvers');
export const dnsReverseResolverAdd = (subnet: string, resolver_uri: string) => {
	const s = subnet.trim();
	const r = resolver_uri.trim();
	const params = new URLSearchParams({ subnet: s, resolver_uri: r });
	return post<void>(`/dns/reverse-resolvers?${params.toString()}`, { subnet: s, resolver_uri: r });
};
export const dnsReverseResolverRemove = (subnet: string) => {
	const s = subnet.trim();
	const params = new URLSearchParams({ subnet: s });
	return del<void>(`/dns/reverse-resolvers?${params.toString()}`, { subnet: s });
};

// ---------------------------------------------------------------------------
// DNS — cache
// ---------------------------------------------------------------------------

export const dnsCacheDump = async (params?: {
	limit?: number;
	offset?: number;
	q?: string;
	kind?: string;
}): Promise<{ entries: DnsCacheEntry[]; total: number }> =>
	extractPaginated<DnsCacheEntry>(await getRaw<any>('/dns/cache', params), 'entries');
export const dnsCacheFlush = () => del<void>('/dns/cache');
export const dnsCacheStatsExt = () => get<DnsCacheStatsResponse>('/dns/cache/stats');

// ---------------------------------------------------------------------------
// DNS — adblock
// ---------------------------------------------------------------------------

export const dnsAdblockStatus = () => get<DnsAdblockStatusResponse>('/dns/adblock');
export const dnsAdblockSet = (enabled: boolean, duration_secs?: number) =>
	put<void>('/dns/adblock', { enabled, duration_secs: duration_secs ?? null });
export const dnsAdblockReload = () => post<void>('/dns/adblock/reload');
export const dnsAdblockAllowlist = async (): Promise<AllowlistEntry[]> =>
	extractList<AllowlistEntry>(await get<any>('/dns/adblock/allowlist'), 'allowlist');
export const dnsBlock = (domain: string) => post<void>('/dns/adblock/block', { domain });
export const dnsAllow = (domain: string) => post<void>('/dns/adblock/allow', { domain });
export const dnsUnallow = (target: string) =>
	del<void>(`/dns/adblock/allow/${encodeURIComponent(target)}`);
export const dnsAdblockUrls = async (): Promise<DnsAdblockUrlEntry[]> =>
	extractList<DnsAdblockUrlEntry>(await get<any>('/dns/adblock/urls'), 'urls');
export const dnsAdblockSources = () => get<DnsAdblockSourcesResponse>('/dns/adblock/sources');
export const dnsAdblockCheck = (domain: string) =>
	get<AdblockCheckResponse>(`/dns/adblock/check?domain=${encodeURIComponent(domain)}`);
export const dnsAdblockUrlAdd = (entry: DnsAdblockUrlEntry) =>
	post<void>('/dns/adblock/sources', entry);
export const dnsAdblockUrlRemove = (entry: DnsAdblockUrlEntry) =>
	del<void>('/dns/adblock/sources', entry);
export const dnsAdblockConfigSet = (config: {
	blocking_mode?: BlockingMode;
	blocking_ip_v4?: string | null;
	blocking_ip_v6?: string | null;
	refresh_time?: TimeOfDay;
}) => post<void>('/dns/adblock/config', config);
export const dnsAdblockRules = async (): Promise<AdblockRuleEntry[]> =>
	extractList<AdblockRuleEntry>(await get<any>('/dns/adblock/rules'), 'rules');
export const dnsAdblockRuleAdd = (domain: string, action: 'block' | 'allow') =>
	post<void>('/dns/adblock/rules', { domain, action });
export const dnsAdblockRuleRemove = (id: number) =>
	del<void>(`/dns/adblock/rules/${id}`);
export const dnsAdblockRuleStatus = (id: number, enabled: boolean) =>
	put<void>(`/dns/adblock/rules/${id}/status`, { enabled });

// ---------------------------------------------------------------------------
// DNS — rewrites
// ---------------------------------------------------------------------------

export const dnsRewriteList = async (): Promise<RewriteRule[]> =>
	extractList<RewriteRule>(await get<any>('/dns/rewrites'), 'rewrites');
export const dnsRewriteAdd = (rule: Omit<RewriteRule, 'id'>) => post<void>('/dns/rewrites', rule);
export const dnsRewriteRemove = (id: number) => del<void>(`/dns/rewrites/${id}`);
export const dnsRewriteClear = () => del<void>('/dns/rewrites');
export const dnsRewriteExport = async (): Promise<RewriteRule[]> =>
	extractList<RewriteRule>(await get<any>('/dns/rewrites/export'), 'rewrites');
export const dnsRewriteImport = (rules: RewriteRule[]) => post<void>('/dns/rewrites/import', rules);

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

export const leases = async (): Promise<DhcpLease[]> =>
	extractList<DhcpLease>(await get<any>('/dhcp/leases'), 'leases');

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

export const userList = async (): Promise<UserInfo[]> =>
	extractList<UserInfo>(await get<any>('/users'), 'users');

export const userCreate = async (username: string, password: string, role?: string): Promise<UserInfo> => {
	const res = await post<any>('/users', { username, password, role });
	if (res?.data?.user) return res.data.user;
	if (res?.user) return res.user;
	return res as UserInfo;
};
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
// Firewall (nftables)
// ---------------------------------------------------------------------------

export const firewallStatus = () => get<FirewallStatus>('/firewall/status');
export const firewallConfig = () => get<FirewallConfig>('/firewall/config');
export const firewallPropose = (config: FirewallConfig) =>
	post<FirewallValidationReport>('/firewall/propose', config);
export const firewallCommit = (req: FirewallCommitRequest) =>
	post<FirewallCommitResponse>('/firewall/commit', req);
export const firewallConfirm = (tx_id: string) =>
	post<void>('/firewall/confirm', { tx_id });
export const firewallAbort = (tx_id: string) =>
	post<void>('/firewall/abort', { tx_id });

export const trafficStatus = () => get<TrafficStatusResponse>('/traffic/status');
export const trafficTelemetry = () => get<TrafficTelemetryResponse>('/traffic/telemetry');
export const trafficConfig = () => get<TrafficConfig>('/traffic/config');
export const trafficUpdateConfig = (config: TrafficConfig) =>
	post<void>('/traffic/config', config);


// ---------------------------------------------------------------------------
// Setup & Onboarding
// ---------------------------------------------------------------------------


export const getSetupStatus = () => get<SetupStatusResponse>('/system/setup-status');
export const submitSetup = (payload: SetupPayload) => post<SetupResponse>('/system/setup', payload);

// ---------------------------------------------------------------------------
// Service Control
// ---------------------------------------------------------------------------

export const serviceBanners = async (): Promise<ServiceBanner[]> => {
	const res = await get<{ banners: ServiceBanner[] }>('/service_banners');
	return res?.banners ?? [];
};

export const controlService = (
	id: string,
	action: 'start' | 'stop' | 'restart' | 'Start' | 'Stop' | 'Restart'
) => post<void>(`/service/${encodeURIComponent(id)}/control`, { action: action.toLowerCase() });

/**
 * Fetch historical system events via REST.
 */
export const eventsHistory = async (params?: {
	filter?: string;
	limit?: number;
	offset?: number;
}): Promise<{ entries: SseEvent[]; total: number }> => {
	const raw = await getRaw<any>('/events/history', params);
	const paginated = extractPaginated<unknown>(raw, 'events');
	return {
		entries: paginated.entries.map((item) => parseTimedEvent(item)),
		total: paginated.total
	};
};

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
	const token = getToken();
	if (token) url.searchParams.set('token', token);
	return url.toString();
}

/**
 * Build the URL for the DNS log SSE stream.
 */
export function dnsLogSseUrl(params?: {
	client?: string;
	domain?: string;
	qtype?: string;
	result?: string;
	limit?: number;
}): string {
	const url = new URL('/api/v1/dns/logs', window.location.origin);
	url.searchParams.set('follow', 'true');
	if (params?.client) url.searchParams.set('client', params.client);
	if (params?.domain) url.searchParams.set('domain', params.domain);
	if (params?.qtype) url.searchParams.set('qtype', params.qtype);
	if (params?.result) url.searchParams.set('result', params.result);
	if (params?.limit) url.searchParams.set('limit', String(params.limit));
	const token = getToken();
	if (token) url.searchParams.set('token', token);
	return url.toString();
}
