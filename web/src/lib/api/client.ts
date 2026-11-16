/**
 * Lanforge API client — thin typed fetch wrapper.
 * Method names mirror API.md 1:1 for easy cross-reference.
 * All calls are proxied through Vite's `/api` proxy in dev,
 * or hit the same origin in production (served by axum).
 */

import type {
	AdblockRuleEntry,
	ServiceStopImpact,
	LogLevelStatus,
	SetLogLevelRequest,
	AdblockRulesImport,
	AuthStatusResponse,
	AuthToken,
	BlockingMode,
	DeviceDnsResponse,
	DnsDomainResponse,
	DeviceRulesResponse,
	DeviceEntry,
	DevicesMeta,
	DevicesResponse,
	DhcpLease,
	DhcpOptionsConfig,
	DhcpOptionsResponse,
	DhcpPoolsConfigResponse,
	DhcpPoolsResponse,
	DhcpReconcileResponse,
	Dhcpv4PoolConfig,
	Dhcpv6PoolConfig,
	AdblockCheckResponse,
	DnsAdblockGroupsResponse,
	DnsAdblockSourcesResponse,
	DnsAdblockStatusResponse,
	DnsAdblockUrlEntry,
	DnsAnalyticsResponse,
	DnsCacheEntry,
	DnsCacheStatsResponse,
	DnsQueryLogEntry,
	DnsStatsResponse,
	DnsUpstreamEntry,
	HostConfigEntry,
	LeaseTarget,
	LoginRequest,
	LoginResponse,
	ReverseResolverEntry,
	RewriteRule,
	DnsRecordType,
	SetupPayload,
	SetupResponse,
	SetupStatusResponse,
	StatusResponse,
	ServiceBanner,
	UserInfo,
	WhoisResponse,
	PppoeConfig,
	PppoeStatusResponse,
	RaServerConfig,
	RaStatusResponse,
	DbMetrics,
	SystemConfigExport,
	SystemConfigImportResponse,
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

/** localStorage key of the session token; the client owns it, the auth store mirrors it. */
export const TOKEN_KEY = 'lf_session';

let memoryToken: string | null = null;
let memoryTokenLoaded = false;
const tokenListeners = new Set<(token: string | null) => void>();

export function getToken(): string | null {
	if (!memoryTokenLoaded) {
		memoryTokenLoaded = true;
		if (typeof localStorage !== 'undefined') {
			memoryToken = localStorage.getItem(TOKEN_KEY);
		}
	}
	return memoryToken;
}

/** Calls `listener` whenever the token changes (set, cleared by a 401, ...); returns the unsubscribe. */
export function onTokenChange(listener: (token: string | null) => void): () => void {
	tokenListeners.add(listener);
	return () => tokenListeners.delete(listener);
}

export function setClientToken(token: string | null) {
	memoryToken = token;
	memoryTokenLoaded = true;
	if (typeof localStorage !== 'undefined') {
		if (token) {
			localStorage.setItem(TOKEN_KEY, token);
		} else {
			localStorage.removeItem(TOKEN_KEY);
		}
	}
	for (const listener of tokenListeners) listener(token);
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

/** The `{ data, meta }` body of a paginated endpoint (fetched with `getRaw`). */
interface Paginated<T> {
	data: T[];
	meta?: { total?: number };
}

function paginated<T>(res: Paginated<T>): { entries: T[]; total: number } {
	return { entries: res.data, total: res.meta?.total ?? res.data.length };
}

// ---------------------------------------------------------------------------
// Re-authentication: sensitive actions (users, token creation, database reset)
// answer 403 "Re-authentication required" until the session proves its password.
// The server then issues a short-lived elevation token sent in a header.
// ---------------------------------------------------------------------------

const REAUTH_REQUIRED = 'Re-authentication required';

/** Asks the user for their password; resolves `null` when cancelled. */
export type ReauthPrompt = (error?: string) => Promise<string | null>;

let reauthPrompt: ReauthPrompt | null = null;
let elevation: { token: string; expiresAt: number } | null = null;

export function setReauthPrompt(prompt: ReauthPrompt | null) {
	reauthPrompt = prompt;
}

function currentElevation(): string | null {
	if (elevation && Date.now() < elevation.expiresAt) return elevation.token;
	elevation = null;
	return null;
}

/** Prompts until the password is accepted; false when the user cancels. */
async function reauthenticate(): Promise<boolean> {
	if (!reauthPrompt) return false;
	let error: string | undefined;
	for (;;) {
		const password = await reauthPrompt(error);
		if (password === null) return false;
		try {
			const res = await requestCore<{ elevation_token: string; expires_in: number }>(
				'POST',
				'/auth/elevate',
				{ password },
				undefined,
				false,
				true
			);
			// Renew a little before the server-side expiry.
			elevation = {
				token: res.elevation_token,
				expiresAt: Date.now() + Math.max(res.expires_in - 15, 0) * 1000
			};
			return true;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Re-authentication failed';
		}
	}
}

/** Adds the session bearer token and, when active, the elevation header. */
function authHeaders(base: Record<string, string> = {}): Record<string, string> {
	const token = getToken();
	if (token) base['Authorization'] = `Bearer ${token}`;
	const elevated = currentElevation();
	if (elevated) base['X-Lanforge-Elevation'] = elevated;
	return base;
}

async function requestCore<T>(
	method: string,
	path: string,
	body?: unknown,
	extraHeaders?: Record<string, string>,
	raw: boolean = false,
	noReauth: boolean = false
): Promise<T> {
	const headers = authHeaders({
		'Content-Type': 'application/json',
		...extraHeaders
	});

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
		if (res.status === 403 && errorMsg === REAUTH_REQUIRED && !noReauth) {
			elevation = null;
			if (await reauthenticate()) {
				return requestCore<T>(method, path, body, extraHeaders, raw, true);
			}
		}
		throw new ApiError(res.status, errorMsg);
	}

	if (raw) {
		return (json !== null ? json : text) as T;
	}

	if (!json && text) {
		return text as unknown as T;
	}

	// Unwrap { "data": ... } envelope
	return (json && typeof json === 'object' && 'data' in json ? json.data : json) as T;
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

// `/system/config` needs the config_write permission but no elevation (authz.rs `requirement`),
// so this skips the re-authentication retry of `requestCore`.
async function requestText(
	path: string,
	params?: Record<string, string | number | boolean | undefined>
): Promise<string> {
	const res = await fetch(`/api/v1${buildPath(path, params)}`, {
		method: 'GET',
		headers: authHeaders()
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
export const me = () => get<UserInfo>('/auth/me');
/** Changing the password ends every session of the user; keep this one on the new token. */
export const changePassword = async (current_password: string, new_password: string) => {
	const res = await post<{ message: string; token?: string }>('/auth/change-password', {
		current_password,
		new_password
	});
	if (res?.token) setClientToken(res.token);
};
export const listTokens = async (): Promise<AuthToken[]> =>
	(await get<{ tokens: AuthToken[] }>('/auth/tokens')).tokens;

export const generateToken = (req: GenerateTokenRequest) => post<AuthToken>('/auth/tokens', req);

export const deleteToken = (idOrName: string | number) =>
	del<void>(`/auth/tokens/${encodeURIComponent(String(idOrName))}`);

export const renewToken = (idOrName: string | number) =>
	post<AuthToken>(`/auth/tokens/${encodeURIComponent(String(idOrName))}/renew`, {});

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
	const raw = await getRaw<{ data: DeviceEntry[]; meta: DevicesMeta }>('/devices', params);
	return { devices: raw.data, meta: raw.meta };
};

export const whois = async (target: string): Promise<WhoisResponse> => {
	const res = await get<WhoisResponse>(`/devices/${encodeURIComponent(target)}`);
	if (!res?.entry) throw new ApiError(404, `Device not found: ${target}`);
	return res;
};

/** The device's DNS activity over the last day. */
export const deviceDns = (mac: string) =>
	get<DeviceDnsResponse>(`/devices/${encodeURIComponent(mac)}/dns`);
/** One domain's activity over the last day: hourly rate and who asked. */
export const dnsDomain = (domain: string) =>
	get<DnsDomainResponse>(`/dns/domains/${encodeURIComponent(domain)}`);
/** The forwards, rewrites and name bindings the daemon resolves to the device. */
export const deviceRules = (mac: string) =>
	get<DeviceRulesResponse>(`/devices/${encodeURIComponent(mac)}/rules`);
export const purge = (target: string) => del<void>(`/devices/${encodeURIComponent(target)}`);
export const wol = (target: string) => post<void>(`/devices/${encodeURIComponent(target)}/wol`);

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

export const hostList = async (): Promise<HostConfigEntry[]> =>
	(await get<{ hosts: HostConfigEntry[] }>('/hosts')).hosts;

export const hostAdd = (entry: HostConfigEntry) => post<void>('/hosts', entry);
export const hostSet = (mac: string, field: string, value: string) =>
	patch<void>(`/hosts/${mac}`, { field, value });
export const hostRemove = (mac: string) => del<void>(`/hosts/${mac}`);

export const hostExport = async (): Promise<HostConfigEntry[]> =>
	(await get<{ hosts: HostConfigEntry[] }>('/hosts/export')).hosts;

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
	paginated(await getRaw<Paginated<DnsQueryLogEntry>>('/dns/logs', params));

function formatDnsAddr(addr: string): string {
	const trimmed = addr.trim();
	if (!trimmed) return trimmed;
	// Already formatted with port?
	if (trimmed.startsWith('[') && trimmed.includes(']:')) return trimmed;
	if (
		trimmed.includes(':') &&
		!trimmed.includes('::') &&
		trimmed.split(':').length === 2 &&
		trimmed.includes('.')
	) {
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
	(await get<{ upstreams: DnsUpstreamEntry[] }>('/dns/upstreams')).upstreams;
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
/** Replaces the default (non domain-scoped) upstreams with plain-DNS servers in one change. */
export const dnsUpstreamSetDefault = (addrs: string[]) =>
	put<void>('/dns/upstreams', { upstreams: addrs.map(formatDnsAddr) });
export const dnsUpstreamModeGet = () => get<{ mode: string }>('/dns/upstreams/mode');
export const dnsUpstreamModeSet = (mode: string) =>
	put<{ mode: string }>('/dns/upstreams/mode', { mode });
export const dnsUpstreamTest = (entry: { addr: string; protocol?: string; domain?: string }) => {
	const formattedAddr = formatDnsAddr(entry.addr);
	const proto = (entry.protocol || 'udp').toLowerCase();
	const params = new URLSearchParams({ addr: formattedAddr, protocol: proto });
	if (entry.domain) params.set('domain', entry.domain);
	return get<{ ok: boolean; latency_ms: number; error?: string }>(
		`/dns/upstreams/test?${params.toString()}`
	);
};

export const dnsReverseResolverList = async (): Promise<ReverseResolverEntry[]> =>
	(await get<{ resolvers: ReverseResolverEntry[] }>('/dns/reverse-resolvers')).resolvers;
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
	paginated(await getRaw<Paginated<DnsCacheEntry>>('/dns/cache', params));
export const dnsCacheFlush = () => del<void>('/dns/cache');
export const dnsCacheStatsExt = () => get<DnsCacheStatsResponse>('/dns/cache/stats');

// ---------------------------------------------------------------------------
// DNS — adblock
// ---------------------------------------------------------------------------

export const dnsAdblockStatus = () => get<DnsAdblockStatusResponse>('/dns/adblock');
export const dnsAdblockSet = (enabled: boolean, duration_secs?: number) =>
	put<void>('/dns/adblock', { enabled, duration_secs: duration_secs ?? null });
export const dnsAdblockReload = () => post<void>('/dns/adblock/reload');
export const dnsBlock = (domain: string) => dnsAdblockRuleAdd(domain, 'block');
export const dnsAllow = (domain: string) => dnsAdblockRuleAdd(domain, 'allow');
export const dnsAdblockUrls = async (): Promise<DnsAdblockUrlEntry[]> =>
	(await get<{ urls: DnsAdblockUrlEntry[] }>('/dns/adblock/urls')).urls;
export const dnsAdblockSources = () => get<DnsAdblockSourcesResponse>('/dns/adblock/sources');
export const dnsAdblockCheck = (domain: string, client?: string) =>
	get<AdblockCheckResponse>(
		`/dns/adblock/check?domain=${encodeURIComponent(domain)}` +
			(client ? `&client=${encodeURIComponent(client)}` : '')
	);
/** `?group=<name>` for a group's rules or lists; nothing for the global layer. */
const groupQuery = (group?: string | null) => (group ? `?group=${encodeURIComponent(group)}` : '');

/** Adds a list to the global layer, or to `group`. */
export const dnsAdblockUrlAdd = (entry: DnsAdblockUrlEntry, group?: string | null) =>
	post<void>(`/dns/adblock/sources${groupQuery(group)}`, entry);
export const dnsAdblockUrlRemove = (entry: DnsAdblockUrlEntry) =>
	del<void>('/dns/adblock/sources', entry);
export const dnsAdblockConfigSet = (config: {
	blocking_mode?: BlockingMode;
	blocking_ip_v4?: string | null;
	blocking_ip_v6?: string | null;
	refresh_time?: TimeOfDay;
}) => post<void>('/dns/adblock/config', config);
// The rules calls act on the global rules file, or on `group`'s.
export const dnsAdblockRules = async (group?: string | null): Promise<AdblockRuleEntry[]> =>
	(await get<{ rules: AdblockRuleEntry[] }>(`/dns/adblock/rules${groupQuery(group)}`)).rules;
export const dnsAdblockRuleAdd = (
	domain: string,
	action: 'block' | 'allow',
	group?: string | null
) => post<void>(`/dns/adblock/rules${groupQuery(group)}`, { domain, action });
// Rules and rewrites are addressed by content: their ids are 63-bit hashes that JSON.parse rounds.
export const dnsAdblockRuleRemove = (rule: string, group?: string | null) =>
	del<void>(`/dns/adblock/rules${groupQuery(group)}`, { rule });
export const dnsAdblockRuleStatus = (rule: string, enabled: boolean, group?: string | null) =>
	put<void>(`/dns/adblock/rules/status${groupQuery(group)}`, { rule, enabled });
/** A pasted list in one call: one rules-file write, one engine reload. */
export const dnsAdblockRulesImport = (
	text: string,
	action: 'block' | 'allow',
	group?: string | null
) => post<AdblockRulesImport>(`/dns/adblock/rules/import${groupQuery(group)}`, { text, action });

// Adblock groups (overrides of the global layer for some clients) and bypass.
export const dnsAdblockGroups = () => get<DnsAdblockGroupsResponse>('/dns/adblock/groups');
export const dnsAdblockGroupCreate = (name: string, lists: string[], clients: string[]) =>
	post<void>('/dns/adblock/groups', { name, lists, clients });
export const dnsAdblockGroupUpdate = (name: string, lists: string[], clients: string[]) =>
	put<void>(`/dns/adblock/groups/${encodeURIComponent(name)}`, { lists, clients });
export const dnsAdblockGroupDelete = (name: string) =>
	del<void>(`/dns/adblock/groups/${encodeURIComponent(name)}`);
export const dnsAdblockBypassSet = (clients: string[]) =>
	put<void>('/dns/adblock/bypass', { clients });
/** Replaces the addresses linked to one device (its tailnet / VPN addresses). */
export const deviceLinkedSet = (mac: string, addresses: string[]) =>
	put<void>(`/devices/${encodeURIComponent(mac)}/linked`, { addresses });
/** Puts one device in exactly `groups`, and bypassed or not. */
export const dnsAdblockDeviceSet = (mac: string, groups: string[], bypass: boolean) =>
	put<void>(`/dns/adblock/devices/${encodeURIComponent(mac)}`, { groups, bypass });

// ---------------------------------------------------------------------------
// DNS — rewrites
// ---------------------------------------------------------------------------

export const dnsRewriteList = async (): Promise<RewriteRule[]> =>
	(await get<{ rewrites: RewriteRule[] }>('/dns/rewrites')).rewrites;
export const dnsRewriteAdd = (rule: { domain: string; rtype: DnsRecordType; answer: string }) =>
	post<void>('/dns/rewrites', rule);
export const dnsRewriteRemove = (rule: RewriteRule) =>
	del<void>('/dns/rewrites/rule', { domain: rule.domain, rtype: rule.rtype, answer: rule.answer });
export const dnsRewriteClear = () => del<void>('/dns/rewrites');
export const dnsRewriteExport = async (): Promise<RewriteRule[]> =>
	(await get<{ rewrites: RewriteRule[] }>('/dns/rewrites/export')).rewrites;
export const dnsRewriteImport = (rules: RewriteRule[]) => post<void>('/dns/rewrites/import', rules);

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

export const leases = async (): Promise<DhcpLease[]> =>
	(await get<{ leases: DhcpLease[] }>('/dhcp/leases')).leases;

export const dhcpPools = () => get<DhcpPoolsResponse>('/dhcp/pools');

export const dhcpOptionsGet = async (): Promise<DhcpOptionsConfig> =>
	(await get<DhcpOptionsResponse>('/dhcp/options')).options;

export const dhcpOptionsUpdate = (options: DhcpOptionsConfig) =>
	put<void>('/dhcp/options', options);

export const dhcpPoolsConfigGet = () => get<DhcpPoolsConfigResponse>('/dhcp/pools/config');

export const dhcpPoolsConfigUpdate = (
	v4_pools: Dhcpv4PoolConfig[],
	v6_pools: Dhcpv6PoolConfig[]
) => {
	const sanitizedV4 = v4_pools.map((p) => ({
		...p,
		name: p.name?.trim() || null,
		router: p.router?.trim() || null,
		subnet_mask: p.subnet_mask?.trim() || null,
		domain_name: p.domain_name?.trim() || null,
		boot_file: p.boot_file?.trim() || null,
		tftp_server: p.tftp_server?.trim() || null,
		lease_time: p.lease_time ? Number(p.lease_time) : null
	}));
	const sanitizedV6 = v6_pools.map((p) => ({
		...p,
		name: p.name?.trim() || null,
		address: p.address?.trim() || null
	}));
	return put<void>('/dhcp/pools/config', { v4_pools: sanitizedV4, v6_pools: sanitizedV6 });
};

export const leaseRenew = (mac: string, target?: LeaseTarget) =>
	post<void>(
		`/dhcp/leases/${encodeURIComponent(mac)}/renew`,
		target !== undefined ? { target } : {}
	);

export const leaseRelease = (mac: string, target?: LeaseTarget) =>
	post<void>(
		`/dhcp/leases/${encodeURIComponent(mac)}/release`,
		target !== undefined ? { target } : {}
	);

export const dhcpReconcile = () => post<DhcpReconcileResponse>('/dhcp/reconcile', {});

// ---------------------------------------------------------------------------
// Database & Configuration
// ---------------------------------------------------------------------------

export const dbStats = () => get<DbMetrics>('/db/stats');
export const dbPrune = () => post<void>('/db/prune');
export const dbLogClean = () => post<void>('/db/log-clean');
export const dbReset = () => del<void>('/db', undefined, { 'x-confirm': 'wipe' });
export const exportSystemConfig = () => get<SystemConfigExport>('/system/config');
export const exportSystemConfigToml = () => getText('/system/config', { format: 'toml' });
export const importSystemConfig = (config: SystemConfigExport) =>
	post<SystemConfigImportResponse>('/system/config', config);

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export const userList = async (): Promise<UserInfo[]> =>
	(await get<{ users: UserInfo[] }>('/users')).users;

export const userCreate = async (
	username: string,
	password: string,
	role?: string
): Promise<UserInfo> =>
	(await post<{ user: UserInfo }>('/users', { username, password, role })).user;
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
export const firewallConfirm = (tx_id: string) => post<void>('/firewall/confirm', { tx_id });
export const firewallAbort = (tx_id: string) => post<void>('/firewall/abort', { tx_id });

export const trafficStatus = () => get<TrafficStatusResponse>('/traffic/status');
/**
 * An incremental telemetry poller: the first call returns the whole history, later calls only
 * the samples newer than the last one received (`?since=`). Everything outside `history` is
 * always complete. One feed per page; `TrafficActivityChart` merges the partial histories.
 */
export function trafficTelemetryFeed() {
	let since: number | undefined;
	let inflight: Promise<TrafficTelemetryResponse> | null = null;
	const fetchOnce = async () => {
		const t = await get<TrafficTelemetryResponse>('/traffic/telemetry', { since });
		const last = t.history?.at(-1)?.timestamp;
		if (since !== undefined && t.timestamp < since) {
			// The daemon's clock went back: its new samples are older than `since`. Reload.
			since = undefined;
		} else if (last !== undefined) {
			since = last;
		}
		return t;
	};
	// Overlapping callers share one request so the cursor never moves twice for the same samples.
	return () => (inflight ??= fetchOnce().finally(() => (inflight = null)));
}
export const trafficConfig = () => get<TrafficConfig>('/traffic/config');
export const trafficUpdateConfig = (config: TrafficConfig) => post<void>('/traffic/config', config);

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

/** The daemon's log filter and where it comes from. */
export const logLevel = () => get<LogLevelStatus>('/system/log-level');

/** Saves the filter (`duration_secs: null`), sets it for a while, or resets it (`filter: null`). */
export const setLogLevel = (req: SetLogLevelRequest) =>
	put<LogLevelStatus>('/system/log-level', req);

/** What stopping `id` does to the running services that require it (dry-run, D-20). */
export const serviceStopImpact = (id: string) =>
	get<ServiceStopImpact>(`/service/${encodeURIComponent(id)}/stop-impact`);

/**
 * Fetch historical system events via REST.
 */
export const eventsHistory = async (params?: {
	filter?: string;
	limit?: number;
	offset?: number;
}): Promise<{ entries: SseEvent[]; total: number }> => {
	const page = paginated(await getRaw<Paginated<unknown>>('/events/history', params));
	return { entries: page.entries.map((item) => parseTimedEvent(item)), total: page.total };
};

// ---------------------------------------------------------------------------
// SSE helpers
// ---------------------------------------------------------------------------

/**
 * Build the URL for the global event SSE stream.
 * Open it with `openEventStream`; the session token is never put in the URL.
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
	return url.toString();
}

export interface EventStream {
	close(): void;
}

export interface EventStreamHandlers {
	onopen?(): void;
	onmessage(ev: { data: string; lastEventId: string }): void;
	onerror?(): void;
}

/**
 * Fetch-based EventSource replacement that authenticates with the bearer header.
 * Reconnects after the stream ends or fails (honours `retry:`, backs off on HTTP errors);
 * a 401 logs out and stops. `close()` is safe at any time.
 */
export function openEventStream(url: string, handlers: EventStreamHandlers): EventStream {
	const abort = new AbortController();
	let retryMs = 3000;
	let lastEventId = '';
	let failures = 0;

	const dispatch = (data: string[], id: string) => {
		if (data.length === 0) return;
		handlers.onmessage({ data: data.join('\n'), lastEventId: id });
	};

	async function connect(): Promise<void> {
		const headers = authHeaders({ Accept: 'text/event-stream' });
		if (lastEventId) headers['Last-Event-ID'] = lastEventId;
		const res = await fetch(url, {
			headers,
			cache: 'no-store',
			signal: abort.signal
		});
		if (res.status === 401) {
			handleUnauthorized(url);
			abort.abort();
			return;
		}
		if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
		failures = 0;
		handlers.onopen?.();

		const reader = res.body.getReader();
		const decoder = new TextDecoder();
		let buf = '';
		let data: string[] = [];
		let id = lastEventId;
		let skipLf = false;
		try {
			for (;;) {
				const { done, value } = await reader.read();
				if (done) return;
				buf += decoder.decode(value, { stream: true });
				let start = 0;
				for (let i = 0; i < buf.length; i++) {
					const c = buf.charCodeAt(i);
					if (c !== 10 && c !== 13) continue;
					if (c === 10 && skipLf && i === start) {
						skipLf = false;
						start = i + 1;
						continue;
					}
					skipLf = c === 13;
					const line = buf.slice(start, i);
					start = i + 1;
					if (line === '') {
						dispatch(data, id);
						data = [];
						continue;
					}
					if (line.charCodeAt(0) === 58) continue;
					const colon = line.indexOf(':');
					const field = colon < 0 ? line : line.slice(0, colon);
					let val = colon < 0 ? '' : line.slice(colon + 1);
					if (val.charCodeAt(0) === 32) val = val.slice(1);
					if (field === 'data') data.push(val);
					else if (field === 'id' && !val.includes('\0')) {
						id = val;
						lastEventId = val;
					} else if (field === 'retry' && /^\d+$/.test(val)) retryMs = Number(val);
				}
				buf = buf.slice(start);
			}
		} finally {
			reader.cancel().catch(() => {});
		}
	}

	(async () => {
		while (!abort.signal.aborted) {
			try {
				await connect();
			} catch {
				failures++;
			}
			if (abort.signal.aborted) return;
			handlers.onerror?.();
			const delay = failures > 0 ? Math.min(retryMs * 1.5 ** (failures - 1), 15000) : retryMs;
			await new Promise<void>((resolve) => {
				const wake = () => {
					clearTimeout(timer);
					resolve();
				};
				// One listener per wait, removed when the timer fires, so reconnects do not pile them up.
				const timer = setTimeout(() => {
					abort.signal.removeEventListener('abort', wake);
					resolve();
				}, delay);
				abort.signal.addEventListener('abort', wake, { once: true });
			});
		}
	})();

	return { close: () => abort.abort() };
}
