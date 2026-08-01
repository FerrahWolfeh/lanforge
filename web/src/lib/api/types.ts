// API type definitions mirroring API_TYPES.md

// ---------------------------------------------------------------------------
// Primitives / shared
// ---------------------------------------------------------------------------

export type DnsRecordType =
	| 'A'
	| 'AAAA'
	| 'CNAME'
	| 'NS'
	| 'PTR'
	| 'MX'
	| 'TXT'
	| 'SOA'
	| 'SRV'
	| 'HTTPS'
	| 'SVCB'
	| 'ANY';

export type EventKind =
	| 'DeviceOnline'
	| 'DeviceOffline'
	| 'DeviceUpdated'
	| 'DevicePurged'
	| 'DhcpLeaseGranted'
	| 'DhcpLeaseReleased'
	| 'DnsQuery'
	| 'DnsBlocked'
	| 'DnsRewriteUpdated'
	| 'AdblockToggled'
	| 'ScanCompleted'
	| 'ConfigReloaded'
	| string; // open-ended — daemon may emit new kinds

export type LeaseTarget = 'V4' | 'V6' | 'Both';
export type UserRole = 'admin' | 'operator' | 'viewer';

export type ServiceState = 'active' | 'starting' | 'offline' | 'error' | string;

// ---------------------------------------------------------------------------
// Pagination meta
// ---------------------------------------------------------------------------

export interface PaginationMeta {
	total: number;
	limit: number;
	offset: number;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export interface LoginRequest {
	username?: string;
	password?: string;
	token?: string;
	remember_me?: boolean;
}

export interface LoginResponse {
	token: string;
}

export interface AuthStatusResponse {
	auth_required: boolean;
	authenticated: boolean;
}

export interface UserInfo {
	id: number;
	username: string;
	role: UserRole;
	created_at: number;
	updated_at: number;
	last_login: number | null;
}

export interface AuthToken {
	id: string;
	token?: string; // present only on generate
	name: string;
	created_at: number;
	last_used: number | null;
	scopes: string[];
	expires_at: number | null;
}

// ---------------------------------------------------------------------------
// System / Status
// ---------------------------------------------------------------------------

export interface NetworkStatus {
	lan_iface: string;
	lan_ipv4: string | null;
	lan_ipv6: string | null;
	gua: string | null;
	ula: string | null;
}

export interface DbStatus {
	path: string;
	size_bytes: number;
	last_flush_secs_ago: number;
}

export interface ResourceUsage {
	memory_rss_bytes?: number;
	memory_vms_bytes?: number;
	rss_bytes?: number;
	vms_bytes?: number;
}

export interface ServiceBanner {
	name: string;
	state: ServiceState;
	uptime_secs: number;
	stats: Record<string, string>;
}

export interface ServerCapabilities {
	compiled: string[];
	enabled: string[];
}

export interface StatusResponse {
	uptime_secs: number;
	version?: string;
	network: NetworkStatus;
	db: DbStatus;
	resources: ResourceUsage;
	capabilities: ServerCapabilities;
	services: Record<string, unknown>;
	service_banners?: ServiceBanner[];
}

export function normalizeServices(status?: StatusResponse | null): ServiceBanner[] {
	if (!status) return [];
	if (Array.isArray(status.service_banners) && status.service_banners.length > 0) {
		return status.service_banners;
	}
	if (status.services && typeof status.services === 'object') {
		return Object.entries(status.services).map(([name, item]) => {
			const svc = item && typeof item === 'object' ? (item as Record<string, unknown>) : {};
			const state = String(svc.state ?? 'active');
			const uptime_secs = typeof svc.uptime_secs === 'number' ? svc.uptime_secs : 0;
			const stats: Record<string, string> = {};
			for (const [k, v] of Object.entries(svc)) {
				if (k !== 'state' && k !== 'uptime_secs' && v !== null && v !== undefined) {
					stats[k] = typeof v === 'object' ? JSON.stringify(v) : String(v);
				}
			}
			return { name, state, uptime_secs, stats };
		});
	}
	return [];
}

export function parseTimedEvent(raw: unknown, eventId?: string): SseEvent {
	const id = eventId || String(Date.now() + Math.random());
	let ts = Date.now();

	if (raw && typeof raw === 'object') {
		const rawObj = raw as Record<string, unknown>;
		if (typeof rawObj.timestamp === 'number') {
			ts = rawObj.timestamp;
		} else if (rawObj.timestamp && typeof rawObj.timestamp === 'object') {
			const tObj = rawObj.timestamp as Record<string, unknown>;
			if (typeof tObj.secs_since_epoch === 'number') {
				ts = tObj.secs_since_epoch * 1000;
			}
		}
	}

	let kind = 'Event';
	let payload: Record<string, unknown> = {};

	const rawObj = raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : null;
	const eventObj = rawObj?.event ?? raw;

	if (typeof eventObj === 'string') {
		kind = eventObj;
	} else if (typeof eventObj === 'object' && eventObj !== null) {
		const catKey = Object.keys(eventObj)[0];
		if (catKey) {
			const catVal = (eventObj as Record<string, unknown>)[catKey];
			if (typeof catVal === 'string') {
				kind = catVal;
			} else if (typeof catVal === 'object' && catVal !== null) {
				const varKey = Object.keys(catVal)[0];
				if (varKey) {
					kind = varKey;
					const varVal = (catVal as Record<string, unknown>)[varKey];
					if (typeof varVal === 'object' && varVal !== null) {
						payload = varVal as Record<string, unknown>;
					} else if (varVal !== undefined && varVal !== null) {
						payload = { value: String(varVal) };
					}
				} else {
					kind = catKey;
					payload = catVal as Record<string, unknown>;
				}
			} else {
				kind = catKey;
			}
		}
	}

	return { id, kind: kind as EventKind, data: payload, ts };
}

export function formatEventPayload(data: Record<string, unknown>, kind?: string): string {
	if (!data || Object.keys(data).length === 0) return '—';

	// 1. Network Activity
	if (kind === 'NetworkActivity' || 'change' in data) {
		const mac = (data.mac as string) || '';
		const host = (data.hostname as string) || mac || 'Device';
		const change = data.change;
		if (typeof change === 'object' && change !== null) {
			const keys = Object.keys(change);
			if (keys.length > 0) {
				const activityKind = keys[0];
				const inner = (change as Record<string, Record<string, unknown>>)[activityKind];
				if (activityKind === 'NdpActivity' && inner?.ip) {
					return `${host} updated NDP address (${inner.ip})`;
				}
				if (activityKind === 'ArpActivity' && inner?.ip) {
					return `${host} active on ARP (${inner.ip})`;
				}
				if (activityKind === 'DhcpActivity' && inner?.ip) {
					return `${host} DHCP activity (${inner.ip})`;
				}
				if (activityKind === 'L2Activity') {
					return `Layer 2 traffic detected from ${host}`;
				}
			}
		}
		return `Activity detected for ${host}`;
	}

	// 2. Neighbor Batch Summary
	if (kind === 'NeighborBatchSummary' || ('total' in data && 'duration_ms' in data)) {
		const total = Number(data.total ?? 0);
		const newCount = Number(data.new ?? 0);
		const duration = data.duration_ms ? ` in ${data.duration_ms}ms` : '';
		if (newCount > 0) {
			return `Discovered ${newCount} new device${newCount > 1 ? 's' : ''} (${total} total${duration})`;
		}
		return `Scanned ${total} neighbor${total === 1 ? '' : 's'} (${total} known${duration})`;
	}

	// 3. DHCP Lease Granted / Released
	if (kind === 'DhcpLeaseGranted') {
		const host = (data.hostname as string) || (data.mac as string) || 'client';
		const ip = (data.ip as string) || '';
		return `Lease granted to ${host}${ip ? ` (${ip})` : ''}`;
	}
	if (kind === 'DhcpLeaseReleased') {
		const host = (data.hostname as string) || (data.ip as string) || (data.mac as string) || 'client';
		return `Lease released for ${host}`;
	}

	// 4. Device Online / Offline
	if (kind === 'DeviceOnline') {
		const host = (data.hostname as string) || (data.mac as string) || 'Device';
		return `${host} came online`;
	}
	if (kind === 'DeviceOffline') {
		const host = (data.hostname as string) || (data.mac as string) || 'Device';
		return `${host} went offline`;
	}

	// 5. Keepalive & Scans
	if (kind === 'KeepaliveRestored') {
		return 'Daemon connection keepalive restored';
	}
	if (kind === 'ScanCompleted') {
		const dur = data.duration_ms ? ` (${data.duration_ms}ms)` : '';
		return `Network ARP/NDP scan completed${dur}`;
	}

	// 6. DNS Blocked
	if (kind === 'DnsBlocked') {
		const domain = (data.domain as string) || '';
		const client = (data.client as string) || '';
		return `Blocked ${domain}${client ? ` for ${client}` : ''}`;
	}

	// General Fallback formatting
	const parts: string[] = [];
	for (const [k, v] of Object.entries(data)) {
		if (v === null || v === undefined) continue;
		if (typeof v === 'object') {
			parts.push(`${k}=${JSON.stringify(v)}`);
		} else {
			parts.push(`${k}=${v}`);
		}
	}
	return parts.join(' · ') || '—';
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export interface LeaseInfo {
	ip: string;
	expires: string;
	reserved: boolean;
}

export interface Ipv6Entry {
	addr: string;
	kind: string;
}

export interface DeviceEntry {
	mac: string;
	hostname: string;
	origin: 'Dynamic' | 'Static' | 'System';
	online: boolean;
	last_seen: string;
	duid: string | null;
	display_v4: string;
	display_v6: string;
	v4: LeaseInfo | null;
	seen_v4: string[];
	v6: LeaseInfo | null;
	ipv6_addrs: Ipv6Entry[];
	learning_method: string;
	class: string;
}

export interface DevicesResponse {
	devices: DeviceEntry[];
	meta: { total: number; online: number; last_scan_secs_ago: number };
}

export interface HostConfigEntry {
	mac: string;
	hostname: string | null;
	v4?: string | null;
	v4_fixed?: string | null;
	v6_suffix?: string | null;
	origin?: string;
}

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

export interface DhcpLease {
	mac: string;
	ip: string;
	hostname: string | null;
	expires: string;
	version: 'V4' | 'V6';
}

export interface DhcpPoolStats {
	name: string;
	start: string;
	end: string;
	total: number;
	active: number;
	free: number;
}

// ---------------------------------------------------------------------------
// DNS — resolver
// ---------------------------------------------------------------------------

export interface DnsStatsResponse {
	total_requests: number;
	cache_hits: number;
	cache_misses: number;
	blocked_queries: number;
	cache_entries: number;
}

export interface TopDomainEntry {
	domain: string;
	count: number;
}

export interface TopClientEntry {
	ip: string;
	hostname: string | null;
	count: number;
}

export interface QueryTypeEntry {
	qtype: string;
	count: number;
}

export interface ProtocolStatEntry {
	protocol: string;
	count: number;
	percentage: number;
}

export interface DnsAnalyticsResponse {
	top_domains: TopDomainEntry[];
	top_clients: TopClientEntry[];
	query_types: QueryTypeEntry[];
	protocol_stats: ProtocolStatEntry[];
}

export interface DnsQueryLogEntry {
	timestamp: number;
	src_ip: string;
	domain: string;
	qtype: DnsRecordType;
	result: string;
	upstream_us: number;
	cached: boolean;
}

export interface DnsUpstreamEntry {
	url: string;
	protocol: string;
	rtt_ms: number | null;
	success_rate_pct: number;
	status: 'healthy' | 'degraded' | 'unreachable';
}

// ---------------------------------------------------------------------------
// DNS — cache
// ---------------------------------------------------------------------------

export interface DnsCacheEntry {
	name: string;
	rtype: DnsRecordType;
	value: string;
	ttl_secs: number;
}

export interface DnsCacheStatsResponse {
	entries: number;
	capacity: number;
	hit_rate_pct: number;
	memory_bytes: number;
}

// ---------------------------------------------------------------------------
// DNS — adblock
// ---------------------------------------------------------------------------

export interface DnsAdblockStatusResponse {
	enabled: boolean;
	blocklist_size: number;
	allowlist_size: number;
	timer_secs_remaining: number | null;
	last_updated: string | null;
}

export interface DnsAdblockUrlEntry {
	url: string;
	kind: 'blocklist' | 'allowlist';
}

export interface AllowlistEntry {
	id: number;
	domain: string;
}

// ---------------------------------------------------------------------------
// DNS — rewrites
// ---------------------------------------------------------------------------

export interface RewriteRule {
	id: number | null;
	domain: string;
	rtype: DnsRecordType;
	answer: string;
	resolved_ips: string[] | null;
}

// ---------------------------------------------------------------------------
// Events (SSE)
// ---------------------------------------------------------------------------

export interface SseEvent {
	id: string;
	kind: EventKind;
	data: Record<string, unknown>;
	ts: number; // parsed from id (ms)
}
