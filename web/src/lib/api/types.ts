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
	id?: string;
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
	iface?: string | null;
	vlan_id?: number | null;
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

export type LeaseKind = 'v4' | 'v6' | 'v6_prefix';

export type LeaseTarget =
	| 'V4'
	| { V6: { iaid: number } }
	| { V6Prefix: { iaid: number } };

export interface LeaseEntry {
	mac: string;
	hostname: string;
	address: string;
	kind: LeaseKind;
	expires: number;
	remaining_secs: number;
}

export type DhcpLease = LeaseEntry;

export type DhcpPoolType = 'v4' | 'v6';

export interface DhcpPoolEntry {
	pool_type: DhcpPoolType;
	range_start: string | null;
	range_end: string | null;
	prefix: string | null;
	prefix_len: number | null;
	total: number;
	used: number;
	available: number;
	utilization_percent: number;
}

export interface DhcpPoolsResponse {
	v4_pools: DhcpPoolEntry[];
	v6_pools: DhcpPoolEntry[];
}

export interface Dhcpv4PoolConfig {
	name?: string | null;
	range_start: string;
	range_end: string;
	subnet_mask?: string | null;
	router?: string | null;
	dns_servers?: string[];
	domain_name?: string | null;
	search_domains?: string[];
	ntp_servers?: string[];
	lease_time?: number | null;
	boot_file?: string | null;
	tftp_server?: string | null;
}

export interface Dhcpv6PoolConfig {
	name?: string | null;
	range_start?: string | null;
	range_end?: string | null;
	address?: string | null;
	dns_servers?: string[];
	search_domains?: string[];
	ntp_servers?: string[];
	lease_time?: number | null;
	boot_file?: string | null;
}

export interface DhcpPoolsConfigResponse {
	v4_pools: Dhcpv4PoolConfig[];
	v6_pools: Dhcpv6PoolConfig[];
	active_ula_prefix?: string | null;
	active_gua_prefix?: string | null;
}

export interface Dhcpv4Options {
	enabled: boolean;
	lease_time: number;
	router: string | null;
	subnet_mask: string | null;
	dns_servers: string[];
	domain_name: string | null;
	search_domains: string[];
	ntp_servers: string[];
	tftp_server: string | null;
	boot_file: string | null;
	raw_options: Record<number, string>;
}

export interface Dhcpv6Options {
	enabled: boolean;
	lease_time: number;
	dns_servers: string[];
	search_domains: string[];
	ntp_servers: string[];
	boot_file: string | null;
	raw_options: Record<number, string>;
}

export interface TftpOptions {
	enabled: boolean;
	listen_addr: string;
	root_dir: string;
	block_size: number;
	timeout: number;
	max_retries: number;
}

export interface DhcpOptionsConfig {
	v4: Dhcpv4Options;
	v6: Dhcpv6Options;
	tftp: TftpOptions;
}

export interface DhcpOptionsResponse {
	options: DhcpOptionsConfig;
}

export interface InvalidatedLeaseInfo {
	mac: string;
	ip: string;
	hostname: string | null;
	reason: string;
}

export interface DhcpReconcileResponse {
	invalidated_v4_leases: InvalidatedLeaseInfo[];
	valid_v4_leases: number;
	preserved_static_leases: number;
}

export interface LeasesResponse {
	leases: LeaseEntry[];
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

export interface QueryRateEntry {
	timestamp: number;
	count: number;
	cached?: number;
	forwarded?: number;
	blocked?: number;
}

export interface DnsAnalyticsResponse {
	top_domains: TopDomainEntry[];
	top_clients: TopClientEntry[];
	query_types: QueryTypeEntry[];
	protocol_stats: ProtocolStatEntry[];
	query_rate?: QueryRateEntry[];
	blocked_query_rate?: QueryRateEntry[];
	top_blocked_domains?: TopDomainEntry[];
	top_blocked_clients?: TopClientEntry[];
}

export interface DnsQueryLogEntry {
	timestamp: number;
	src_ip: string;
	src_mac?: string | null;
	src_hostname?: string | null;
	domain: string;
	qtype: DnsRecordType;
	result: string;
	upstream_us: number;
	cached: boolean;
	answer?: string | null;
}

export interface DnsUpstreamEntry {
	target?: string | { addr?: string; protocol?: string };
	url?: string;
	addr?: string;
	protocol: string;
	domain?: string | null;
	rtt_ewma_us?: number;
	last_rtt_us?: number;
	rtt_ms?: number | null;
	latency_ms?: number | null;
	success_rate_pct?: number;
	status?: 'healthy' | 'degraded' | 'unreachable' | string;
}

export interface DnsUpstreamsResponse {
	upstreams: DnsUpstreamEntry[];
}

export interface ReverseResolverEntry {
	subnet: string | { addr: string; prefix_len: number };
	resolver?: string | { addr?: string; protocol?: string };
	resolver_uri?: string;
}

// ---------------------------------------------------------------------------
// DNS — cache
// ---------------------------------------------------------------------------

export interface DnsCacheEntry {
	name: string;
	kind: DnsRecordType;
	data: string;
	expires_in_secs: number;
}

export interface DnsCacheStatsExtResponse {
	total_entries: number;
	entries_by_type: Record<DnsRecordType, number>;
	memory_usage_bytes: number;
	average_ttl_secs: number;
	min_ttl: number;
	evictions: number;
	capacity: number;
}

export type DnsCacheStatsResponse = DnsCacheStatsExtResponse;

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
	answer: string | Record<string, unknown>;
	resolved_ips: string[] | null;
}

export function formatRewriteAnswer(ans: unknown): string {
	if (!ans) return "";
	if (typeof ans === "string") return ans.trim();
	if (typeof ans === "object" && ans !== null) {
		const obj = ans as Record<string, any>;
		if (typeof obj.a === "string") return obj.a;
		if (typeof obj.aaaa === "string") return obj.aaaa;
		if (typeof obj.cname === "string") return obj.cname;
		if (obj.device) {
			const dev = obj.device;
			const id = typeof dev === "string"
				? dev
				: typeof dev.identifier === "string"
					? dev.identifier
					: typeof dev.identifier === "object" && dev.identifier
						? (dev.identifier.hostname ?? dev.identifier.mac ?? dev.identifier.duid ?? JSON.stringify(dev.identifier))
						: String(dev);
			const fb = dev.fallback ? `|${formatRewriteAnswer(dev.fallback)}` : "";
			return `dev:${id}${fb}`;
		}
		if (obj.service) {
			const s = obj.service;
			const svc = s.service ?? "_http";
			const proto = s.protocol ?? "_tcp";
			const dev = typeof s.device === "string" ? s.device : JSON.stringify(s.device ?? "");
			const port = s.port ?? 80;
			return `srv:${svc}:${proto}:${dev}:${port}`;
		}
		// Single key serde enum fallback e.g. { Cname: "dev:raspie" }
		const keys = Object.keys(obj);
		if (keys.length === 1) {
			const val = obj[keys[0]];
			if (typeof val === "string") return val;
			return formatRewriteAnswer(val);
		}
	}
	return String(ans);
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

// ---------------------------------------------------------------------------
// Setup & Onboarding
// ---------------------------------------------------------------------------

export interface NetworkInterfaceInfo {
	name: string;
	mac: string | null;
	is_physical: boolean;
	is_up: boolean;
	carrier_up: boolean;
	ips: string[];
	bus_type: string;
}

export interface SetupStatusResponse {
	first_run: boolean;
	detected_lan_iface: string;
	detected_gateway: string | null;
	detected_ula_prefix: string;
	interfaces: NetworkInterfaceInfo[];
}

export type SetupWanConfig =
	| {
			mode: 'pppoe';
			interface: string;
			username: string;
			password: string;
			vlan_id?: number | null;
			mtu?: number | null;
	  }
	| {
			mode: 'system_gateway';
			gateway_ip: string;
	  };

export interface SetupPayload {
	admin_username: string;
	admin_password: string;
	lan_iface: string;
	lan_ip: string;
	domain_name: string;
	dhcp_enabled: boolean;
	dhcp_pool_start: string;
	dhcp_pool_end: string;
	adblock_enabled: boolean;
	wan?: SetupWanConfig | null;
}

export interface SetupResponse {
	success: boolean;
	token: string;
	username: string;
	message: string;
}

// ---------------------------------------------------------------------------
// PPPoE
// ---------------------------------------------------------------------------

export type PppoeDataplane = 'kernel' | 'ebpf';
export type PppoeAuthMethod = 'none' | 'pap' | 'chap_md5';
export type PppoeSessionState = 'disconnected' | 'authenticating' | 'connected' | 'reconnecting';

export interface PppoeNftablesConfig {
	enabled: boolean;
	table_name: string;
	flow_offload: boolean;
	mss_clamping: boolean;
	bypass_dns: boolean;
	bypass_vowifi: boolean;
	masquerade: boolean;
	custom_rules_file: string | null;
	lan_ifaces?: string[];
}

export interface PppoeConfig {
	enabled: boolean;
	dataplane: PppoeDataplane;
	wan_iface: string;
	username: string;
	password: string;
	service_name: string | null;
	ac_name: string | null;
	auth: PppoeAuthMethod;
	mru: number;
	lcp_echo_interval_secs: number;
	lcp_echo_max_failures: number;
	reconnect_delay_secs: number;
	send_padt_on_shutdown: boolean;
	discovery_padi_retries: number;
	discovery_padi_timeout_secs: number;
	nftables: PppoeNftablesConfig;
}

export interface PppoeStatusResponse {
	enabled: boolean;
	dataplane?: PppoeDataplane | null;
	state: PppoeSessionState;
	interface: string | null;
	wan_iface: string | null;
	local_ip: string | null;
	peer_ip: string | null;
	ac_mac: string | null;
	ac_name: string | null;
	session_id: number | null;
	mru: number | null;
	dns_servers: string[];
	uptime_secs: number | null;
	reconnect_attempts: number;
	last_error: string | null;
}

// ---------------------------------------------------------------------------
// Router Advertisement (RA)
// ---------------------------------------------------------------------------

export type RouterPriority = 'low' | 'medium' | 'high';

export interface RaPrefix {
	prefix: string;
	on_link?: boolean;
	autonomous?: boolean;
	valid_lifetime?: number | null;
	preferred_lifetime?: number | null;
	router_address?: boolean;
}

export interface RdnssConfig {
	addresses: string[];
	lifetime?: number | null;
}

export interface DnsslConfig {
	domains: string[];
	lifetime?: number | null;
}

export interface RaServerConfig {
	enabled: boolean;
	iface?: string | null;
	managed: boolean;
	other_config: boolean;
	hop_limit: number;
	priority: RouterPriority;
	max_interval_secs: number;
	min_interval_secs?: number | null;
	lifetime_secs?: number | null;
	reachable_time_ms: number;
	retrans_timer_ms: number;
	mtu?: number | null;
	prefixes: RaPrefix[];
	rdnss: RdnssConfig[];
	dnssl: DnsslConfig[];
}

export interface RaStatusResponse {
	enabled: boolean;
	interface: string | null;
	link_local: string | null;
	active_gua_prefix: string | null;
	active_ula_prefix: string | null;
	prefixes: RaPrefix[];
	rdnss: RdnssConfig[];
	dnssl: DnsslConfig[];
	deprecated_prefixes: [string, number][];
	sent_multicast_ras: number;
	sent_unicast_ras: number;
	received_solicitations: number;
	ignored_solicitations: number;
	last_ra_sent_secs_ago: number | null;
	last_rs_received_secs_ago: number | null;
	next_ra_in_secs: number | null;
	managed: boolean;
	other_config: boolean;
	hop_limit: number;
	priority: RouterPriority;
	max_interval_secs: number;
	min_interval_secs: number;
	router_lifetime_secs: number;
	mtu: number | null;
	uptime_secs: number | null;
}

