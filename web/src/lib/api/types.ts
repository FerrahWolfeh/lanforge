// API type definitions mirroring API_TYPES.md

// ---------------------------------------------------------------------------
// Primitives / shared
// ---------------------------------------------------------------------------

export type DnsRecordType =
	| 'A'
	| 'AAAA'
	| 'DEVICE'
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
	id: number | string;
	token?: string; // present only on generate
	name: string;
	created_at: number;
	last_used: number | null;
	scopes: string[];
	expires_at: number | null;
}

export interface GenerateTokenRequest {
	name: string;
	scopes?: string[];
	expires_at?: number | null;
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

export interface TransportSnapshot {
	rx_packets: number;
	rx_bytes: number;
	tx_packets: number;
	tx_bytes: number;
	dropped: number;
	rate_limited: number;
	errors: number;
	last_error_age_secs?: number;
}

export interface ServiceBanner {
	id?: string;
	name: string;
	state: ServiceState;
	uptime_secs: number;
	stats: Record<string, string>;
	detail?: any;
	transport?: TransportSnapshot;
}

export interface CapabilitiesInfo {
	encodings: string[];
	compression: string[];
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
	capabilities?: CapabilitiesInfo | ServerCapabilities;
	server_caps: ServerCapabilities;
	services: Record<string, unknown>;
	service_banners?: ServiceBanner[];
}

export function normalizeServices(status?: StatusResponse | null): ServiceBanner[] {
	if (!status) return [];
	if (Array.isArray(status.service_banners) && status.service_banners.length > 0) {
		return status.service_banners.map((b) => ({
			...b,
			id: b.id || b.name.toLowerCase().replace(/\s+/g, '_')
		}));
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
			return {
				id: typeof svc.id === 'string' && svc.id ? svc.id : name.toLowerCase().replace(/\s+/g, '_'),
				name,
				state,
				uptime_secs,
				stats
			};
		});
	}
	return [];
}

export function parseTimedEvent(raw: unknown, eventId?: string): SseEvent {
	const id = eventId || String(Date.now() + Math.random());
	let ts = Date.now();

	if (raw && typeof raw === 'object') {
		const rawObj = raw as Record<string, unknown>;
		if (typeof rawObj.timestamp_ms === 'number') {
			ts = rawObj.timestamp_ms;
		} else if (typeof rawObj.timestamp === 'number') {
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
	let catKey: string | undefined;

	if (typeof eventObj === 'string') {
		kind = eventObj;
	} else if (typeof eventObj === 'object' && eventObj !== null) {
		catKey = Object.keys(eventObj)[0];
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

	const topic = typeof rawObj?.topic === 'string'
		? rawObj.topic
		: (catKey ? catKey.toLowerCase() : undefined);

	if (typeof rawObj?.kind === 'string') {
		kind = rawObj.kind;
	}

	const device_info = (rawObj?.device_info && typeof rawObj.device_info === 'object')
		? (rawObj.device_info as EventDeviceInfo)
		: undefined;
	const interface_info = (rawObj?.interface_info && typeof rawObj.interface_info === 'object')
		? (rawObj.interface_info as EventInterfaceInfo)
		: undefined;
	const service_info = (rawObj?.service_info && typeof rawObj.service_info === 'object')
		? (rawObj.service_info as EventServiceInfo)
		: undefined;

	return {
		id,
		kind: kind as EventKind,
		topic,
		data: payload,
		ts,
		device_info,
		interface_info,
		service_info,
		raw
	};
}

export function formatEventPayload(
	data: Record<string, unknown>,
	kind?: string,
	deviceInfo?: EventDeviceInfo,
	interfaceInfo?: EventInterfaceInfo,
	serviceInfo?: EventServiceInfo
): string {
	if (!data && !deviceInfo && !interfaceInfo && !serviceInfo) return '—';

	// Helper to get preferred device display name
	const devLabel = deviceInfo?.hostname
		? `${deviceInfo.hostname}${deviceInfo.ip ? ` (${deviceInfo.ip})` : ''}`
		: (deviceInfo?.ip || deviceInfo?.mac || (data?.hostname as string) || (data?.mac as string) || 'device');

	// 1. Device Network & Admin Updates / Activity
	if (kind === 'NetworkUpdate' || kind === 'NetworkActivity' || kind === 'AdminUpdate' || (data && 'change' in data)) {
		const change = data?.change;
		if (typeof change === 'object' && change !== null) {
			const keys = Object.keys(change);
			if (keys.length > 0) {
				const changeKind = keys[0];
				const inner = (change as Record<string, Record<string, unknown>>)[changeKind];

				// Reachability & status transitions
				if (changeKind === 'StatusChanged') {
					const status = inner?.status as string;
					const isOnline = inner?.online === true || status === 'Online';
					if (isOnline) {
						return `${devLabel} is now online`;
					} else if (status === 'Stale') {
						return `${devLabel} marked as stale`;
					} else {
						return `${devLabel} went offline`;
					}
				}

				// Addressing & Leases
				if (changeKind === 'V4Assigned' && inner?.ip) {
					return `IPv4 assigned to ${devLabel}: ${inner.ip}`;
				}
				if (changeKind === 'V6Assigned' && inner?.ip) {
					return `IPv6 assigned to ${devLabel}: ${inner.ip}`;
				}
				if (changeKind === 'V6PrefixAssigned' && inner?.prefix) {
					return `IPv6 prefix delegated to ${devLabel}: ${inner.prefix}/${inner.len ?? 64}`;
				}
				if (changeKind === 'SlaacObserved' && inner?.addr) {
					return `Observed SLAAC on ${devLabel}: ${inner.addr}`;
				}
				if (changeKind === 'LeaseExpired') {
					return `Lease expired for ${devLabel}`;
				}
				if (changeKind === 'IpDeleted' && inner?.ip) {
					return `IP removed from ${devLabel}: ${inner.ip}`;
				}
				if (changeKind === 'IpOffline' && inner?.ip) {
					return `IP offline for ${devLabel}: ${inner.ip}`;
				}

				// Metadata & Discovery hints
				if (changeKind === 'HostnameHint' && inner?.hostname) {
					return `Hostname updated for ${devLabel}: ${inner.hostname}`;
				}
				if (changeKind === 'DuidAssociated' && inner?.duid) {
					return `DUID associated with ${devLabel}: ${inner.duid}`;
				}

				// Transient wire activity
				if (changeKind === 'NdpActivity' && inner?.ip) {
					return `${devLabel} active on NDP (${inner.ip})`;
				}
				if (changeKind === 'ArpActivity' && inner?.ip) {
					return `${devLabel} active on ARP (${inner.ip})`;
				}
				if (changeKind === 'DhcpActivity' && inner?.ip) {
					return `${devLabel} active on DHCP (${inner.ip})`;
				}
				if (changeKind === 'L2Activity') {
					return `Layer 2 traffic detected from ${devLabel}`;
				}

				// Administrative changes
				if (changeKind === 'HostnameChanged' && inner?.hostname) {
					return `Hostname configured for ${devLabel}: ${inner.hostname}`;
				}
				if (changeKind === 'Classified' && inner?.class) {
					return `${devLabel} classified as ${inner.class}`;
				}
				if (changeKind === 'V4StaticChanged') {
					return inner?.ip ? `Static IPv4 set for ${devLabel}: ${inner.ip}` : `Static IPv4 removed for ${devLabel}`;
				}
				if (changeKind === 'V6SuffixChanged') {
					return inner?.suffix ? `Static IPv6 suffix set for ${devLabel}: ${inner.suffix}` : `Static IPv6 suffix removed for ${devLabel}`;
				}
				if (changeKind === 'HostRemoved') {
					return `Static host configuration removed for ${devLabel}`;
				}
				if (changeKind === 'CliHostUpdated') {
					return `Host configuration updated for ${devLabel}`;
				}
			}
		}
		if (kind === 'AdminUpdate') {
			return `Device configuration updated for ${devLabel}`;
		}
		if (kind === 'NetworkUpdate') {
			return `Network parameters updated for ${devLabel}`;
		}
		return `Activity detected from ${devLabel}`;
	}

	// 2. Neighbor Batch Summary
	if (kind === 'NeighborBatchSummary' || (data && 'total' in data && 'duration_ms' in data)) {
		const total = Number(data?.total ?? 0);
		const newCount = Number(data?.new ?? 0);
		const duration = data?.duration_ms ? ` in ${data.duration_ms}ms` : '';
		if (newCount > 0) {
			return `Discovered ${newCount} new device${newCount > 1 ? 's' : ''} (${total} total${duration})`;
		}
		return `Scanned ${total} neighbor${total === 1 ? '' : 's'} (${total} known${duration})`;
	}

	// 3. DHCP Transactions & Leases
	if (kind === 'DhcpV4Transaction' || kind === 'DhcpV6Transaction') {
		const proto = kind === 'DhcpV4Transaction' ? 'DHCPv4' : 'DHCPv6';
		const msg = (data?.msg_type as string) || '';
		const det = (data?.details as string) || '';
		return `${proto} ${msg} from ${devLabel}${det ? ` — ${det}` : ''}`;
	}
	if (kind === 'DhcpLeaseGranted') {
		const ip = (data?.ip as string) || deviceInfo?.ip || '';
		return `Lease granted to ${devLabel}${ip && !devLabel.includes(ip) ? ` (${ip})` : ''}`;
	}
	if (kind === 'DhcpLeaseReleased' || kind === 'LeaseRelease') {
		return `Lease released for ${devLabel}`;
	}
	if (kind === 'LeaseRenew') {
		return `Lease renewed for ${devLabel}`;
	}

	// 4. Device Lifecycle
	if (kind === 'Discovered') {
		const iface = deviceInfo?.iface ? ` on ${deviceInfo.iface}` : '';
		return `New device discovered: ${devLabel}${iface}`;
	}
	if (kind === 'Expired') {
		return `Device lease expired: ${devLabel}`;
	}
	if (kind === 'Purged') {
		return `Device record purged: ${devLabel}`;
	}
	if (kind === 'DeviceOnline') {
		return `${devLabel} came online`;
	}
	if (kind === 'DeviceOffline') {
		return `${devLabel} went offline`;
	}

	// 5. Network / Interfaces / WOL
	if (kind === 'WolTriggered') {
		return `Wake-on-LAN magic packet sent to ${devLabel}`;
	}
	if (kind === 'RsReceived') {
		return `Router Solicitation (RS) received from ${devLabel}`;
	}
	if (kind === 'InterfaceUpdated') {
		const name = interfaceInfo?.name || `ifindex #${interfaceInfo?.ifindex ?? data?.ifindex ?? ''}`;
		const ip = interfaceInfo?.ipv4 ? ` (${interfaceInfo.ipv4})` : '';
		const gua = interfaceInfo?.gua ? ` [GUA: ${interfaceInfo.gua}]` : '';
		return `Interface ${name} state updated${ip}${gua}`;
	}

	// 6. Firewall Events
	if (kind === 'RulesetApplied') {
		const count = data?.rules_count !== undefined ? `${data.rules_count} rules` : 'rules';
		const wan = data?.wan_iface ? ` on ${data.wan_iface}` : '';
		const offload = data?.flow_offload ? ' (flow offload active)' : '';
		return `Firewall ruleset applied: ${count}${wan}${offload}`;
	}
	if (kind === 'PortOpenRequested' || kind === 'PortReleaseRequested') {
		const action = kind === 'PortOpenRequested' ? 'opened' : 'released';
		return `Port ${data?.port || ''}/${data?.protocol || ''} ${action} for ${data?.service || 'service'}`;
	}
	if (kind === 'RulesetFlushed') {
		return 'Firewall ruleset flushed';
	}
	if (kind === 'ApplyFailed') {
		return `Firewall apply failed: ${data?.error || 'kernel error'}`;
	}

	// 7. PPPoE WAN Events
	if (kind === 'SessionUp') {
		return `PPPoE session up on ${data?.interface || 'WAN'}${data?.ipv4 ? ` (${data.ipv4})` : ''}`;
	}
	if (kind === 'SessionDown') {
		return `PPPoE session disconnected: ${data?.reason || 'unknown'}`;
	}
	if (kind === 'Reconnecting') {
		return `PPPoE reconnecting (attempt ${data?.attempt || 1})`;
	}
	if (kind === 'AuthFailed') {
		return `PPPoE authentication failed: ${data?.reason || 'bad credentials'}`;
	}

	// 8. System Lifecycle & Services
	if (kind === 'ReloadConfig' || kind === 'ConfigReloaded') {
		return 'Daemon configuration reloaded';
	}
	if (kind === 'Shutdown') {
		return 'System daemon shutdown initiated';
	}
	if (kind === 'SystemReady') {
		return 'All system services initialized and ready';
	}
	if (kind === 'ServiceReady') {
		return `Service '${data?.name || 'service'}' is ready and operational`;
	}
	if (kind === 'ServiceControl') {
		const svcName = serviceInfo?.id || (data?.id as string) || 'service';
		const svcState = serviceInfo?.state ? ` [${serviceInfo.state}]` : '';
		return `Service control command: ${data?.action || 'signal'} -> ${svcName}${svcState}`;
	}
	if (kind === 'ConfigDhcpV4Changed') {
		return 'DHCPv4 service configuration updated in-place';
	}
	if (kind === 'ConfigDhcpV6Changed') {
		return 'DHCPv6 service configuration updated in-place';
	}
	if (kind === 'ConfigRaChanged') {
		return 'IPv6 Router Advertisement configuration updated in-place';
	}
	if (kind === 'ConfigTftpChanged') {
		return 'TFTP service configuration updated in-place';
	}
	if (kind === 'ConfigDhcpOptionsChanged') {
		return 'DHCP custom options updated in-place';
	}

	// 9. Traffic & SQM Events
	if (kind === 'TuningApplied') {
		return `Network tuning applied (CPU mask: ${data?.cpu_mask || 'default'})`;
	}
	if (kind === 'SqmApplied') {
		return `SQM active on ${data?.interface || 'interface'} (${data?.download_mbps || 0}M down / ${data?.upload_mbps || 0}M up)`;
	}
	if (kind === 'SqmCleared') {
		return `SQM queues removed from ${data?.interface || 'interface'}`;
	}

	// 10. Keepalive & Scans
	if (kind === 'KeepaliveRestored') {
		return 'Daemon connection keepalive restored';
	}
	if (kind === 'ScanCompleted') {
		const dur = data?.duration_ms ? ` (${data.duration_ms}ms)` : '';
		return `Network ARP/NDP scan completed${dur}`;
	}

	// 11. DNS Events
	if (kind === 'DnsBlocked') {
		const domain = (data?.domain as string) || '';
		const client = (data?.client as string) || '';
		return `Blocked ${domain}${client ? ` for ${client}` : ''}`;
	}
	if (kind === 'CacheFlush') {
		return 'DNS cache flushed';
	}
	if (kind === 'AdblockReload') {
		return 'DNS adblock rules reloaded';
	}

	// General Fallback formatting
	if (!data) return '—';
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
	primary_v4: string | null;
	primary_v6: string | null;
	v4: LeaseInfo | null;
	v6: LeaseInfo | null;
	ipv6_addrs: Ipv6Entry[];
	learning_method: string;
	class: string;
	iface?: string | null;
	vlan_id?: number | null;
	ignore_dns_log?: boolean;
	ignored_log_domains?: string[];
}

export interface DevicesMeta {
	total: number;
	online: number;
	last_scan_secs_ago: number;
}

export interface DevicesResponse {
	devices: DeviceEntry[];
	meta: DevicesMeta;
}

export interface WhoisResponse {
	entry: DeviceEntry;
}

export interface TransientHostEntry {
	ip: string;
	hostname: string;
	origin: string;
	resolved_at: number;
	last_seen: number;
}

export interface TransientHostsResponse {
	hosts: TransientHostEntry[];
}

export interface HostConfigEntry {
	mac: string;
	hostname: string | null;
	v4?: string | null;
	v4_fixed?: string | null;
	v6_suffix?: string | null;
	origin?: 'Static' | 'Dynamic' | 'System' | string;
	ignore_dns_log?: boolean;
	ignored_log_domains?: string[];
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
	cache_evictions?: number;
	cache_capacity?: number;
	upstream_errors?: number;
	auth_queries?: number;
	recursions?: number;
	resolved_total?: number;
	failed_total?: number;
}

export interface TopDomainEntry {
	domain: string;
	count: number;
}

export interface TopClientEntry {
	ip: string;
	hostname: string | null;
	count: number;
	blocked_count?: number;
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
	local?: number;
	rewritten?: number;
	record_types?: Record<string, number>;
	outcome_types?: Record<string, Record<string, number>>;
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

export type QueryResult =
	| 'local'
	| 'forwarded'
	| 'blocked'
	| 'nxdomain'
	| 'error'
	| 'cached'
	| 'rewritten'
	| 'cachedblock'
	| 'coalesced';

export interface DnsQueryLogEntry {
	timestamp: number;
	src_ip: string;
	src_mac?: string | null;
	src_hostname?: string | null;
	domain: string;
	qtype: DnsRecordType;
	result: QueryResult | string;
	upstream_us: number;
	cached: boolean;
	answer?: string | null;
	filter?: FilterMatch | null;
	coalesce_id?: number | null;
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

export type BlockingMode = 'nxdomain' | 'null_ip' | 'custom_ip' | 'refused';

export type FilterAction = 'block' | 'allow';

export type FilterOrigin =
	| { type: 'user_rule' }
	| { type: 'user_allowlist' }
	| { type: 'list'; source_id: number };

export interface FilterMatch {
	action: FilterAction;
	origin: FilterOrigin;
	rule?: string | null;
	important?: boolean;
}

export type AdblockSourceFormat =
	| 'auto'
	| 'adblock'
	| 'hosts'
	| 'domains'
	| 'wildcard_domains';

export interface AdblockSourceStatus {
	source_id: number;
	name?: string | null;
	url: string;
	format: AdblockSourceFormat;
	format_detected?: AdblockSourceFormat | null;
	last_fetch_attempt?: number | null;
	last_success?: number | null;
	consecutive_failures: number;
	last_error?: string | null;
	rules_count: number;
	exceptions_count: number;
	unsupported_count: number;
}

export interface DnsAdblockSourcesResponse {
	sources: AdblockSourceStatus[];
}

export interface AdblockSourceMatch {
	source_id: number;
	url: string;
	action: FilterAction;
	rule?: string | null;
	important: boolean;
}

export interface AdblockCheckResponse {
	domain: string;
	matched: boolean;
	filter?: FilterMatch | null;
	source_matches: AdblockSourceMatch[];
}

export interface TimeOfDay {
	hour: number;
	minute: number;
}

export interface DnsAdblockStatusResponse {
	enabled: boolean;
	disabled_until?: number | null;
	remaining_secs?: number | null;
	blocklist_size: number;
	allowlist_size: number;
	exceptions_size?: number;
	last_update?: number | null;
	next_update?: number | null;
	sources_ok?: number;
	sources_failing?: number;
	blocking_mode: BlockingMode;
	blocking_ip_v4?: string | null;
	blocking_ip_v6?: string | null;
}

export interface DnsAdblockUrlEntry {
	id?: number | null;
	name?: string | null;
	url: string;
	kind: 'blocklist' | 'allowlist';
	format?: AdblockSourceFormat;
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

export interface EventDeviceInfo {
	mac: string;
	hostname?: string;
	ip?: string;
	class?: string;
	status?: string;
	origin?: string;
	is_static?: boolean;
	iface?: string;
}

export interface EventInterfaceInfo {
	ifindex: number;
	name?: string;
	ipv4?: string;
	gua?: string;
	ula?: string;
}

export interface EventServiceInfo {
	id: string;
	state: string;
	uptime_secs: number;
}

export interface SseEvent {
	id: string;
	kind: EventKind;
	topic?: string;
	data: Record<string, unknown>;
	ts: number; // parsed from id (ms)
	device_info?: EventDeviceInfo;
	interface_info?: EventInterfaceInfo;
	service_info?: EventServiceInfo;
	raw?: unknown;
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
	is_provisioned: boolean;
	detected_lan_iface: string;
	detected_gateway: string | null;
	detected_subnet_mask?: string | null;
	detected_ula_prefix: string;
	interfaces: NetworkInterfaceInfo[];
}

export interface SetupPppoeNftables {
	mss_clamping: boolean;
	flow_offload: boolean;
	masquerade: boolean;
	bypass_dns: boolean;
	bypass_vowifi: boolean;
}

export interface SetupRaConfig {
	enabled: boolean;
	auto_gua: boolean;
	auto_ula?: boolean;
	ula_enabled: boolean;
	ula_prefix?: string | null;
	managed: boolean;
	other_config: boolean;
}

export type SetupWanConfig =
	| {
		mode: 'pppoe';
		interface: string;
		username: string;
		password: string;
		vlan_id?: number | null;
		mtu?: number | null;
		nftables?: SetupPppoeNftables | null;
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
	subnet_mask?: string;
	domain_name: string;
	dhcp_enabled: boolean;
	dhcp_pool_start: string;
	dhcp_pool_end: string;
	dhcp_router?: string | null;
	dhcp_v6_enabled?: boolean;
	dhcp_v6_pool_range?: string | null;
	adblock_enabled: boolean;
	adblock_sources?: DnsAdblockUrlEntry[];
	upstream_dns?: string[];
	ra?: SetupRaConfig | null;
	wan?: SetupWanConfig | null;
	firewall_mode?: FirewallMode;
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
export type PppoeSessionState =
	| 'disconnected'
	| 'waiting_for_carrier'
	| 'waiting_for_terminal'
	| 'discovering'
	| 'authenticating'
	| 'connected'
	| 'reconnecting';

export interface TerminalProbeConfig {
	enabled: boolean;
	target_ip: string;
	sender_ip?: string | null;
	iface?: string | null;
	timeout_ms: number;
	poll_interval_secs: number;
	max_wait_secs: number;
}

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
	terminal_probe?: TerminalProbeConfig;
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
	auth?: PppoeAuthMethod | null;
	terminal_reachable?: boolean | null;
	terminal_mac?: string | null;
	terminal_rtt_us?: number | null;
}


// ---------------------------------------------------------------------------
// Router Advertisement (RA)
// ---------------------------------------------------------------------------

export type RouterPriority = 'low' | 'medium' | 'high';
export type PrefixSource = 'static' | 'ula' | 'auto_gua';

export interface RaPrefix {
	source: PrefixSource;
	address?: string | null;
	prefix_len: number;
	on_link?: boolean;
	autonomous?: boolean;
	router_addr?: boolean;
	valid_lifetime?: string | number | null;
	preferred_lifetime?: string | number | null;
}

export interface RdnssConfig {
	servers: string[];
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
	deprecate_on_renumber: boolean;
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

// ---------------------------------------------------------------------------
// Database & System Configuration
// ---------------------------------------------------------------------------

export interface DbMetrics {
	last_flush_ts: number;
	flush_count: number;
	devices_written: number;
	last_error: boolean | number;
}

export interface DbEngineSwitchRequest {
	engine?: 'redb' | 'memory' | string;
	url?: string;
	max_connections?: number;
	min_connections?: number;
}

export interface ExportedApiToken {
	token: string;
	name: string;
	created_at: number;
	last_used?: number | null;
	scopes: string;
	expires_at?: number | null;
}

export interface DnsUpstreamConfig {
	addr: string;
	protocol: string;
	domain?: string | null;
}

export interface AdblockDbConfig {
	enabled: boolean;
	blocking_mode: string;
	blocking_ip_v4?: string | null;
	blocking_ip_v6?: string | null;
	refresh_time: TimeOfDay;
}

export interface AdblockRuleEntry {
	id?: number;
	domain: string;
	action: 'block' | 'allow';
	enabled: boolean;
}

export interface SystemConfigExport {
	hosts: HostConfigEntry[];
	dns_rewrites: RewriteRule[];
	dns_upstreams: DnsUpstreamConfig[];
	dns_adblock_config: AdblockDbConfig;
	dns_adblock_urls: DnsAdblockUrlEntry[];
	dns_allowlist: AllowlistEntry[];
	dns_adblock_rules?: AdblockRuleEntry[] | null;
	api_tokens?: ExportedApiToken[] | null;
	dhcp_v4_pools?: Dhcpv4PoolConfig[] | null;
	dhcp_v6_pools?: Dhcpv6PoolConfig[] | null;
	ra_prefixes?: RaPrefix[] | null;
	ra_rdnss?: RdnssConfig[] | null;
	ra_dnssl?: DnsslConfig[] | null;
	pppoe_config?: PppoeConfig | null;
	dhcp_options?: DhcpOptionsConfig | null;
	dns_reverse_resolvers?: ReverseResolverEntry[] | null;
	overwrite?: boolean;
}

export interface ImportResult {
	section: string;
	success: boolean;
	count: number;
	error?: string | null;
}

export interface SystemConfigImportResponse {
	results: ImportResult[];
	total_success: boolean;
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

export type FirewallPolicy = 'Drop' | 'Accept' | 'Reject';
export type L4Protocol = 'Tcp' | 'Udp' | 'Both';

export interface HostPortRule {
	comment: string | null;
	port: number;
	protocol: L4Protocol;
}

export interface DynamicPortRequest {
	service: string;
	zone: string;
	comment: string | null;
	port: number;
	protocol: L4Protocol;
}

export interface FirewallZone {
	name: string;
	interfaces: string[];
	open_ports: HostPortRule[];
	allowed_subnets: string[];
	input_policy: FirewallPolicy;
	forward_policy: FirewallPolicy;
	masquerade: boolean;
	mtu_fix: boolean;
}

export interface ZoneForwarding {
	from: string;
	to: string;
}

export interface PortForwardRule {
	comment: string | null;
	src_zone: string;
	internal_ip: string;
	external_port: number;
	internal_port: number;
	protocol: L4Protocol;
	enable_hairpin: boolean;
}

export type FirewallMode = "full" | "minimal" | "disabled";

export type FirewallStopAction = "lockdown" | "remove";

export interface FirewallConfig {
	mode: FirewallMode;
	table_name: string;
	zones: FirewallZone[];
	forwardings: ZoneForwarding[];
	port_forwards: PortForwardRule[];
	custom_rules_file: string | null;
	enabled: boolean;
	flow_offload: boolean;
	bypass_dns: boolean;
	bypass_vowifi: boolean;
	default_input_policy: FirewallPolicy;
	default_forward_policy: FirewallPolicy;
	/** What stopping the firewall leaves in the kernel: a closed-WAN lockdown or nothing. */
	on_stop?: FirewallStopAction;
}

export interface FirewallStatus {
	mode: FirewallMode;
	table: string;
	active_wan: string | null;
	lan_ifaces: string[];
	last_applied_secs_ago: number | null;
	open_ports_count: number;
	rules_count: number;
	enabled: boolean;
	flow_offload_active: boolean;
	flow_offload_suspended?: boolean;
	default_drop_active: boolean;
}

export interface FirewallValidationReport {
	valid: boolean;
	tx_id: string | null;
	diff_summary: string[];
	warnings: string[];
	errors: string[];
}

export interface FirewallCommitRequest {
	tx_id: string;
	auto_rollback_secs: number | null;
}

export interface FirewallCommitResponse {
	success: boolean;
	message: string;
	auto_rollback_active: boolean;
	rollback_deadline_secs: number | null;
}

// ---------------------------------------------------------------------------
// Traffic & SQM
// ---------------------------------------------------------------------------

export type SqmOverhead = "auto" | "pppoe" | "ethernet" | "docsis" | "none";
export type SqmDiffserv = "diffserv4" | "diffserv3" | "besteffort";

export interface NicTuningConfig {
	enabled: boolean;
	interfaces: string[];
	cpu_mask: string;
	rps_flow_entries: number;
	rps_flow_cnt: number;
	rx_ring: string;
	tx_ring: string;
	disable_eee: boolean;
	udp_gro_forwarding: boolean;
}

export interface SqmConfig {
	enabled: boolean;
	interface: string;
	download_mbps: number;
	upload_mbps: number;
	overhead: SqmOverhead;
	diffserv: SqmDiffserv;
	per_host_isolation: boolean;
	rtt_ms: number | null;
	ingress_device: string;
	raw_cake_args: string | null;
}

export interface TrafficConfig {
	tuning: NicTuningConfig;
	sqm: SqmConfig;
}

export interface TrafficStatusResponse {
	service_state: ServiceState;
	tuning_applied: boolean;
	tuned_interfaces: string[];
	effective_cpu_mask: string;
	sqm_active: boolean;
	wan_interface: string | null;
	ingress_device: string | null;
	download_mbps: number;
	upload_mbps: number;
	overhead: SqmOverhead;
	diffserv: SqmDiffserv;
	flow_offload_suppressed: boolean;
}

export interface InterfaceTrafficStats {
	interface: string;
	rx_bytes: number;
	tx_bytes: number;
	rx_packets: number;
	tx_packets: number;
	rx_errors: number;
	tx_errors: number;
	rx_dropped: number;
	tx_dropped: number;
	rx_rate_bps: number;
	tx_rate_bps: number;
}

export interface CakeTinStats {
	tin_index: number;
	name: string;
	threshold_rate: number;
	sent_bytes: number;
	sent_packets: number;
	backlog_bytes: number;
	peak_delay_us: number;
	avg_delay_us: number;
	base_delay_us: number;
	drops: number;
	ecn_mark: number;
	ack_drops: number;
	sparse_flows: number;
	bulk_flows: number;
	unresponsive_flows: number;
}

export interface CakeQdiscStats {
	dev: string;
	kind: string;
	bandwidth: number;
	bytes: number;
	packets: number;
	drops: number;
	overlimits: number;
	backlog: number;
	qlen: number;
	memory_used: number;
	memory_limit: number;
	capacity_estimate: number;
	tins: CakeTinStats[];
}

export interface SqmTelemetryStats {
	active: boolean;
	egress: CakeQdiscStats | null;
	ingress: CakeQdiscStats | null;
}

export interface ConntrackStats {
	active_connections: number;
	max_connections: number;
	utilization_percent: number;
	search: number;
	new: number;
	drop: number;
	invalid: number;
}

export interface InterfaceThroughputPoint {
	interface: string;
	rx_rate_bps: number;
	tx_rate_bps: number;
}

export interface TrafficHistorySample {
	timestamp: number;
	interfaces: InterfaceThroughputPoint[];
}

export interface TrafficTelemetryResponse {
	timestamp: number;
	interfaces: InterfaceTrafficStats[];
	sqm: SqmTelemetryStats | null;
	conntrack: ConntrackStats | null;
	history?: TrafficHistorySample[];
	wan_interface?: string | null;
	ingress_device?: string | null;
}


