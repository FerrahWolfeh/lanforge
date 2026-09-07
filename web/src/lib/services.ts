import type { Component } from 'svelte';
import GlobeIcon from '@lucide/svelte/icons/globe';
import ServerIcon from '@lucide/svelte/icons/server';
import NetworkIcon from '@lucide/svelte/icons/network';
import ZapIcon from '@lucide/svelte/icons/zap';
import RadioIcon from '@lucide/svelte/icons/radio';
import HardDriveIcon from '@lucide/svelte/icons/hard-drive';
import FolderIcon from '@lucide/svelte/icons/folder';
import KeyIcon from '@lucide/svelte/icons/key';
import CpuIcon from '@lucide/svelte/icons/cpu';
import ShieldCheckIcon from '@lucide/svelte/icons/shield-check';

export interface ServiceMeta {
	id: string;
	name: string;
	tag: string;
	proto: string;
	description: string;
	configHref: string;
	configLabel: string;
	icon: Component;
	canControl: boolean;
}

const SERVICE_REGISTRY: Record<string, Omit<ServiceMeta, 'id'>> = {
	pppoe: {
		name: 'PPPoE Concentrator & WAN',
		tag: 'WAN Gateway',
		proto: 'PPP over Ethernet',
		description: 'FTTH / DSL broadband session manager, MTU clamping, and kernel pppoe tunnel',
		configHref: '/network/pppoe',
		configLabel: 'PPPoE Settings',
		icon: ZapIcon,
		canControl: true
	},
	ra: {
		name: 'IPv6 Router Advertisements',
		tag: 'RADVD / SLAAC',
		proto: 'ICMPv6 (NDP)',
		description: 'RFC 4861 autoconfiguration announcements, GUA/ULA prefixes, and RDNSS DNS option',
		configHref: '/network/ra',
		configLabel: 'Router Advertisement Settings',
		icon: RadioIcon,
		canControl: true
	},
	dhcpv4: {
		name: 'DHCPv4 Server',
		tag: 'Dynamic Leases',
		proto: 'UDP Port 67',
		description: 'IPv4 dynamic pool leasing, static reservations, default gateway, and DNS options',
		configHref: '/dhcp/server',
		configLabel: 'DHCPv4 Server Options',
		icon: ServerIcon,
		canControl: true
	},
	dhcpv6: {
		name: 'DHCPv6 Server',
		tag: 'Stateful / Stateless',
		proto: 'UDP Port 547',
		description: 'IPv6 address assignment, prefix delegation (IA_PD), and NTP/DNS announcements',
		configHref: '/dhcp/scopes',
		configLabel: 'DHCPv6 Scopes',
		icon: ServerIcon,
		canControl: true
	},
	dns: {
		name: 'DNS Resolver & Filter Engine',
		tag: 'Recursive & Cache',
		proto: 'UDP/TCP Port 53',
		description: 'Multi-upstream recursive forwarder, query cache, local rewrites, and DNS shielding',
		configHref: '/dns/resolver',
		configLabel: 'DNS Resolver Settings',
		icon: GlobeIcon,
		canControl: true
	},
	dot: {
		name: 'DNS over TLS (DoT)',
		tag: 'Encrypted Transport',
		proto: 'TCP Port 853',
		description: 'Standard privacy-preserving encrypted DNS over TLS transport',
		configHref: '/dns/resolver',
		configLabel: 'DNS Transports',
		icon: ShieldCheckIcon,
		canControl: true
	},
	doq: {
		name: 'DNS over QUIC (DoQ)',
		tag: 'QUIC / UDP',
		proto: 'UDP Port 853',
		description: 'Low-latency modern multiplexed encrypted DNS transport over QUIC',
		configHref: '/dns/resolver',
		configLabel: 'DNS Transports',
		icon: ShieldCheckIcon,
		canControl: true
	},
	monitor: {
		name: 'Neighbor Discovery & ARP/NDP',
		tag: 'Kernel Netlink',
		proto: 'RTM_GETNEIGH',
		description: 'Passive Linux kernel ARP/NDP cache tracking and active ICMP keepalive probes',
		configHref: '/network/devices',
		configLabel: 'Device Inventory',
		icon: NetworkIcon,
		canControl: true
	},
	mdns: {
		name: 'mDNS Hostname Prober',
		tag: 'ZeroConf / SD',
		proto: 'UDP Port 5353',
		description: 'Multicast DNS PTR/SRV discovery prober for automatic hostname resolution',
		configHref: '/network/devices',
		configLabel: 'Device Inventory',
		icon: RadioIcon,
		canControl: true
	},
	tftp: {
		name: 'Bootstrapping TFTP Server',
		tag: 'PXE Boot',
		proto: 'UDP Port 69',
		description: 'Network PXE bootloader, kernel, and initial ramdisk image distribution server',
		configHref: '/system',
		configLabel: 'System Status',
		icon: FolderIcon,
		canControl: true
	},
	db: {
		name: 'Persistent Database Worker',
		tag: 'Embedded Redb',
		proto: 'ACID Transactions',
		description: 'Transactional key-value store managing device leases, audit logs, and configurations',
		configHref: '/system/database',
		configLabel: 'Database Storage',
		icon: HardDriveIcon,
		canControl: false
	},
	control: {
		name: 'Control API & UDS IPC',
		tag: 'Admin Interface',
		proto: 'Unix Domain Socket',
		description: 'Internal daemon RPC dispatcher for CLI operations and authenticated management',
		configHref: '/system',
		configLabel: 'System Status',
		icon: KeyIcon,
		canControl: false
	},
	http: {
		name: 'REST API & WebUI Server',
		tag: 'HTTP / REST',
		proto: 'TCP Port 8088',
		description: 'REST API backend, Prometheus metrics exporter, and embedded web interface host',
		configHref: '/system',
		configLabel: 'System Status',
		icon: CpuIcon,
		canControl: false
	}
};

export function getServiceMeta(id?: string, name?: string): ServiceMeta {
	const rawId = (id || '').toLowerCase().trim();
	const rawName = (name || '').toLowerCase().trim();

	// Match by known ID first
	for (const [key, meta] of Object.entries(SERVICE_REGISTRY)) {
		if (rawId === key || rawName === key) {
			return { id: key, ...meta };
		}
	}

	// Match by heuristic name contains
	if (rawId.includes('pppoe') || rawName.includes('pppoe')) {
		return { id: 'pppoe', ...SERVICE_REGISTRY.pppoe };
	}
	if (rawId.includes('ra') || rawName.includes('router') || rawName.includes('advert')) {
		return { id: 'ra', ...SERVICE_REGISTRY.ra };
	}
	if (rawId.includes('dhcpv6') || rawName.includes('dhcpv6') || rawName.includes('dhcp 6')) {
		return { id: 'dhcpv6', ...SERVICE_REGISTRY.dhcpv6 };
	}
	if (rawId.includes('dhcp') || rawName.includes('dhcp')) {
		return { id: 'dhcpv4', ...SERVICE_REGISTRY.dhcpv4 };
	}
	if (rawId.includes('dot')) return { id: 'dot', ...SERVICE_REGISTRY.dot };
	if (rawId.includes('doq')) return { id: 'doq', ...SERVICE_REGISTRY.doq };
	if (rawId.includes('dns') || rawName.includes('dns')) {
		return { id: 'dns', ...SERVICE_REGISTRY.dns };
	}
	if (rawId.includes('monitor') || rawName.includes('neighbor') || rawName.includes('discovery')) {
		return { id: 'monitor', ...SERVICE_REGISTRY.monitor };
	}
	if (rawId.includes('mdns')) return { id: 'mdns', ...SERVICE_REGISTRY.mdns };
	if (rawId.includes('tftp')) return { id: 'tftp', ...SERVICE_REGISTRY.tftp };
	if (rawId.includes('db')) return { id: 'db', ...SERVICE_REGISTRY.db };
	if (rawId.includes('control')) return { id: 'control', ...SERVICE_REGISTRY.control };
	if (rawId.includes('http')) return { id: 'http', ...SERVICE_REGISTRY.http };

	// Fallback generic meta
	const cleanName = (name || id || 'Unknown Service').replace(/_/g, ' ');
	return {
		id: id || cleanName.toLowerCase().replace(/\s+/g, '-'),
		name: cleanName,
		tag: 'Background Service',
		proto: 'Tokio Async',
		description: 'Supervised daemon service worker task',
		configHref: '/system',
		configLabel: 'System Status',
		icon: CpuIcon,
		canControl: true
	};
}
