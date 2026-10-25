<script lang="ts" module>
	import type { AdblockSourceFormat } from "$lib/api/types";

	export interface AdblockPresetOption {
		id: string;
		title: string;
		description: string;
		badge: string;
		url: string;
		format: AdblockSourceFormat;
	}

	export const ADBLOCK_PRESET_OPTIONS: AdblockPresetOption[] = [
		{
			id: "stevenblack",
			title: "StevenBlack Unified",
			description: "Adware and malware blocking hosts list (~150k rules)",
			badge: "Hosts",
			url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			format: "hosts"
		},
		{
			id: "oisd",
			title: "OISD Basic",
			description: "Ad, tracking, and telemetry blocklist (~250k rules)",
			badge: "Domains",
			url: "https://big.oisd.nl/domainswg",
			format: "domains"
		},
		{
			id: "hagezi",
			title: "Hägezi Multi Normal",
			description: "Tracker, phishing, and telemetry domain list",
			badge: "Hosts",
			url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
			format: "hosts"
		},
		{
			id: "adguard",
			title: "AdGuard Mobile",
			description: "Mobile app trackers and telemetry domain list",
			badge: "Domains",
			url: "https://v.firebog.net/hosts/AdguardDNS.txt",
			format: "domains"
		},
		{
			id: "spyblocker",
			title: "Windows SpyBlocker",
			description: "Telemetry, diagnostics, and update tracking endpoints",
			badge: "Hosts",
			url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
			format: "hosts"
		}
	];
</script>

<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Label } from "$lib/components/ui/label";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ServerIcon from "@lucide/svelte/icons/server";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ArrowLeftIcon from "@lucide/svelte/icons/arrow-left";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import CheckIcon from "@lucide/svelte/icons/check";
	import type { NetworkInterfaceInfo } from "$lib/api/types";

	let {
		lanIface = $bindable(""),
		lanIp = $bindable("192.168.1.1"),
		subnetMask = $bindable("255.255.255.0"),
		domainName = $bindable("lan"),
		dhcpV4Enabled = $bindable(true),
		dhcpPoolStart = $bindable("192.168.1.100"),
		dhcpPoolEnd = $bindable("192.168.1.240"),
		dhcpRouter = $bindable("192.168.1.1"),
		dhcpV6Enabled = $bindable(true),
		dhcpV6PoolRange = $bindable("::100-::1fff"),
		raEnabled = $bindable(true),
		raAutoGua = $bindable(true),
		raAutoUla = $bindable(true),
		raCustomUla = $bindable(false),
		raUlaPrefix = $bindable(""),
		dnsPreset = $bindable("quad9"),
		customDnsServers = $bindable("9.9.9.9, 149.112.112.112"),
		adblockEnabled = $bindable(true),
		selectedAdblockPresets = $bindable(["stevenblack", "oisd"]),
		interfaces = [],
		onLanIfaceChange,
		onback,
		onnext,
	}: {
		lanIface: string;
		lanIp: string;
		subnetMask: string;
		domainName: string;
		dhcpV4Enabled: boolean;
		dhcpPoolStart: string;
		dhcpPoolEnd: string;
		dhcpRouter: string;
		dhcpV6Enabled: boolean;
		dhcpV6PoolRange: string;
		raEnabled: boolean;
		raAutoGua: boolean;
		raAutoUla: boolean;
		raCustomUla: boolean;
		raUlaPrefix: string;
		dnsPreset: "quad9" | "cloudflare" | "google" | "custom";
		customDnsServers: string;
		adblockEnabled: boolean;
		selectedAdblockPresets: string[];
		interfaces: NetworkInterfaceInfo[];
		onLanIfaceChange: (name: string) => void;
		onback: () => void;
		onnext: () => void;
	} = $props();

	function togglePreset(id: string) {
		if (selectedAdblockPresets.includes(id)) {
			selectedAdblockPresets = selectedAdblockPresets.filter((p) => p !== id);
		} else {
			selectedAdblockPresets = [...selectedAdblockPresets, id];
		}
	}
</script>

<Card.Header>
	<div class="flex items-center gap-3">
		<div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
			<NetworkIcon class="h-5 w-5" />
		</div>
		<div>
			<Card.Title>LAN Subnet, DHCP, RA & DNS</Card.Title>
			<Card.Description>Configure local address pools, IPv6 SLAAC, and DNS resolver.</Card.Description>
		</div>
	</div>
</Card.Header>

<Card.Content class="space-y-4">
	<!-- Interface & Addressing -->
	<div class="space-y-1.5">
		<Label for="lan_iface">LAN Interface (Local Network)</Label>
		<select
			id="lan_iface"
			class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background"
			value={lanIface}
			onchange={(e) => onLanIfaceChange((e.target as HTMLSelectElement).value)}
		>
			{#each interfaces as iface}
				<option value={iface.name}>
					{iface.name} ({iface.bus_type} - {iface.carrier_up ? '🟢 Cable Connected' : '⚪ Disconnected'} {iface.ips[0] ? `[${iface.ips[0]}]` : ''})
				</option>
			{/each}
		</select>
	</div>

	<div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
		<div class="space-y-1.5">
			<Label for="lan_ip">Lanforge Router IP</Label>
			<Input id="lan_ip" bind:value={lanIp} placeholder="192.168.1.1" onchange={() => (dhcpRouter = lanIp)} />
		</div>
		<div class="space-y-1.5">
			<Label for="subnet_mask">Subnet Mask</Label>
			<Input id="subnet_mask" bind:value={subnetMask} placeholder="255.255.255.0" />
		</div>
		<div class="space-y-1.5">
			<Label for="domain_name">Local Domain</Label>
			<Input id="domain_name" bind:value={domainName} placeholder="lan" />
		</div>
	</div>

	<Separator class="my-2" />

	<!-- DHCPv4 Server Card -->
	<div class="rounded-lg border bg-muted/20 p-3.5 space-y-3">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<ServerIcon class="h-4 w-4 text-emerald-400" />
				<div>
					<h5 class="text-sm font-semibold text-foreground">DHCPv4 Server</h5>
					<p class="text-xs text-muted-foreground">Dynamic IPv4 address assignment for local clients.</p>
				</div>
			</div>
			<Switch bind:checked={dhcpV4Enabled} />
		</div>

		{#if dhcpV4Enabled}
			<div class="grid grid-cols-1 gap-3 sm:grid-cols-3 pt-2 border-t">
				<div class="space-y-1.5">
					<Label for="pool_start" class="text-xs">Pool Start</Label>
					<Input id="pool_start" class="h-8 text-xs font-mono" bind:value={dhcpPoolStart} placeholder="192.168.1.100" />
				</div>
				<div class="space-y-1.5">
					<Label for="pool_end" class="text-xs">Pool End</Label>
					<Input id="pool_end" class="h-8 text-xs font-mono" bind:value={dhcpPoolEnd} placeholder="192.168.1.240" />
				</div>
				<div class="space-y-1.5">
					<Label for="dhcp_router" class="text-xs">Default Gateway</Label>
					<Input id="dhcp_router" class="h-8 text-xs font-mono" bind:value={dhcpRouter} placeholder="192.168.1.1" />
				</div>
			</div>
		{/if}
	</div>

	<!-- DHCPv6 Server Card -->
	<div class="rounded-lg border bg-muted/20 p-3.5 space-y-3">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<ServerIcon class="h-4 w-4 text-cyan-400" />
				<div>
					<h5 class="text-sm font-semibold text-foreground">DHCPv6 Server (RFC 8415)</h5>
					<p class="text-xs text-muted-foreground">Stateful IPv6 address delegation and DNS announcement.</p>
				</div>
			</div>
			<Switch bind:checked={dhcpV6Enabled} />
		</div>

		{#if dhcpV6Enabled}
			<div class="space-y-1.5 pt-2 border-t text-xs">
				<Label for="v6_range" class="text-xs">Dynamic Allocation Range (Suffix Suffix or CIDR)</Label>
				<Input id="v6_range" class="h-8 text-xs font-mono" bind:value={dhcpV6PoolRange} placeholder="::100-::1fff" />
				<p class="text-[11px] text-muted-foreground">
					Standard suffix scope announced over UDP 547. Dynamically combined with active LAN ULA or GUA prefixes.
				</p>
			</div>
		{/if}
	</div>

	<!-- IPv6 Router Advertisement (RA) Card -->
	<div class="rounded-lg border bg-muted/20 p-3.5 space-y-3">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<RadioIcon class="h-4 w-4 text-purple-400" />
				<div>
					<h5 class="text-sm font-semibold text-foreground">IPv6 Router Advertisement (SLAAC)</h5>
					<p class="text-xs text-muted-foreground">Autonomous IPv6 configuration announced via ICMPv6 periodic router beacons.</p>
				</div>
			</div>
			<Switch bind:checked={raEnabled} />
		</div>

		{#if raEnabled}
			<div class="grid grid-cols-1 gap-2 sm:grid-cols-2 pt-2 border-t text-xs">
				<div class="flex items-center justify-between rounded border bg-background/50 p-2">
					<div>
						<p class="font-medium text-foreground">Auto-GUA Delegated Prefix</p>
						<p class="text-muted-foreground">SLAAC for ISP public IPv6 addresses.</p>
					</div>
					<Switch bind:checked={raAutoGua} />
				</div>

				<div class="flex items-center justify-between rounded border bg-background/50 p-2">
					<div>
						<p class="font-medium text-foreground">Auto-ULA Local Prefix</p>
						<p class="text-muted-foreground">Derived dynamically from active interface ULA.</p>
					</div>
					<Switch bind:checked={raAutoUla} />
				</div>
			</div>

			<div class="pt-1">
				<div class="flex items-center justify-between rounded border bg-background/50 p-2">
					<div>
						<p class="font-medium text-foreground">Custom Static ULA Prefix</p>
						<p class="text-muted-foreground">Override dynamic auto-discovery with a fixed /64 prefix.</p>
					</div>
					<Switch bind:checked={raCustomUla} />
				</div>

				{#if raCustomUla}
					<div class="space-y-1 pt-2">
						<Label for="ra_prefix" class="text-xs">Custom ULA Prefix (RFC 4193)</Label>
						<Input id="ra_prefix" class="h-8 text-xs font-mono" bind:value={raUlaPrefix} placeholder="fdxx:xxxx:xxxx:xxxx::/64" />
						<p class="text-[11px] text-muted-foreground">
							Requires a valid /64 prefix length (e.g. <code class="font-mono text-foreground">fd12:3456:789a:1::/64</code>).
						</p>
					</div>
				{/if}
			</div>
		{/if}
	</div>

	<!-- Upstream DNS Resolvers -->
	<div class="rounded-lg border bg-muted/20 p-3.5 space-y-2.5">
		<div class="flex items-center justify-between">
			<div>
				<h5 class="text-sm font-semibold text-foreground">Upstream DNS Resolvers</h5>
				<p class="text-xs text-muted-foreground">Secure upstream DNS forwarding servers for external domain queries.</p>
			</div>
			<Badge variant="outline">{dnsPreset.toUpperCase()}</Badge>
		</div>

		<div class="grid grid-cols-2 gap-2 sm:grid-cols-4 pt-1">
			<button
				type="button"
				class="rounded-md border py-1.5 text-xs font-medium transition-colors {dnsPreset === 'quad9' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
				onclick={() => (dnsPreset = "quad9")}
			>
				Quad9 (Default)
			</button>
			<button
				type="button"
				class="rounded-md border py-1.5 text-xs font-medium transition-colors {dnsPreset === 'cloudflare' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
				onclick={() => (dnsPreset = "cloudflare")}
			>
				Cloudflare
			</button>
			<button
				type="button"
				class="rounded-md border py-1.5 text-xs font-medium transition-colors {dnsPreset === 'google' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
				onclick={() => (dnsPreset = "google")}
			>
				Google
			</button>
			<button
				type="button"
				class="rounded-md border py-1.5 text-xs font-medium transition-colors {dnsPreset === 'custom' ? 'border-primary bg-primary/10 text-primary' : 'bg-background hover:bg-muted'}"
				onclick={() => (dnsPreset = "custom")}
			>
				Custom
			</button>
		</div>

		{#if dnsPreset === "quad9"}
			<div class="rounded border bg-background/50 p-2.5 space-y-1.5 text-xs">
				<div class="flex items-center justify-between text-muted-foreground">
					<span class="font-medium text-foreground">Quad9 Dual-Stack Anycast (4 Resolvers)</span>
					<Badge variant="secondary" class="text-[10px] px-1.5 py-0">Malware Filter + DNSSEC</Badge>
				</div>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
					<div class="flex items-center gap-1.5">
						<span class="px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 font-sans text-[10px] font-semibold">IPv4</span>
						<span>9.9.9.9, 149.112.112.112</span>
					</div>
					<div class="flex items-center gap-1.5">
						<span class="px-1 py-0.5 rounded bg-purple-500/10 text-purple-400 font-sans text-[10px] font-semibold">IPv6</span>
						<span>2620:fe::fe, 2620:fe::9</span>
					</div>
				</div>
			</div>
		{:else if dnsPreset === "cloudflare"}
			<div class="rounded border bg-background/50 p-2.5 space-y-1.5 text-xs">
				<div class="flex items-center justify-between text-muted-foreground">
					<span class="font-medium text-foreground">Cloudflare 1.1.1.1 (4 Resolvers)</span>
					<Badge variant="secondary" class="text-[10px] px-1.5 py-0">Ultra-Fast + Privacy</Badge>
				</div>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
					<div class="flex items-center gap-1.5">
						<span class="px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 font-sans text-[10px] font-semibold">IPv4</span>
						<span>1.1.1.1, 1.0.0.1</span>
					</div>
					<div class="flex items-center gap-1.5">
						<span class="px-1 py-0.5 rounded bg-purple-500/10 text-purple-400 font-sans text-[10px] font-semibold">IPv6</span>
						<span>2606:4700:4700::1111, 2606:4700:4700::1001</span>
					</div>
				</div>
			</div>
		{:else if dnsPreset === "google"}
			<div class="rounded border bg-background/50 p-2.5 space-y-1.5 text-xs">
				<div class="flex items-center justify-between text-muted-foreground">
					<span class="font-medium text-foreground">Google Public DNS (4 Resolvers)</span>
					<Badge variant="secondary" class="text-[10px] px-1.5 py-0">Worldwide Anycast</Badge>
				</div>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
					<div class="flex items-center gap-1.5">
						<span class="px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 font-sans text-[10px] font-semibold">IPv4</span>
						<span>8.8.8.8, 8.8.4.4</span>
					</div>
					<div class="flex items-center gap-1.5">
						<span class="px-1 py-0.5 rounded bg-purple-500/10 text-purple-400 font-sans text-[10px] font-semibold">IPv6</span>
						<span>2001:4860:4860::8888, 2001:4860:4860::8844</span>
					</div>
				</div>
			</div>
		{:else if dnsPreset === "custom"}
			<div class="space-y-1 pt-1">
				<Label for="custom_dns" class="text-xs">Custom DNS Server IPs (Comma separated)</Label>
				<Input id="custom_dns" class="h-8 text-xs font-mono" bind:value={customDnsServers} placeholder="1.1.1.1, 8.8.8.8, 2620:fe::fe" />
				<p class="text-[11px] text-muted-foreground">
					Specify IPv4 and/or IPv6 upstream resolver addresses.
				</p>
			</div>
		{/if}
	</div>

	<!-- Built-in DNS Adblocker Card with Presets -->
	<div class="rounded-lg border bg-muted/20 p-3.5 space-y-3">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<ShieldIcon class="h-4 w-4 text-emerald-400" />
				<div>
					<h5 class="text-sm font-semibold text-foreground">Built-in DNS Adblocker</h5>
					<p class="text-xs text-muted-foreground">Block ads, trackers, and telemetry network-wide via Lanforge DNS.</p>
				</div>
			</div>
			<Switch bind:checked={adblockEnabled} />
		</div>

		{#if adblockEnabled}
			<div class="space-y-2 pt-2 border-t">
				<div class="flex items-center justify-between">
					<span class="text-xs font-medium text-foreground">Initial Community Filter Lists</span>
					<Badge variant="outline" class="text-[10px]">{selectedAdblockPresets.length} selected</Badge>
				</div>
				<p class="text-[11px] text-muted-foreground">
					Selected community feeds will be downloaded and enforced immediately on first boot.
				</p>

				<div class="grid grid-cols-1 gap-2 pt-1">
					{#each ADBLOCK_PRESET_OPTIONS as preset}
						{@const isSelected = selectedAdblockPresets.includes(preset.id)}
						<button
							type="button"
							class="flex items-center justify-between rounded-lg border p-2.5 text-left transition-colors {isSelected ? 'border-primary/50 bg-primary/10' : 'bg-background hover:bg-muted/40'}"
							onclick={() => togglePreset(preset.id)}
						>
							<div class="space-y-0.5 pr-2">
								<div class="flex items-center gap-2">
									<span class="text-xs font-semibold text-foreground">{preset.title}</span>
									<Badge variant="secondary" class="text-[9px] px-1.5 py-0 font-mono">{preset.badge}</Badge>
								</div>
								<p class="text-[11px] text-muted-foreground">{preset.description}</p>
							</div>
							<div class="flex h-5 w-5 shrink-0 items-center justify-center rounded border {isSelected ? 'bg-primary border-primary text-primary-foreground' : 'border-input bg-background'}">
								{#if isSelected}
									<CheckIcon class="h-3.5 w-3.5" />
								{/if}
							</div>
						</button>
					{/each}
				</div>
			</div>
		{/if}
	</div>
</Card.Content>

<Card.Footer class="flex justify-between">
	<Button variant="outline" onclick={onback} class="gap-2">
		<ArrowLeftIcon class="h-4 w-4" />
		Back
	</Button>
	<Button onclick={onnext} class="gap-2">
		Next: Firewall & Security
		<ArrowRightIcon class="h-4 w-4" />
	</Button>
</Card.Footer>
