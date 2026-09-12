<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import NetworkIcon from "@lucide/svelte/icons/network";

	let {
		v4Enabled = $bindable(true),
		v4Router = $bindable("192.168.0.1"),
		v4SubnetMask = $bindable("255.255.255.0"),
		v4DnsStr = $bindable("192.168.0.1"),
		v4DomainName = $bindable(""),
		v4SearchDomainsStr = $bindable(""),
		v4NtpStr = $bindable("162.159.200.1, 216.239.35.0"),
		v4LeaseTime = $bindable(86400),
		subnetInfo = { valid: true, cidr: "/24", totalHosts: 256, usableHosts: 254 },
		humanLeaseDuration = "24 hours",
	}: {
		v4Enabled?: boolean;
		v4Router?: string;
		v4SubnetMask?: string;
		v4DnsStr?: string;
		v4DomainName?: string;
		v4SearchDomainsStr?: string;
		v4NtpStr?: string;
		v4LeaseTime?: number;
		subnetInfo?: { valid: boolean; cidr: string; totalHosts: number; usableHosts: number };
		humanLeaseDuration?: string;
	} = $props();
</script>

<Card.Root class="border-border/80 shadow-sm overflow-hidden">
	<Card.Header class="bg-muted/20 border-b pb-4">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2.5">
				<NetworkIcon class="size-5 text-blue-500" />
				<div>
					<Card.Title class="text-base font-bold">IPv4 Network Parameters</Card.Title>
					<Card.Description class="text-xs">
						Core DHCPv4 options advertised to all dynamic leases (RFC 2132)
					</Card.Description>
				</div>
			</div>

			<div class="flex items-center gap-2">
				<Label for="v4-enable-toggle" class="text-xs font-medium cursor-pointer">DHCPv4 Service</Label>
				<Switch id="v4-enable-toggle" bind:checked={v4Enabled} />
			</div>
		</div>
	</Card.Header>

	<Card.Content class={["p-4 sm:p-6 flex flex-col gap-6", !v4Enabled && "opacity-50 pointer-events-none"].filter(Boolean).join(" ")}>
		<!-- Highlighted: Default Gateway (Option 3) -->
		<div class="p-4 rounded-xl border border-primary/20 bg-primary/[0.03] flex flex-col gap-3">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<Label for="v4-router" class="text-sm font-bold text-foreground">
						Default Gateway (Option 3 — Router)
					</Label>
					{#if v4Router.trim()}
						<Badge variant="outline" class="text-[10px] text-emerald-500 border-emerald-500/30 bg-emerald-500/10 font-mono">
							Active Gateway
						</Badge>
					{:else}
						<Badge variant="outline" class="text-[10px] text-amber-500 border-amber-500/30 bg-amber-500/10 font-mono">
							Not Advertised
						</Badge>
					{/if}
				</div>
			</div>

			<div class="flex flex-col sm:flex-row gap-3">
				<div class="flex-1">
					<Input
						id="v4-router"
						bind:value={v4Router}
						placeholder="e.g. 10.0.0.1 or 192.168.1.1"
						class="font-mono text-sm font-semibold h-10 border-primary/30 focus-visible:ring-primary"
					/>
				</div>
			</div>
			<p class="text-xs text-muted-foreground">
				This IP is advertised to all DHCP clients as their default router. Clients send all default/internet traffic through this address.
			</p>
		</div>

		<!-- Subnet Mask (Option 1) with CIDR calculation & quick presets -->
		<div class="flex flex-col gap-2.5">
			<div class="flex items-center justify-between">
				<Label for="v4-subnet-mask" class="text-xs font-semibold">
					Subnet Mask (Option 1)
				</Label>
				{#if subnetInfo.valid}
					<span class="text-xs font-mono font-medium text-primary">
						{subnetInfo.cidr} · {subnetInfo.usableHosts.toLocaleString()} usable hosts
					</span>
				{/if}
			</div>

			<div class="flex flex-col sm:flex-row gap-3">
				<Input
					id="v4-subnet-mask"
					bind:value={v4SubnetMask}
					placeholder="255.255.252.0"
					class="font-mono text-xs sm:w-64"
				/>

				<!-- Quick Presets -->
				<div class="flex flex-wrap items-center gap-1.5">
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9 px-2.5"
						onclick={() => (v4SubnetMask = "255.255.255.0")}
					>
						/24 (255.255.255.0)
					</Button>
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9 px-2.5 font-medium border-primary/30"
						onclick={() => (v4SubnetMask = "255.255.252.0")}
					>
						/22 (255.255.252.0)
					</Button>
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9 px-2.5"
						onclick={() => (v4SubnetMask = "255.255.254.0")}
					>
						/23 (255.255.254.0)
					</Button>
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9 px-2.5"
						onclick={() => (v4SubnetMask = "255.255.0.0")}
					>
						/16 (255.255.0.0)
					</Button>
				</div>
			</div>
			<p class="text-xs text-muted-foreground">
				Broadcasted network mask. For a /22 subnet, use <code class="font-mono text-primary font-semibold">255.255.252.0</code> (1,022 usable host addresses).
			</p>
		</div>

		<Separator />

		<!-- DNS & Domains -->
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			<div class="flex flex-col gap-1.5">
				<Label for="v4-dns" class="text-xs font-semibold">DNS Resolvers (Option 6)</Label>
				<Input
					id="v4-dns"
					bind:value={v4DnsStr}
					placeholder="192.168.0.1, 1.1.1.1"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Comma-separated list of IPv4 DNS servers.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v4-domain" class="text-xs font-semibold">Local Domain Name (Option 15)</Label>
				<Input
					id="v4-domain"
					bind:value={v4DomainName}
					placeholder="lan, home.arpa"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Appended to unqualified hostnames on the link.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v4-search" class="text-xs font-semibold">Domain Search List (Option 119)</Label>
				<Input
					id="v4-search"
					bind:value={v4SearchDomainsStr}
					placeholder="lan, internal.corp"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Comma-separated list of search domain suffixes.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v4-ntp" class="text-xs font-semibold">NTP Time Servers (Option 42)</Label>
				<Input
					id="v4-ntp"
					bind:value={v4NtpStr}
					placeholder="162.159.200.1, 216.239.35.0"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					NTP time synchronization IPs for network clients.
				</p>
			</div>
		</div>

		<Separator />

		<!-- Default Lease Lifetime -->
		<div class="flex flex-col gap-2.5">
			<div class="flex items-center justify-between">
				<Label for="v4-lease-time" class="text-xs font-semibold">Default Lease Duration (Seconds)</Label>
				<span class="text-xs font-medium text-emerald-500 font-mono">
					≈ {humanLeaseDuration}
				</span>
			</div>

			<div class="flex flex-col sm:flex-row gap-3">
				<Input
					id="v4-lease-time"
					type="number"
					bind:value={v4LeaseTime}
					placeholder="86400"
					class="font-mono text-xs sm:w-48"
				/>

				<div class="flex flex-wrap items-center gap-1.5">
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9"
						onclick={() => (v4LeaseTime = 43200)}
					>
						12h (43200s)
					</Button>
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9"
						onclick={() => (v4LeaseTime = 86400)}
					>
						24h (86400s)
					</Button>
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9"
						onclick={() => (v4LeaseTime = 604800)}
					>
						7d (604800s)
					</Button>
					<Button
						variant="outline"
						size="sm"
						class="text-xs h-9"
						onclick={() => (v4LeaseTime = 2592000)}
					>
						30d (2592000s)
					</Button>
				</div>
			</div>
		</div>
	</Card.Content>
</Card.Root>
