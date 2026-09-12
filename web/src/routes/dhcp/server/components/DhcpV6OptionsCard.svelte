<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import GlobeIcon from "@lucide/svelte/icons/globe";

	let {
		v6Enabled = $bindable(true),
		v6LeaseTime = $bindable(86400),
		v6DnsStr = $bindable(""),
		v6SearchDomainsStr = $bindable(""),
		v6NtpStr = $bindable("time.cloudflare.com, time.google.com"),
	}: {
		v6Enabled?: boolean;
		v6LeaseTime?: number;
		v6DnsStr?: string;
		v6SearchDomainsStr?: string;
		v6NtpStr?: string;
	} = $props();
</script>

<Card.Root class="border-border/80 shadow-sm overflow-hidden">
	<Card.Header class="bg-muted/20 border-b pb-4">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2.5">
				<GlobeIcon class="size-5 text-purple-500" />
				<div>
					<Card.Title class="text-base font-bold">IPv6 Network Parameters</Card.Title>
					<Card.Description class="text-xs">
						Global DHCPv6 options advertised to stateful clients (RFC 8415)
					</Card.Description>
				</div>
			</div>

			<div class="flex items-center gap-2">
				<Label for="v6-enable-toggle" class="text-xs font-medium cursor-pointer">DHCPv6 Service</Label>
				<Switch id="v6-enable-toggle" bind:checked={v6Enabled} />
			</div>
		</div>
	</Card.Header>

	<Card.Content class={["p-4 sm:p-6 flex flex-col gap-6", !v6Enabled && "opacity-50 pointer-events-none"].filter(Boolean).join(" ")}>
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
			<div class="flex flex-col gap-1.5">
				<Label for="v6-dns" class="text-xs font-semibold">DNS Recursive Servers (Option 23)</Label>
				<Input
					id="v6-dns"
					bind:value={v6DnsStr}
					placeholder="fd00::1, 2606:4700:4700::1111"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Comma-separated list of IPv6 recursive DNS servers.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v6-lease" class="text-xs font-semibold">Lease Duration (Seconds)</Label>
				<Input
					id="v6-lease"
					type="number"
					bind:value={v6LeaseTime}
					placeholder="86400"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Valid lifetime for stateful IPv6 leases.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v6-search" class="text-xs font-semibold">Domain Search List (Option 24)</Label>
				<Input
					id="v6-search"
					bind:value={v6SearchDomainsStr}
					placeholder="lan, internal.corp"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					Comma-separated search domains for IPv6 hosts.
				</p>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v6-ntp" class="text-xs font-semibold">NTP Servers (Option 56)</Label>
				<Input
					id="v6-ntp"
					bind:value={v6NtpStr}
					placeholder="time.cloudflare.com, time.google.com"
					class="font-mono text-xs"
				/>
				<p class="text-[11px] text-muted-foreground">
					SNTP/NTP network time servers for IPv6.
				</p>
			</div>
		</div>
	</Card.Content>
</Card.Root>
