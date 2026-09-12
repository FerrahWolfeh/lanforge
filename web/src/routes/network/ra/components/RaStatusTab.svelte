<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import { Badge } from "$lib/components/ui/badge";
	import { Label } from "$lib/components/ui/label";
	import { Separator } from "$lib/components/ui/separator";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import type { RaStatusResponse, RaPrefix } from "$lib/api/types";

	let {
		status = null,
	}: {
		status?: RaStatusResponse | null;
	} = $props();

	function getPrefixKey(pref: RaPrefix, i: number): string {
		return `${i}-${pref.source}-${pref.address || "none"}-${pref.prefix_len || 64}`;
	}

	function formatLifetime(sec: string | number | null | undefined): string {
		if (sec === null || sec === undefined) return "Infinity";
		const num = typeof sec === "string" ? Number(sec) : sec;
		if (isNaN(num)) return String(sec);
		if (num === 0) return "0s (Expired)";
		if (num < 60) return `${num}s`;
		if (num < 3600) return `${Math.floor(num / 60)}m`;
		const h = Math.floor(num / 3600);
		if (h < 48) return `${h}h`;
		return `${Math.floor(h / 24)}d`;
	}
</script>

<div class="flex flex-col gap-6">
	<!-- Active Advertised Prefixes -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<Card.Title class="text-base flex items-center justify-between">
				<span class="flex items-center gap-2">
					<GlobeIcon class="size-4 text-primary" />
					Active Advertised Prefixes
				</span>
				<Badge variant="outline" class="font-normal text-xs font-mono">
					{(status?.prefixes ?? []).length} Announced
				</Badge>
			</Card.Title>
			<Card.Description class="text-xs">
				Autonomous SLAAC prefixes and on-link routing prefixes broadcast to LAN hosts.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-0">
			{#if (status?.prefixes ?? []).length === 0}
				<div class="p-8 text-center text-muted-foreground text-sm flex flex-col items-center justify-center gap-2">
					<AlertCircleIcon class="size-8 text-muted-foreground/50" />
					<span>No prefixes actively advertised. Check configuration or delegated WAN IPv6 state.</span>
				</div>
			{:else}
				<div class="overflow-x-auto">
					<Table.Root class="min-w-[600px]">
						<Table.Header class="bg-muted/50">
							<Table.Row>
								<Table.Head>Prefix Subnet</Table.Head>
								<Table.Head class="w-[130px]">SLAAC (A-Flag)</Table.Head>
								<Table.Head class="w-[130px]">On-Link (L-Flag)</Table.Head>
								<Table.Head class="w-[120px]">Valid Lifetime</Table.Head>
								<Table.Head class="w-[130px]">Preferred Lifetime</Table.Head>
							</Table.Row>
						</Table.Header>
						<Table.Body class="font-mono text-xs">
							{#each status?.prefixes ?? [] as pref, i (getPrefixKey(pref, i))}
								<Table.Row>
									<Table.Cell class="font-medium">
										{#if pref.source === "auto_gua"}
											<div class="flex items-center gap-1.5">
												<span class="text-emerald-400">
													{status?.active_gua_prefix
														? `${status.active_gua_prefix}/${pref.prefix_len || 64}`
														: "auto_gua"}
												</span>
												<Badge variant="secondary" class="text-[9px] px-1 py-0 font-normal">GUA</Badge>
											</div>
										{:else if pref.source === "ula"}
											<div class="flex items-center gap-1.5">
												<span class="text-sky-400">
													{pref.address
														? `${pref.address}/${pref.prefix_len || 64}`
														: status?.active_ula_prefix
															? `${status.active_ula_prefix}/${pref.prefix_len || 64}`
															: "ula"}
												</span>
												<Badge variant="secondary" class="text-[9px] px-1 py-0 font-normal">ULA</Badge>
											</div>
										{:else}
											<div class="flex items-center gap-1.5">
												<span>
													{pref.address
														? `${pref.address}/${pref.prefix_len || 64}`
														: `${pref.source} (/${pref.prefix_len || 64})`}
												</span>
												<Badge variant="outline" class="text-[9px] px-1 py-0 font-normal capitalize">
													{pref.source}
												</Badge>
											</div>
										{/if}
									</Table.Cell>

									<Table.Cell class="font-sans">
										{#if pref.autonomous ?? true}
											<Badge variant="outline" class="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 text-xs">
												Enabled (A=1)
											</Badge>
										{:else}
											<Badge variant="secondary" class="text-xs">Disabled (A=0)</Badge>
										{/if}
									</Table.Cell>

									<Table.Cell class="font-sans">
										{#if pref.on_link ?? true}
											<Badge variant="outline" class="bg-blue-500/10 text-blue-600 border-blue-500/20 text-xs">
												On-Link (L=1)
											</Badge>
										{:else}
											<Badge variant="secondary" class="text-xs">Off-Link (L=0)</Badge>
										{/if}
									</Table.Cell>

									<Table.Cell class="text-muted-foreground">
										{formatLifetime(pref.valid_lifetime)}
									</Table.Cell>

									<Table.Cell class="text-muted-foreground">
										{formatLifetime(pref.preferred_lifetime)}
									</Table.Cell>
								</Table.Row>
							{/each}
						</Table.Body>
					</Table.Root>
				</div>
			{/if}

			{#if (status?.deprecated_prefixes ?? []).length > 0}
				<div class="m-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/20 flex flex-col gap-1.5">
					<div class="flex items-center gap-2 text-amber-600 font-semibold text-xs">
						<AlertCircleIcon class="size-4" />
						<span>Deprecated Prefixes (RFC 9096 Graceful Invalidation)</span>
					</div>
					<p class="text-[11px] text-amber-700 dark:text-amber-400">
						Obsolete prefixes broadcast with Preferred Lifetime = 0 to rapidly revoke them from client routing tables:
					</p>
					<div class="flex flex-wrap gap-1.5 pt-1">
						{#each status?.deprecated_prefixes ?? [] as [pfx, remaining], i (`deprecated-${i}-${pfx}`)}
							<Badge variant="outline" class="font-mono text-[11px] border-amber-500/30 text-amber-600 bg-background">
								{pfx} ({remaining}s remaining)
							</Badge>
						{/each}
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- DNS & Timing Parameters Grid -->
	<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
		<!-- Card: RDNSS and DNSSL -->
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<Card.Title class="text-base flex items-center gap-2">
					<ServerIcon class="size-4 text-primary" />
					DNS Options Announced (RFC 8106)
				</Card.Title>
				<Card.Description class="text-xs">
					Recursive DNS servers (RDNSS) and search lists (DNSSL) distributed in RA packets.
				</Card.Description>
			</Card.Header>

			<Card.Content class="p-4 flex flex-col gap-4">
				<div class="flex flex-col gap-2">
					<Label class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
						RDNSS Servers
					</Label>
					{#if (status?.rdnss ?? []).flatMap((r) => r.servers || []).length === 0}
						<span class="text-xs text-muted-foreground italic">
							None configured (clients fall back to local link-local or DHCPv6)
						</span>
					{:else}
						<div class="flex flex-wrap gap-1.5">
							{#each (status?.rdnss ?? []).flatMap((r) => r.servers || []) as addr, i (`rdnss-${i}-${addr}`)}
								<Badge variant="secondary" class="font-mono text-xs">
									{addr}
								</Badge>
							{/each}
						</div>
					{/if}
				</div>

				<Separator />

				<div class="flex flex-col gap-2">
					<Label class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
						DNSSL Search Domains
					</Label>
					{#if (status?.dnssl ?? []).flatMap((d) => d.domains || []).length === 0}
						<span class="text-xs text-muted-foreground italic">None configured</span>
					{:else}
						<div class="flex flex-wrap gap-1.5">
							{#each (status?.dnssl ?? []).flatMap((d) => d.domains || []) as domain, i (`dnssl-${i}-${domain}`)}
								<Badge variant="outline" class="text-xs">
									{domain}
								</Badge>
							{/each}
						</div>
					{/if}
				</div>
			</Card.Content>
		</Card.Root>

		<!-- Card: Active Protocol Parameters -->
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<Card.Title class="text-base flex items-center gap-2">
					<SlidersIcon class="size-4 text-primary" />
					Protocol Parameters
				</Card.Title>
				<Card.Description class="text-xs">
					Timing intervals, hop limit, and router priority currently enforced by daemon.
				</Card.Description>
			</Card.Header>

			<Card.Content class="p-4 flex flex-col gap-2.5 text-xs">
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground">Managed Flag (M):</span>
					<Badge variant={status?.managed ? "default" : "secondary"}>
						{status?.managed ? "True (DHCPv6)" : "False (SLAAC)"}
					</Badge>
				</div>
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground">Other Config Flag (O):</span>
					<Badge variant={status?.other_config ? "default" : "secondary"}>
						{status?.other_config ? "True (Stateless DHCPv6)" : "False"}
					</Badge>
				</div>
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground">Router Priority:</span>
					<Badge variant="outline" class="capitalize font-mono">
						{status?.priority ?? "medium"}
					</Badge>
				</div>
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground">Adv. Interval Range:</span>
					<span class="font-mono">{status?.min_interval_secs ?? 66}s – {status?.max_interval_secs ?? 200}s</span>
				</div>
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground">Default Router Lifetime:</span>
					<span class="font-mono">{status?.router_lifetime_secs ?? 600}s</span>
				</div>
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground">Current Hop Limit:</span>
					<span class="font-mono">{status?.hop_limit ?? 64}</span>
				</div>
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground">Link MTU:</span>
					<span class="font-mono">{status?.mtu ?? "Unspecified (Interface MTU)"}</span>
				</div>
			</Card.Content>
		</Card.Root>
	</div>
</div>
