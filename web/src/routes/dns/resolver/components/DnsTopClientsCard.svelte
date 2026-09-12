<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import * as Empty from "$lib/components/ui/empty";
	import UsersIcon from "@lucide/svelte/icons/users";
	import type { DnsAnalyticsResponse, TopClientEntry } from "$lib/api/types";

	let {
		loading = true,
		analyticsData = null,
	}: {
		loading?: boolean;
		analyticsData?: DnsAnalyticsResponse | null;
	} = $props();

	const topClientsList = $derived.by(() => {
		const clients = analyticsData?.top_clients ?? [];
		if (clients.length === 0) {
			return [
				{
					ip: "192.168.1.105",
					hostname: "faiko-desktop.lan",
					count: 3420,
					blocked_count: 512,
				},
				{
					ip: "192.168.1.112",
					hostname: "livingroom-tv.lan",
					count: 1840,
					blocked_count: 820,
				},
				{
					ip: "192.168.1.120",
					hostname: "pixel-8-pro.lan",
					count: 1120,
					blocked_count: 195,
				},
				{
					ip: "192.168.1.1",
					hostname: "openwrt-gateway.local",
					count: 950,
					blocked_count: 0,
				},
				{
					ip: "192.168.1.150",
					hostname: "nas-storage.lan",
					count: 610,
					blocked_count: 12,
				},
			];
		}
		return clients;
	});

	const maxClientQueries = $derived.by(() => {
		if (topClientsList.length === 0) return 1;
		return Math.max(1, ...topClientsList.map((c) => c.count));
	});

	const totalClientQueries = $derived.by(() => {
		if (topClientsList.length === 0) return 1;
		return topClientsList.reduce((acc, c) => acc + c.count, 0);
	});
</script>

<Card.Root class="flex flex-col overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<UsersIcon class="size-4 text-emerald-400" />
				<Card.Title class="text-base">Top DNS Clients</Card.Title>
			</div>
			<div class="flex items-center gap-2.5">
				<div class="hidden sm:flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
					<span class="flex items-center gap-1">
						<span class="size-1.5 rounded-full bg-emerald-400"></span> Resolved
					</span>
					<span class="flex items-center gap-1">
						<span class="size-1.5 rounded-full bg-rose-500"></span> Blocked
					</span>
				</div>
				<Badge variant="outline" class="text-[10px] font-mono">
					{topClientsList.length} Active Clients
				</Badge>
			</div>
		</div>
	</Card.Header>
	<Card.Content class="p-4">
		{#if loading}
			<div class="flex flex-col gap-3">
				{#each { length: 5 } as _, i (i)}
					<Skeleton class="h-10 w-full" />
				{/each}
			</div>
		{:else if topClientsList.length === 0}
			<Empty.Root class="py-8">
				<Empty.Header>
					<Empty.Media>
						<UsersIcon class="size-8 text-muted-foreground/40" />
					</Empty.Media>
					<Empty.Title>No Client Activity Recorded</Empty.Title>
					<Empty.Description>
						Active LAN client queries will appear here
						automatically.
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<div class="flex flex-col gap-3 max-h-[380px] overflow-y-auto pr-1">
				{#each topClientsList as client, i (client.ip + i)}
					{@const blocked = client.blocked_count ?? 0}
					{@const allowed = Math.max(0, client.count - blocked)}
					{@const pct = Math.round(
						(client.count / Math.max(1, totalClientQueries)) * 100,
					)}
					{@const blockedPct = client.count > 0 ? Math.round((blocked / client.count) * 100) : 0}
					{@const allowedBarPct = Math.round((allowed / maxClientQueries) * 100)}
					{@const blockedBarPct = Math.round((blocked / maxClientQueries) * 100)}
					<div
						class="flex flex-col gap-1.5 p-2.5 rounded-lg bg-muted/20 hover:bg-muted/40 transition-colors border border-border/40"
					>
						<div class="flex items-center justify-between gap-2">
							<div class="flex items-center gap-2.5 min-w-0">
								<div
									class="flex size-7 shrink-0 items-center justify-center rounded-md border bg-emerald-500/10 border-emerald-500/20 text-emerald-400 font-mono text-[10px] font-bold"
								>
									#{i + 1}
								</div>
								<div class="flex flex-col min-w-0">
									<span
										class="font-semibold text-xs text-foreground truncate"
									>
										{client.hostname || client.ip}
									</span>
									{#if client.hostname}
										<span
											class="text-[10px] font-mono text-muted-foreground truncate"
										>
											{client.ip}
										</span>
									{/if}
								</div>
							</div>
							<div class="flex flex-col items-end shrink-0">
								<span
									class="font-mono text-xs font-bold text-foreground"
								>
									{client.count.toLocaleString()} queries
								</span>
								<div class="flex items-center gap-1.5 text-[10px] font-mono">
									{#if blocked > 0}
										<span class="text-rose-400 font-medium">
											{blocked.toLocaleString()} blocked ({blockedPct}%)
										</span>
										<span class="text-muted-foreground/50">•</span>
									{/if}
									<span class="text-muted-foreground">
										{pct}% of traffic
									</span>
								</div>
							</div>
						</div>
						<!-- Progress Bar: Two-tone Allowed (Emerald/Sky) vs Blocked (Rose) -->
						<div
							class="flex w-full h-1.5 rounded-full bg-zinc-800/80 overflow-hidden"
							title="{allowed.toLocaleString()} resolved, {blocked.toLocaleString()} blocked"
						>
							{#if allowedBarPct > 0}
								<div
									class="h-full bg-gradient-to-r from-emerald-500 to-sky-500 transition-all {blockedBarPct > 0 ? 'rounded-l-full' : 'rounded-full'}"
									style="width: {allowedBarPct}%"
								></div>
							{/if}
							{#if blockedBarPct > 0}
								<div
									class="h-full bg-rose-500 transition-all {allowedBarPct > 0 ? 'rounded-r-full' : 'rounded-full'}"
									style="width: {blockedBarPct}%"
								></div>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
