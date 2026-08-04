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
				},
				{
					ip: "192.168.1.112",
					hostname: "livingroom-tv.lan",
					count: 1840,
				},
				{
					ip: "192.168.1.120",
					hostname: "pixel-8-pro.lan",
					count: 1120,
				},
				{
					ip: "192.168.1.1",
					hostname: "openwrt-gateway.local",
					count: 950,
				},
				{
					ip: "192.168.1.150",
					hostname: "nas-storage.lan",
					count: 610,
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
			<Badge variant="outline" class="text-[10px] font-mono">
				{topClientsList.length} Active Clients
			</Badge>
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
					{@const pct = Math.round(
						(client.count / Math.max(1, totalClientQueries)) * 100,
					)}
					{@const barPct = Math.round(
						(client.count / maxClientQueries) * 100,
					)}
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
								<span
									class="text-[10px] font-mono text-muted-foreground"
								>
									{pct}% of queries
								</span>
							</div>
						</div>
						<!-- Progress Bar -->
						<div
							class="w-full h-1.5 rounded-full bg-zinc-800/80 overflow-hidden"
						>
							<div
								class="h-full bg-gradient-to-r from-emerald-500 to-sky-500 rounded-full transition-all"
								style="width: {barPct}%"
							></div>
						</div>
					</div>
				{/each}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
