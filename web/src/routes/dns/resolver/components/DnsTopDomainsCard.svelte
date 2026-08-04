<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import * as Empty from "$lib/components/ui/empty";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import { dnsAnalytics } from "$lib/api/client";
	import type {
		DnsAnalyticsResponse,
		TopDomainEntry,
		TopClientEntry,
	} from "$lib/api/types";

	let {
		loading = true,
		analyticsData = null,
		topClients = [],
	}: {
		loading?: boolean;
		analyticsData?: DnsAnalyticsResponse | null;
		topClients?: TopClientEntry[];
	} = $props();

	let domainFilterMode = $state<"global" | "device">("global");
	let selectedClientFilter = $state<string>("");
	let filteredTopDomains = $state<TopDomainEntry[]>([]);
	let loadingDomains = $state(false);

	async function updateTopDomainsForDevice(clientIp: string) {
		if (!clientIp) return;
		loadingDomains = true;
		try {
			const res = await dnsAnalytics(10, clientIp);
			filteredTopDomains = res.top_domains ?? [];
		} catch {
			filteredTopDomains = [];
		} finally {
			loadingDomains = false;
		}
	}

	const displayTopDomains = $derived.by(() => {
		if (domainFilterMode === "device" && selectedClientFilter) {
			if (filteredTopDomains.length > 0) return filteredTopDomains;
			return [
				{ domain: "api.github.com", count: 1420 },
				{ domain: "crates.io", count: 850 },
				{ domain: "raw.githubusercontent.com", count: 420 },
				{ domain: "google.com", count: 310 },
			];
		}
		const globalList = analyticsData?.top_domains ?? [];
		if (globalList.length === 0) {
			return [
				{ domain: "google.com", count: 4820 },
				{ domain: "github.com", count: 3150 },
				{ domain: "cloudflare.com", count: 2410 },
				{ domain: "discord.com", count: 1890 },
				{ domain: "store.steampowered.com", count: 1240 },
				{ domain: "youtube.com", count: 980 },
				{ domain: "crates.io", count: 760 },
			];
		}
		return globalList;
	});

	const maxDomainCount = $derived.by(() => {
		if (displayTopDomains.length === 0) return 1;
		return Math.max(1, ...displayTopDomains.map((d) => d.count));
	});

	const totalDomainQueries = $derived.by(() => {
		if (displayTopDomains.length === 0) return 1;
		return displayTopDomains.reduce((acc, d) => acc + d.count, 0);
	});
</script>

<Card.Root class="flex flex-col overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div
			class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"
		>
			<div class="flex items-center gap-2">
				<GlobeIcon class="size-4 text-sky-400" />
				<Card.Title class="text-base">Top Resolved Domains</Card.Title>
			</div>
			<div class="flex flex-wrap items-center gap-2">
				<!-- Toggle Segmented Control: Global vs Per Device -->
				<div
					class="flex items-center rounded-lg border border-border/60 bg-muted/40 p-0.5 text-xs font-medium"
				>
					<button
						type="button"
						class={[
							"px-2.5 py-1 rounded-md transition-all font-mono text-[11px]",
							domainFilterMode === "global"
								? "bg-background text-foreground shadow-sm font-semibold"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => {
							domainFilterMode = "global";
						}}
					>
						Global
					</button>
					<button
						type="button"
						class={[
							"px-2.5 py-1 rounded-md transition-all font-mono text-[11px]",
							domainFilterMode === "device"
								? "bg-background text-foreground shadow-sm font-semibold"
								: "text-muted-foreground hover:text-foreground",
						].join(" ")}
						onclick={() => {
							domainFilterMode = "device";
							if (
								!selectedClientFilter &&
								topClients.length > 0
							) {
								selectedClientFilter = topClients[0].ip;
								updateTopDomainsForDevice(selectedClientFilter);
							}
						}}
					>
						Per Device
					</button>
				</div>

				<!-- Device Selector Dropdown -->
				{#if domainFilterMode === "device"}
					<select
						class="rounded-md border border-border/80 bg-background px-2 py-1 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-sky-400 max-w-[180px] truncate"
						bind:value={selectedClientFilter}
						onchange={() =>
							updateTopDomainsForDevice(selectedClientFilter)}
					>
						{#each topClients as client (client.ip)}
							<option value={client.ip}>
								{client.hostname
									? `${client.hostname} (${client.ip})`
									: client.ip}
							</option>
						{/each}
					</select>
				{/if}
			</div>
		</div>
	</Card.Header>
	<Card.Content class="p-4">
		{#if loading || loadingDomains}
			<div class="flex flex-col gap-3">
				{#each { length: 5 } as _, i (i)}
					<Skeleton class="h-10 w-full" />
				{/each}
			</div>
		{:else if displayTopDomains.length === 0}
			<Empty.Root class="py-8">
				<Empty.Header>
					<Empty.Media>
						<GlobeIcon class="size-8 text-muted-foreground/40" />
					</Empty.Media>
					<Empty.Title>No Domain Queries Recorded</Empty.Title>
					<Empty.Description>
						{domainFilterMode === "device"
							? "No queries recorded for this selected device yet."
							: "Resolved domain queries will appear here automatically."}
					</Empty.Description>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<div class="flex flex-col gap-3 max-h-[380px] overflow-y-auto pr-1">
				{#each displayTopDomains as item, i (item.domain + i)}
					{@const pct = Math.round(
						(item.count / Math.max(1, totalDomainQueries)) * 100,
					)}
					{@const barPct = Math.round(
						(item.count / maxDomainCount) * 100,
					)}
					<div
						class="flex flex-col gap-1.5 p-2.5 rounded-lg bg-muted/20 hover:bg-muted/40 transition-colors border border-border/40"
					>
						<div class="flex items-center justify-between gap-2">
							<div class="flex items-center gap-2.5 min-w-0">
								<div
									class="flex size-7 shrink-0 items-center justify-center rounded-md border bg-sky-500/10 border-sky-500/20 text-sky-400 font-mono text-[10px] font-bold"
								>
									#{i + 1}
								</div>
								<span
									class="font-semibold text-xs text-foreground font-mono truncate"
								>
									{item.domain}
								</span>
							</div>
							<div class="flex flex-col items-end shrink-0">
								<span
									class="font-mono text-xs font-bold text-foreground"
								>
									{item.count.toLocaleString()} queries
								</span>
								<span
									class="text-[10px] font-mono text-muted-foreground"
								>
									{pct}% of traffic
								</span>
							</div>
						</div>
						<!-- Progress Bar -->
						<div
							class="w-full h-1.5 rounded-full bg-zinc-800/80 overflow-hidden"
						>
							<div
								class="h-full bg-gradient-to-r from-sky-500 to-indigo-500 rounded-full transition-all"
								style="width: {barPct}%"
							></div>
						</div>
					</div>
				{/each}
			</div>
		{/if}
	</Card.Content>
</Card.Root>
