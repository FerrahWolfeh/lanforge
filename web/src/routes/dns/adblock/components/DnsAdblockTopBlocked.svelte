<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import { toast } from "svelte-sonner";
	import { dnsAllow } from "$lib/api/client";
	import type { TopClientEntry, TopDomainEntry } from "$lib/api/types";

	let {
		loading = false,
		topBlockedDomains = [],
		topBlockedClients = [],
		onAllowedDomain = (domain: string) => {},
	}: {
		loading?: boolean;
		topBlockedDomains?: TopDomainEntry[];
		topBlockedClients?: TopClientEntry[];
		onAllowedDomain?: (domain: string) => void;
	} = $props();

	let copiedDomain = $state<string | null>(null);

	async function copyText(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copiedDomain = text;
			toast.success(`Copied "${text}" to clipboard`);
			setTimeout(() => {
				copiedDomain = null;
			}, 2000);
		} catch {
			toast.error("Failed to copy to clipboard");
		}
	}

	async function handleAllow(domain: string) {
		try {
			await dnsAllow(domain);
			toast.success(`Whitelisted domain: ${domain}`);
			onAllowedDomain(domain);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to allow domain");
		}
	}

	const maxDomainCount = $derived.by(() => {
		if (topBlockedDomains.length === 0) return 1;
		return Math.max(1, ...topBlockedDomains.map((d) => d.count));
	});

	const maxClientCount = $derived.by(() => {
		if (topBlockedClients.length === 0) return 1;
		return Math.max(1, ...topBlockedClients.map((c) => c.count));
	});
</script>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
	<!-- Top Blocked Domains -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<ShieldAlertIcon class="size-4 text-rose-500" />
					<Card.Title class="text-base">Top Blocked Domains</Card.Title>
				</div>
				<span class="text-xs text-muted-foreground font-mono">
					{topBlockedDomains.length} domains
				</span>
			</div>
			<Card.Description class="text-xs">
				Most frequently intercepted ad-serving, tracking, and malware domains.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-0">
			{#if loading && topBlockedDomains.length === 0}
				<div class="p-4 flex flex-col gap-3">
					{#each Array(5) as _}
						<div class="flex items-center justify-between">
							<Skeleton class="h-4 w-44" />
							<Skeleton class="h-4 w-16" />
						</div>
					{/each}
				</div>
			{:else if topBlockedDomains.length === 0}
				<div class="p-8 text-center text-sm text-muted-foreground">
					No blocked domains recorded yet. Your network is clean!
				</div>
			{:else}
				<div class="divide-y divide-border/50">
					{#each topBlockedDomains as item (item.domain)}
						{@const pct = Math.round((item.count / maxDomainCount) * 100)}
						<div class="flex items-center justify-between p-3.5 hover:bg-muted/40 transition-colors group">
							<div class="flex flex-col gap-1 min-w-0 pr-3 flex-1">
								<div class="flex items-center gap-2 min-w-0">
									<span class="font-mono text-xs font-semibold truncate text-foreground" title={item.domain}>
										{item.domain}
									</span>
									<button
										type="button"
										onclick={() => copyText(item.domain)}
										class="opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-foreground"
										title="Copy domain"
									>
										{#if copiedDomain === item.domain}
											<CheckIcon class="size-3 text-emerald-500" />
										{:else}
											<CopyIcon class="size-3" />
										{/if}
									</button>
								</div>
								<div class="w-full bg-muted/60 rounded-full h-1 overflow-hidden">
									<div class="bg-rose-500 h-1 rounded-full" style="width: {pct}%"></div>
								</div>
							</div>

							<div class="flex items-center gap-3 shrink-0">
								<Badge variant="secondary" class="font-mono text-xs">
									{item.count.toLocaleString()} hits
								</Badge>

								<Button
									variant="ghost"
									size="sm"
									onclick={() => handleAllow(item.domain)}
									class="h-7 px-2 text-xs gap-1 text-emerald-600 hover:text-emerald-500 hover:bg-emerald-500/10"
									title="Add to Allowlist"
								>
									<ShieldCheckIcon class="size-3.5" />
									Allow
								</Button>
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Top Blocked Clients -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<LaptopIcon class="size-4 text-primary" />
					<Card.Title class="text-base">Top Blocked Clients</Card.Title>
				</div>
				<span class="text-xs text-muted-foreground font-mono">
					{topBlockedClients.length} clients
				</span>
			</div>
			<Card.Description class="text-xs">
				Devices on your LAN requesting the highest volume of blocked queries.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-0">
			{#if loading && topBlockedClients.length === 0}
				<div class="p-4 flex flex-col gap-3">
					{#each Array(5) as _}
						<div class="flex items-center justify-between">
							<Skeleton class="h-4 w-44" />
							<Skeleton class="h-4 w-16" />
						</div>
					{/each}
				</div>
			{:else if topBlockedClients.length === 0}
				<div class="p-8 text-center text-sm text-muted-foreground">
					No client blocking statistics recorded yet.
				</div>
			{:else}
				<div class="divide-y divide-border/50">
					{#each topBlockedClients as client (client.ip)}
						{@const pct = Math.round((client.count / maxClientCount) * 100)}
						<div class="flex items-center justify-between p-3.5 hover:bg-muted/40 transition-colors">
							<div class="flex flex-col gap-1 min-w-0 pr-3 flex-1">
								<div class="flex items-center gap-2 min-w-0">
									<span class="text-xs font-semibold truncate text-foreground">
										{client.hostname || client.ip}
									</span>
									{#if client.hostname}
										<span class="text-[11px] font-mono text-muted-foreground">
											({client.ip})
										</span>
									{/if}
								</div>
								<div class="w-full bg-muted/60 rounded-full h-1 overflow-hidden">
									<div class="bg-primary h-1 rounded-full" style="width: {pct}%"></div>
								</div>
							</div>

							<div class="flex items-center gap-2 shrink-0">
								<Badge variant="outline" class="font-mono text-xs">
									{client.count.toLocaleString()} blocks
								</Badge>
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
