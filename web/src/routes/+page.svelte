<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import { eventFeed } from "$lib/stores/events.svelte";
	import { status, dnsStats, leases, scan } from "$lib/api/client";
	import {
		normalizeServices,
		formatEventPayload,
		type StatusResponse,
		type DnsStatsResponse,
		type DhcpLease,
		type ServiceBanner,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	let statusData = $state<StatusResponse | null>(null);
	let dnsData = $state<DnsStatsResponse | null>(null);
	let leasesData = $state<DhcpLease[] | null>(null);
	let loadingData = $state(true);
	let scanning = $state(false);

	async function loadAll() {
		loadingData = true;
		try {
			const [s, dns, ls] = await Promise.allSettled([
				status(),
				dnsStats(),
				leases(),
			]);
			if (s.status === "fulfilled") statusData = s.value;
			if (dns.status === "fulfilled") dnsData = dns.value;
			if (ls.status === "fulfilled")
				leasesData = Array.isArray(ls.value) ? ls.value : [];
		} finally {
			loadingData = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await scan();
			toast.success("Network scan triggered");
		} catch {
			toast.error("Failed to trigger scan");
		} finally {
			scanning = false;
		}
	}

	onMount(loadAll);

	function formatUptime(secs: number): string {
		const d = Math.floor(secs / 86400);
		const h = Math.floor((secs % 86400) / 3600);
		const m = Math.floor((secs % 3600) / 60);
		if (d > 0) return `${d}d ${h}h`;
		if (h > 0) return `${h}h ${m}m`;
		return `${m}m`;
	}

	const serviceList = $derived(normalizeServices(statusData));

	const stateVariant = (state: string) => {
		if (state === "active") return "default";
		if (state === "starting") return "secondary";
		return "destructive";
	};

	const recentEvents = $derived(eventFeed.events.slice(0, 12));

	const statCards = $derived([
		{
			label: "Uptime",
			value: statusData ? formatUptime(statusData.uptime_secs) : null,
			icon: ZapIcon,
			color: "text-green-400",
		},
		{
			label: "DNS Queries",
			value: dnsData ? dnsData.total_requests.toLocaleString() : null,
			icon: GlobeIcon,
			color: "text-blue-400",
		},
		{
			label: "Blocked",
			value: dnsData ? dnsData.blocked_queries.toLocaleString() : null,
			icon: ShieldIcon,
			color: "text-rose-400",
		},
		{
			label: "DHCP Leases",
			value: leasesData ? leasesData.length.toString() : null,
			icon: NetworkIcon,
			color: "text-teal-400",
		},
	]);

	const kindColors: Record<string, string> = {
		DeviceOnline: "text-green-400",
		DeviceOffline: "text-red-400",
		DhcpLeaseGranted: "text-teal-400",
		DhcpLeaseReleased: "text-yellow-400",
		DnsBlocked: "text-rose-400",
		AdblockToggled: "text-purple-400",
		ScanCompleted: "text-cyan-400",
	};

	function kindColor(kind: string) {
		return kindColors[kind] ?? "text-muted-foreground";
	}

	function formatTs(ts: number): string {
		return new Date(ts).toLocaleTimeString(undefined, {
			hour12: false,
			timeStyle: "short",
		});
	}
</script>

<svelte:head>
	<title>Dashboard — Lanforge</title>
</svelte:head>

<div class="flex items-center justify-between">
	<div>
		<h1 class="text-foreground text-2xl font-bold tracking-tight">
			Dashboard
		</h1>
		<p class="text-muted-foreground text-sm">Network at a glance</p>
	</div>
	<div class="flex items-center gap-2">
		<Button
			variant="outline"
			size="sm"
			onclick={loadAll}
			disabled={loadingData}
		>
			<RefreshCwIcon
				data-icon="inline-start"
				class={loadingData ? "animate-spin" : ""}
			/>
			Refresh
		</Button>
		<Button size="sm" onclick={triggerScan} disabled={scanning}>
			{#if scanning}
				<span
					class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"
					data-icon="inline-start"
				></span>
			{:else}
				<ZapIcon data-icon="inline-start" />
			{/if}
			Scan
		</Button>
	</div>
</div>

<!-- Stat cards -->
<div class="grid grid-cols-2 gap-4 lg:grid-cols-4">
	{#each statCards as card (card.label)}
		<Card.Root>
			<Card.Content class="flex flex-col gap-3 p-5">
				<div class="flex items-center justify-between">
					<span class="text-muted-foreground text-sm font-medium"
						>{card.label}</span
					>
					<card.icon class={["size-4", card.color].join(" ")} />
				</div>
				{#if loadingData || card.value === null}
					<Skeleton class="h-8 w-24" />
				{:else}
					<span
						class="text-foreground text-3xl font-bold tabular-nums"
						>{card.value}</span
					>
				{/if}
			</Card.Content>
		</Card.Root>
	{/each}
</div>

<!-- Bottom two panels -->
<div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
	<!-- Recent events -->
	<Card.Root class="flex flex-col">
		<Card.Header class="pb-3">
			<div class="flex items-center justify-between">
				<Card.Title class="text-base">Recent Events</Card.Title>
				<span
					class={[
						"size-2 rounded-full",
						eventFeed.connected
							? "bg-green-500"
							: "bg-muted-foreground",
					].join(" ")}
				></span>
			</div>
		</Card.Header>
		<Card.Content class="flex flex-1 flex-col gap-1 p-0">
			{#if recentEvents.length === 0}
				<div
					class="text-muted-foreground flex flex-col items-center gap-2 py-10 text-sm"
				>
					<MonitorIcon class="size-8 opacity-30" />
					<span>No events yet</span>
				</div>
			{:else}
				<div class="divide-border divide-y">
					{#each recentEvents as ev (ev.id + ev.ts)}
						<div class="flex items-center gap-3 px-5 py-2.5">
							<span
								class={[
									"text-xs font-semibold",
									kindColor(ev.kind),
								].join(" ")}
							>
								{ev.kind}
							</span>
							<span
								class="text-muted-foreground flex-1 truncate text-xs"
							>
								{formatEventPayload(ev.data)}
							</span>
							<span
								class="text-muted-foreground text-xs tabular-nums"
							>
								{formatTs(ev.ts)}
							</span>
						</div>
					{/each}
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Services status -->
	<Card.Root>
		<Card.Header class="pb-3">
			<Card.Title class="text-base">Services</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-0">
			{#if loadingData}
				{#each { length: 4 } as _, i (i)}
					<div class="flex items-center gap-3 px-5 py-2.5">
						<Skeleton class="h-4 w-24" />
						<Skeleton class="ml-auto h-5 w-16 rounded-full" />
					</div>
				{/each}
			{:else if serviceList.length === 0}
				<div
					class="text-muted-foreground px-5 py-10 text-center text-sm"
				>
					No service data available
				</div>
			{:else}
				<div class="divide-border divide-y">
					{#each serviceList as svc (svc.name)}
						<div class="flex items-center gap-3 px-5 py-2.5">
							<div class="flex flex-1 flex-col">
								<span
									class="text-foreground text-sm font-medium capitalize"
								>
									{svc.name.replace(/_/g, " ")}
								</span>
								{#if svc.uptime_secs > 0}
									<span class="text-muted-foreground text-xs">
										up {formatUptime(svc.uptime_secs)}
									</span>
								{/if}
							</div>
							<Badge
								variant={stateVariant(svc.state)}
								class="capitalize"
							>
								{svc.state}
							</Badge>
						</div>
					{/each}
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
