<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Field from "$lib/components/ui/field";
	import { Input } from "$lib/components/ui/input";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import {
		dnsStats,
		dnsUpstreams,
		dnsUpstreamAdd,
		dnsUpstreamRemove,
		dnsReverseResolverList,
		dnsReverseResolverAdd,
		dnsReverseResolverRemove,
		dnsAnalytics,
	} from "$lib/api/client";
	import type {
		DnsStatsResponse,
		DnsUpstreamEntry,
		ReverseResolverEntry,
		DnsAnalyticsResponse,
	} from "$lib/api/types";

	// Page Components
	import DnsResolverTopCards from "./components/DnsResolverTopCards.svelte";
	import DnsResolverActivityChart from "./components/DnsResolverActivityChart.svelte";
	import DnsQueryTypesCard from "./components/DnsQueryTypesCard.svelte";
	import DnsTopClientsCard from "./components/DnsTopClientsCard.svelte";
	import DnsTopDomainsCard from "./components/DnsTopDomainsCard.svelte";
	import DnsUpstreamsCard from "./components/DnsUpstreamsCard.svelte";
	import DnsReverseResolversCard from "./components/DnsReverseResolversCard.svelte";
	import DnsDigModal from "./components/DnsDigModal.svelte";
	import DnsTuningModal from "./components/DnsTuningModal.svelte";
	import SlidersIcon from "@lucide/svelte/icons/sliders";

	let statsData = $state<DnsStatsResponse | null>(null);
	let analyticsData = $state<DnsAnalyticsResponse | null>(null);
	let upstreams = $state<DnsUpstreamEntry[]>([]);
	let reverseResolvers = $state<ReverseResolverEntry[]>([]);
	let loading = $state(true);

	// Modals State
	let digOpen = $state(false);
	let tuningOpen = $state(false);
	let upstreamOpen = $state(false);
	let upstreamSubmitting = $state(false);
	let formUpstreamAddr = $state("");
	let formUpstreamProto = $state("Udp");
	let formUpstreamDomain = $state("");

	let reverseOpen = $state(false);
	let reverseSubmitting = $state(false);
	let formSubnet = $state("");
	let formResolverUri = $state("");

	async function loadAllData() {
		loading = true;
		try {
			const [sRes, uRes, rRes, aRes] = await Promise.allSettled([
				dnsStats(),
				dnsUpstreams(),
				dnsReverseResolverList(),
				dnsAnalytics(10),
			]);

			if (sRes.status === "fulfilled") statsData = sRes.value;
			if (uRes.status === "fulfilled") upstreams = uRes.value;
			if (rRes.status === "fulfilled") reverseResolvers = rRes.value;
			if (aRes.status === "fulfilled") analyticsData = aRes.value;
		} catch (err: any) {
			toast.error("Failed to load DNS resolver data");
		} finally {
			loading = false;
		}
	}

	async function handleAddUpstream(e: SubmitEvent) {
		e.preventDefault();
		if (!formUpstreamAddr.trim()) return;
		upstreamSubmitting = true;
		try {
			await dnsUpstreamAdd({
				addr: formUpstreamAddr.trim(),
				protocol: formUpstreamProto,
				domain: formUpstreamDomain.trim() || undefined,
			});
			toast.success(`Added upstream server ${formUpstreamAddr.trim()}`);
			formUpstreamAddr = "";
			formUpstreamDomain = "";
			upstreamOpen = false;
			await loadAllData();
		} catch (err: any) {
			toast.error(
				`Failed to add upstream: ${err.message || "Invalid address"}`,
			);
		} finally {
			upstreamSubmitting = false;
		}
	}

	function getUpstreamAddrStr(u: DnsUpstreamEntry): string {
		if (typeof u.addr === "string") return u.addr;
		if (u.addr && typeof u.addr === "object" && (u.addr as any).addr) {
			return (u.addr as any).addr;
		}
		if (typeof u.target === "string") return u.target;
		if (typeof u.url === "string") return u.url;
		return String(u.target ?? u.addr ?? u.url ?? "");
	}

	async function handleRemoveUpstream(item: DnsUpstreamEntry) {
		const addrStr = getUpstreamAddrStr(item);
		const protoStr = item.protocol || "UDP";
		try {
			await dnsUpstreamRemove({
				addr: addrStr,
				protocol: protoStr,
				domain: item.domain || undefined,
			});
			toast.success(`Removed upstream server ${addrStr}`);
			await loadAllData();
		} catch {
			toast.error(`Failed to remove upstream server ${addrStr}`);
		}
	}

	async function handleAddReverse(e: SubmitEvent) {
		e.preventDefault();
		if (!formSubnet.trim() || !formResolverUri.trim()) return;
		reverseSubmitting = true;
		try {
			await dnsReverseResolverAdd(
				formSubnet.trim(),
				formResolverUri.trim(),
			);
			toast.success(`Added PTR resolver for ${formSubnet.trim()}`);
			formSubnet = "";
			formResolverUri = "";
			reverseOpen = false;
			await loadAllData();
		} catch (err: any) {
			toast.error(
				`Failed to add PTR resolver: ${err.message || "Invalid CIDR/URI"}`,
			);
		} finally {
			reverseSubmitting = false;
		}
	}

	function formatSubnet(subnet: any): string {
		if (typeof subnet === "string") return subnet;
		if (subnet && typeof subnet === "object") {
			if (subnet.net && subnet.prefix !== undefined) {
				return `${subnet.net}/${subnet.prefix}`;
			}
			if (subnet.cidr) return subnet.cidr;
			if (subnet.ip && subnet.mask) return `${subnet.ip}/${subnet.mask}`;
		}
		return String(subnet ?? "");
	}

	async function handleRemoveReverse(item: ReverseResolverEntry) {
		const subnetStr = formatSubnet(item.subnet);
		try {
			await dnsReverseResolverRemove(subnetStr);
			toast.success(`Removed PTR resolver for ${subnetStr}`);
			await loadAllData();
		} catch {
			toast.error(`Failed to remove PTR resolver for ${subnetStr}`);
		}
	}

	onMount(loadAllData);

	const topClientsList = $derived.by(() => {
		return analyticsData?.top_clients ?? [];
	});
</script>

<svelte:head>
	<title>DNS Resolver — Lanforge</title>
</svelte:head>

<Tooltip.Provider>
	<div class="flex flex-col gap-6">
		<!-- Page Header -->
		<div
			class="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between"
		>
			<div>
				<h1 class="text-2xl font-bold tracking-tight">
					DNS Resolver & Analytics
				</h1>
				<p class="text-muted-foreground text-xs">
					Recursive DNS resolver, query cache, and upstream forwarders
				</p>
			</div>

			<div class="flex flex-wrap items-center gap-2 mt-1 sm:mt-0">
				<Button
					variant="outline"
					size="sm"
					onclick={() => (tuningOpen = true)}
					class="text-xs gap-1.5 h-8 border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300 hover:bg-sky-500/20 transition-colors font-medium shadow-xs"
				>
					<SlidersIcon class="size-3.5 text-sky-600 dark:text-sky-400" />
					<span>Tuning & Cache</span>
				</Button>
				<Button
					variant="outline"
					size="sm"
					onclick={loadAllData}
					disabled={loading}
					class="text-xs h-8"
				>
					<RefreshCwIcon
						class={["size-3.5", loading ? "animate-spin" : ""].join(
							" ",
						)}
					/>
					Refresh
				</Button>
			</div>
		</div>

		<!-- 1. Top Summary Metric Cards -->
		<DnsResolverTopCards {loading} {statsData} {upstreams} />

		<!-- 2. Time-Series Activity Chart & Query Types Breakdown (Pi-hole Style) -->
		<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
			<div class="lg:col-span-2">
				<DnsResolverActivityChart {loading} {analyticsData} {statsData} />
			</div>
			<div class="lg:col-span-1">
				<DnsQueryTypesCard {loading} {analyticsData} />
			</div>
		</div>

		<!-- 3. Row 1: Top Clients - Top Domains -->
		<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
			<DnsTopClientsCard {loading} {analyticsData} />
			<DnsTopDomainsCard
				{loading}
				{analyticsData}
				topClients={topClientsList}
			/>
		</div>

		<!-- 4. Row 2: Upstream DNS Servers - Reverse PTR Resolvers -->
		<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
			<DnsUpstreamsCard
				{loading}
				{upstreams}
				onAddUpstream={() => (upstreamOpen = true)}
				onRemoveUpstream={handleRemoveUpstream}
				onOpenDigModal={() => (digOpen = true)}
				onReloadAll={loadAllData}
			/>
			<DnsReverseResolversCard
				{loading}
				{reverseResolvers}
				onAddReverse={() => (reverseOpen = true)}
				onRemoveReverse={handleRemoveReverse}
			/>
		</div>
	</div>
</Tooltip.Provider>

<!-- Resolver Tuning & Cache Modal -->
<DnsTuningModal bind:open={tuningOpen} {statsData} onReload={loadAllData} />

<!-- Interactive DNS Dig Lookup Modal -->
<DnsDigModal bind:open={digOpen} />

<!-- Add Upstream Server Modal -->
<Dialog.Root bind:open={upstreamOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<PlusIcon class="size-5 text-indigo-400" />
				<span>Add Upstream DNS Server</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleAddUpstream} class="py-2">
			<Field.FieldGroup class="gap-4">
				<Field.Field>
					<Field.FieldLabel for="uaddr"
						>Server Address or DoH/DoT URL *</Field.FieldLabel
					>
					<Input
						id="uaddr"
						placeholder="e.g. 1.1.1.1:53 or https://dns.cloudflare.com/dns-query"
						class="font-mono text-xs"
						bind:value={formUpstreamAddr}
						required
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="uproto">Protocol</Field.FieldLabel>
					<div class="grid grid-cols-4 gap-1.5">
						{#each ["Udp", "Tcp", "Tls", "Https"] as proto (proto)}
							<button
								type="button"
								class={[
									"rounded border px-2 py-1.5 font-mono text-xs font-medium transition-colors",
									formUpstreamProto === proto
										? "bg-primary text-primary-foreground border-primary"
										: "bg-muted/40 border-border text-muted-foreground hover:text-foreground",
								].join(" ")}
								onclick={() => (formUpstreamProto = proto)}
							>
								{proto}
							</button>
						{/each}
					</div>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="udomain"
						>Target Domain Suffix (Optional)</Field.FieldLabel
					>
					<Input
						id="udomain"
						placeholder="e.g. lan or internal.company.com"
						class="text-xs"
						bind:value={formUpstreamDomain}
					/>
					<Field.FieldDescription>
						Leave blank to forward all global DNS queries to this
						upstream server.
					</Field.FieldDescription>
				</Field.Field>

				<div class="flex items-center justify-end gap-2 mt-2">
					<Button
						type="button"
						variant="outline"
						size="sm"
						onclick={() => (upstreamOpen = false)}
					>
						Cancel
					</Button>
					<Button
						type="submit"
						size="sm"
						disabled={upstreamSubmitting}
					>
						{#if upstreamSubmitting}
							<span
								class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
							></span>
						{/if}
						Save Upstream Server
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>

<!-- Add Reverse Resolver Modal -->
<Dialog.Root bind:open={reverseOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<PlusIcon class="size-5 text-purple-400" />
				<span>Add Reverse PTR Resolver</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleAddReverse} class="py-2">
			<Field.FieldGroup class="gap-4">
				<Field.Field>
					<Field.FieldLabel for="rsubnet"
						>Target Subnet (CIDR) *</Field.FieldLabel
					>
					<Input
						id="rsubnet"
						placeholder="e.g. 192.168.1.0/24 or fd00::/64"
						class="font-mono text-xs"
						bind:value={formSubnet}
						required
					/>
				</Field.Field>

				<Field.Field>
					<Field.FieldLabel for="ruri"
						>Resolver URI / Server Address *</Field.FieldLabel
					>
					<Input
						id="ruri"
						placeholder="e.g. 192.168.1.1:53"
						class="font-mono text-xs"
						bind:value={formResolverUri}
						required
					/>
				</Field.Field>

				<div class="flex items-center justify-end gap-2 mt-2">
					<Button
						type="button"
						variant="outline"
						size="sm"
						onclick={() => (reverseOpen = false)}
					>
						Cancel
					</Button>
					<Button
						type="submit"
						size="sm"
						disabled={reverseSubmitting}
					>
						{#if reverseSubmitting}
							<span
								class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"
							></span>
						{/if}
						Save PTR Resolver
					</Button>
				</div>
			</Field.FieldGroup>
		</form>
	</Dialog.Content>
</Dialog.Root>
