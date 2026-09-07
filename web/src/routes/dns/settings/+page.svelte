<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import * as Tabs from "$lib/components/ui/tabs";
	import * as Table from "$lib/components/ui/table";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";

	import ServerIcon from "@lucide/svelte/icons/server";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import LockIcon from "@lucide/svelte/icons/lock";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import DatabaseIcon from "@lucide/svelte/icons/database";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";

	import {
		status as getSystemStatus,
		dnsStats,
		dnsUpstreams,
		dnsUpstreamAdd,
		dnsUpstreamRemove,
		dnsUpstreamClear,
		dnsCacheStatsExt,
		dnsCacheFlush,
		dnsReverseResolverList,
		dnsReverseResolverAdd,
		dnsReverseResolverRemove,
	} from "$lib/api/client";
	import type {
		DnsUpstreamEntry,
		ReverseResolverEntry,
		DnsStatsResponse,
		DnsCacheStatsExtResponse,
		StatusResponse,
	} from "$lib/api/types";
	import DnsDigModal from "../resolver/components/DnsDigModal.svelte";

	let loading = $state(true);
	let applyingPreset = $state(false);
	let flushingCache = $state(false);
	let activeTab = $state("upstreams");

	let systemStatus = $state<StatusResponse | null>(null);
	let statsData = $state<DnsStatsResponse | null>(null);
	let cacheStats = $state<DnsCacheStatsExtResponse | null>(null);
	let upstreams = $state<DnsUpstreamEntry[]>([]);
	let reverseResolvers = $state<ReverseResolverEntry[]>([]);

	// Modals State
	let digOpen = $state(false);
	let addUpstreamOpen = $state(false);
	let addingUpstream = $state(false);
	let formUpstreamAddr = $state("");
	let formUpstreamProto = $state("udp");
	let formUpstreamDomain = $state("");

	let addReverseOpen = $state(false);
	let addingReverse = $state(false);
	let formSubnet = $state("");
	let formResolverUri = $state("");

	let copiedTarget = $state<string | null>(null);

	const DNS_PRESETS = [
		{
			id: "quad9",
			name: "Quad9 (Default)",
			description: "Malware & Phishing protection, DNSSEC, Swiss non-profit privacy-first resolver.",
			badge: "Security & Privacy",
			v4: ["9.9.9.9", "149.112.112.112"],
			v6: ["2620:fe::fe", "2620:fe::9"],
		},
		{
			id: "cloudflare",
			name: "Cloudflare 1.1.1.1",
			description: "Ultra-fast global Anycast network with minimal logging and strict privacy.",
			badge: "Ultra Fast",
			v4: ["1.1.1.1", "1.0.0.1"],
			v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"],
		},
		{
			id: "google",
			name: "Google Public DNS",
			description: "Global resilient Anycast network with worldwide high-availability routing.",
			badge: "High Availability",
			v4: ["8.8.8.8", "8.8.4.4"],
			v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"],
		},
		{
			id: "adguard",
			name: "AdGuard DNS",
			description: "Network-wide ads, trackers, and malicious domains blocked upstream.",
			badge: "Ad-Blocking",
			v4: ["94.140.14.14", "94.140.15.15"],
			v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
		},
	];

	async function loadAllData() {
		loading = true;
		try {
			const [sysRes, sRes, uRes, rRes, cRes] = await Promise.allSettled([
				getSystemStatus(),
				dnsStats(),
				dnsUpstreams(),
				dnsReverseResolverList(),
				dnsCacheStatsExt(),
			]);

			if (sysRes.status === "fulfilled") systemStatus = sysRes.value;
			if (sRes.status === "fulfilled") statsData = sRes.value;
			if (uRes.status === "fulfilled") {
				const val = uRes.value;
				if (Array.isArray(val)) {
					upstreams = val;
				} else if (val && typeof val === "object" && Array.isArray((val as any).upstreams)) {
					upstreams = (val as any).upstreams;
				} else {
					upstreams = [];
				}
			}
			if (rRes.status === "fulfilled") {
				const val = rRes.value;
				if (Array.isArray(val)) {
					reverseResolvers = val;
				} else if (val && typeof val === "object" && Array.isArray((val as any).resolvers)) {
					reverseResolvers = (val as any).resolvers;
				} else {
					reverseResolvers = [];
				}
			}
			if (cRes.status === "fulfilled") cacheStats = cRes.value;
		} catch {
			toast.error("Failed to load DNS configuration data");
		} finally {
			loading = false;
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

	function getUpstreamProtocol(u: DnsUpstreamEntry): string {
		if (u.protocol) return u.protocol.toUpperCase();
		const t = getUpstreamAddrStr(u);
		if (t.startsWith("tls://")) return "TLS";
		if (t.startsWith("quic://")) return "QUIC";
		if (t.startsWith("https://")) return "HTTPS";
		return "UDP";
	}

	function getProtocolBadgeClass(proto: string): string {
		switch (proto.toLowerCase()) {
			case "tls":
			case "dot":
				return "bg-purple-500/10 text-purple-400 border-purple-500/20";
			case "quic":
			case "doq":
				return "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";
			case "https":
			case "doh":
				return "bg-cyan-500/10 text-cyan-400 border-cyan-500/20";
			default:
				return "bg-blue-500/10 text-blue-400 border-blue-500/20";
		}
	}

	function getSubnetStr(subnet: string | { addr: string; prefix_len: number }): string {
		if (typeof subnet === "string") return subnet;
		return `${subnet.addr}/${subnet.prefix_len}`;
	}

	function getUpstreamLatency(u: DnsUpstreamEntry): string {
		if (u.rtt_ewma_us !== undefined && u.rtt_ewma_us !== null) {
			const ms = (u.rtt_ewma_us / 1000).toFixed(1);
			return `${ms} ms`;
		}
		if (u.latency_ms !== undefined) return `${u.latency_ms} ms`;
		return "-";
	}

	async function copyToClipboard(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copiedTarget = text;
			setTimeout(() => {
				if (copiedTarget === text) copiedTarget = null;
			}, 2000);
			toast.success(`Copied ${text} to clipboard`);
		} catch {
			toast.error("Failed to copy to clipboard");
		}
	}

	async function handleApplyPreset(preset: typeof DNS_PRESETS[0]) {
		applyingPreset = true;
		try {
			// Clear existing upstreams first
			await dnsUpstreamClear();
			// Add all 4 addresses (IPv4 + IPv6)
			const allAddrs = [...preset.v4, ...preset.v6];
			for (const addr of allAddrs) {
				await dnsUpstreamAdd({ addr, protocol: "udp" });
			}
			toast.success(`Applied ${preset.name} preset with 4 dual-stack upstreams!`);
			await loadAllData();
		} catch (err: any) {
			toast.error(`Failed to apply preset: ${err.message || "Unknown error"}`);
		} finally {
			applyingPreset = false;
		}
	}

	async function handleClearUpstreams() {
		if (!confirm("Are you sure you want to remove all configured upstream DNS servers? Non-local domain queries will return REFUSED until new upstreams are added.")) {
			return;
		}
		try {
			await dnsUpstreamClear();
			toast.success("All upstream servers cleared successfully");
			await loadAllData();
		} catch (err: any) {
			toast.error(`Failed to clear upstreams: ${err.message || "Unknown error"}`);
		}
	}

	async function handleAddUpstream(e: SubmitEvent) {
		e.preventDefault();
		if (!formUpstreamAddr.trim()) return;
		addingUpstream = true;
		try {
			await dnsUpstreamAdd({
				addr: formUpstreamAddr.trim(),
				protocol: formUpstreamProto,
				domain: formUpstreamDomain.trim() || undefined,
			});
			toast.success(`Added upstream server ${formUpstreamAddr.trim()}`);
			formUpstreamAddr = "";
			formUpstreamDomain = "";
			addUpstreamOpen = false;
			await loadAllData();
		} catch (err: any) {
			toast.error(`Failed to add upstream: ${err.message || "Invalid address"}`);
		} finally {
			addingUpstream = false;
		}
	}

	async function handleRemoveUpstream(item: DnsUpstreamEntry) {
		const addrStr = getUpstreamAddrStr(item);
		const protoStr = (item.protocol || "udp").toLowerCase();
		try {
			await dnsUpstreamRemove({ addr: addrStr, protocol: protoStr });
			toast.success(`Removed upstream ${addrStr}`);
			await loadAllData();
		} catch (err: any) {
			toast.error(`Failed to remove upstream: ${err.message || "Error"}`);
		}
	}

	async function handleAddReverse(e: SubmitEvent) {
		e.preventDefault();
		if (!formSubnet.trim() || !formResolverUri.trim()) return;
		addingReverse = true;
		try {
			await dnsReverseResolverAdd(formSubnet.trim(), formResolverUri.trim());
			toast.success(`Added reverse resolver for ${formSubnet.trim()}`);
			formSubnet = "";
			formResolverUri = "";
			addReverseOpen = false;
			await loadAllData();
		} catch (err: any) {
			toast.error(`Failed to add reverse resolver: ${err.message || "Invalid subnet/URI"}`);
		} finally {
			addingReverse = false;
		}
	}

	async function handleRemoveReverse(subnet: string) {
		try {
			await dnsReverseResolverRemove(subnet);
			toast.success(`Removed reverse resolver for ${subnet}`);
			await loadAllData();
		} catch (err: any) {
			toast.error(`Failed to remove reverse resolver: ${err.message || "Error"}`);
		}
	}

	async function handleFlushCache() {
		flushingCache = true;
		try {
			await dnsCacheFlush();
			toast.success("DNS cache flushed successfully");
			await loadAllData();
		} catch (err: any) {
			toast.error(`Failed to flush cache: ${err.message || "Error"}`);
		} finally {
			flushingCache = false;
		}
	}

	onMount(() => {
		loadAllData();
	});
</script>

<div class="space-y-6 pb-12">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<div class="flex items-center gap-2.5">
				<div class="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
					<GlobeIcon class="h-5 w-5" />
				</div>
				<div>
					<h1 class="text-2xl font-bold tracking-tight text-foreground">DNS Settings & Upstreams</h1>
					<p class="text-sm text-muted-foreground">
						Configure upstream DNS forwarding, dual-stack presets, encrypted transports (DoT & DoQ), and local resolution.
					</p>
				</div>
			</div>
		</div>
		<div class="flex items-center gap-2">
			<Button variant="outline" size="sm" onclick={loadAllData} disabled={loading} class="gap-1.5">
				<RefreshCwIcon class="h-3.5 w-3.5 {loading ? 'animate-spin' : ''}" />
				Refresh
			</Button>
			<Button variant="outline" size="sm" onclick={() => (digOpen = true)} class="gap-1.5">
				<ZapIcon class="h-3.5 w-3.5 text-amber-400" />
				Dig Test
			</Button>
			<Button variant="destructive" size="sm" onclick={handleFlushCache} disabled={flushingCache} class="gap-1.5">
				<Trash2Icon class="h-3.5 w-3.5" />
				Flush Cache
			</Button>
		</div>
	</div>

	<!-- Main Configuration Tabs -->
	<Tabs.Root bind:value={activeTab} class="space-y-4">
		<Tabs.List class="grid grid-cols-2 sm:grid-cols-5 w-full max-w-2xl">
			<Tabs.Trigger value="upstreams" class="gap-1.5">
				<ServerIcon class="h-3.5 w-3.5" />
				Upstreams
			</Tabs.Trigger>
			<Tabs.Trigger value="general" class="gap-1.5">
				<SlidersIcon class="h-3.5 w-3.5" />
				General & Local
			</Tabs.Trigger>
			<Tabs.Trigger value="encryption" class="gap-1.5">
				<LockIcon class="h-3.5 w-3.5" />
				Encrypted DNS
			</Tabs.Trigger>
			<Tabs.Trigger value="cache" class="gap-1.5">
				<DatabaseIcon class="h-3.5 w-3.5" />
				Cache
			</Tabs.Trigger>
			<Tabs.Trigger value="reverse" class="gap-1.5">
				<NetworkIcon class="h-3.5 w-3.5" />
				Reverse PTR
			</Tabs.Trigger>
		</Tabs.List>

		<!-- ================================================================= -->
		<!-- TAB 1: UPSTREAMS & FORWARDING                                     -->
		<!-- ================================================================= -->
		<Tabs.Content value="upstreams" class="space-y-6">
			<!-- 1-Click Fast Presets Card -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<SparklesIcon class="h-4 w-4 text-primary" />
							<div>
								<Card.Title class="text-base">1-Click Dual-Stack Presets</Card.Title>
								<Card.Description>
									Quickly apply recommended public DNS providers with complete dual-stack primary and secondary IPv4 + IPv6 addresses.
								</Card.Description>
							</div>
						</div>
					</div>
				</Card.Header>
				<Card.Content class="pt-4">
					<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
						{#each DNS_PRESETS as preset}
							<div class="flex flex-col justify-between rounded-lg border bg-muted/20 p-3 hover:border-primary/50 transition-colors">
								<div class="space-y-1.5">
									<div class="flex items-center justify-between">
										<span class="font-semibold text-sm text-foreground">{preset.name}</span>
										<Badge variant="secondary" class="text-[10px] px-1.5 py-0">{preset.badge}</Badge>
									</div>
									<p class="text-xs text-muted-foreground leading-relaxed">
										{preset.description}
									</p>
									<div class="pt-2 space-y-1 font-mono text-[11px]">
										<div class="flex items-center gap-1.5 text-muted-foreground">
											<span class="px-1 py-0.5 rounded bg-blue-500/10 text-blue-400 font-sans text-[9px] font-bold">IPv4</span>
											<span>{preset.v4.join(", ")}</span>
										</div>
										<div class="flex items-center gap-1.5 text-muted-foreground">
											<span class="px-1 py-0.5 rounded bg-purple-500/10 text-purple-400 font-sans text-[9px] font-bold">IPv6</span>
											<span class="truncate">{preset.v6.join(", ")}</span>
										</div>
									</div>
								</div>
								<Button
									size="sm"
									variant="outline"
									class="mt-3 w-full gap-1.5 text-xs font-medium"
									disabled={applyingPreset}
									onclick={() => handleApplyPreset(preset)}
								>
									<SparklesIcon class="h-3 w-3 text-primary" />
									Apply 4-IP Preset
								</Button>
							</div>
						{/each}
					</div>
				</Card.Content>
			</Card.Root>

			<!-- Active Upstreams Table -->
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
						<div class="flex items-center gap-2">
							<ServerIcon class="h-4 w-4 text-indigo-400" />
							<div>
								<Card.Title class="text-base">Active Upstream Forwarders ({upstreams.length})</Card.Title>
								<Card.Description>
									External servers queries are forwarded to when resolving non-local domain names.
								</Card.Description>
							</div>
						</div>
						<div class="flex items-center gap-2">
							<Button size="sm" variant="outline" onclick={() => (addUpstreamOpen = true)} class="gap-1.5">
								<PlusIcon class="h-3.5 w-3.5" />
								Add Upstream
							</Button>
							{#if upstreams.length > 0}
								<Button size="sm" variant="ghost" onclick={handleClearUpstreams} class="text-destructive hover:bg-destructive/10 gap-1.5">
									<Trash2Icon class="h-3.5 w-3.5" />
									Clear All
								</Button>
							{/if}
						</div>
					</div>
				</Card.Header>
				<Card.Content class="p-0">
					{#if loading}
						<div class="p-4 space-y-2">
							<Skeleton class="h-8 w-full" />
							<Skeleton class="h-8 w-full" />
							<Skeleton class="h-8 w-full" />
						</div>
					{:else if upstreams.length === 0}
						<div class="flex flex-col items-center justify-center p-8 text-center">
							<ServerIcon class="h-10 w-10 text-muted-foreground/40 mb-2" />
							<p class="font-medium text-foreground">No Upstream Resolvers Configured</p>
							<p class="text-xs text-muted-foreground max-w-sm mt-1">
								Without upstream servers, Lanforge will only resolve local <code class="font-mono text-foreground">*.lan</code> records and return <code class="font-mono text-foreground">REFUSED</code> for external domains.
							</p>
							<div class="flex gap-2 mt-4">
								<Button size="sm" onclick={() => handleApplyPreset(DNS_PRESETS[0])} class="gap-1.5">
									<SparklesIcon class="h-3.5 w-3.5" />
									Load Quad9 (4 IPs)
								</Button>
								<Button size="sm" variant="outline" onclick={() => (addUpstreamOpen = true)}>
									Custom Server
								</Button>
							</div>
						</div>
					{:else}
						<Table.Root>
							<Table.Header>
								<Table.Row>
									<Table.Head>Protocol</Table.Head>
									<Table.Head>Target Address</Table.Head>
									<Table.Head>Domain / SNI</Table.Head>
									<Table.Head>Health Status</Table.Head>
									<Table.Head>Latency</Table.Head>
									<Table.Head class="text-right">Actions</Table.Head>
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{#each upstreams as item}
									{@const addrStr = getUpstreamAddrStr(item)}
									{@const proto = getUpstreamProtocol(item)}
									<Table.Row>
										<Table.Cell>
											<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold border {getProtocolBadgeClass(proto)}">
												{proto}
											</span>
										</Table.Cell>
										<Table.Cell class="font-mono text-xs">
											<div class="flex items-center gap-2">
												<span>{addrStr}</span>
												<button
													type="button"
													class="text-muted-foreground hover:text-foreground transition-colors"
													title="Copy address"
													onclick={() => copyToClipboard(addrStr)}
												>
													{#if copiedTarget === addrStr}
														<CheckIcon class="h-3 w-3 text-emerald-400" />
													{:else}
														<CopyIcon class="h-3 w-3" />
													{/if}
												</button>
											</div>
										</Table.Cell>
										<Table.Cell class="text-xs text-muted-foreground">
											{item.domain || (item as any).hostname || "Global (*)"}
										</Table.Cell>
										<Table.Cell>
											<div class="flex items-center gap-1.5">
												<span class="relative flex h-2 w-2">
													<span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
													<span class="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
												</span>
												<span class="text-xs font-medium text-foreground">
													{item.status || "Healthy"}
												</span>
											</div>
										</Table.Cell>
										<Table.Cell class="font-mono text-xs">
											<span class="inline-flex items-center gap-1 text-emerald-400 font-medium">
												<ActivityIcon class="h-3 w-3" />
												{getUpstreamLatency(item)}
											</span>
										</Table.Cell>
										<Table.Cell class="text-right">
											<Button
												size="icon"
												variant="ghost"
												class="h-7 w-7 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
												title="Remove Upstream"
												onclick={() => handleRemoveUpstream(item)}
											>
												<Trash2Icon class="h-3.5 w-3.5" />
											</Button>
										</Table.Cell>
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					{/if}
				</Card.Content>
			</Card.Root>
		</Tabs.Content>

		<!-- ================================================================= -->
		<!-- TAB 2: GENERAL & LOCAL RESOLUTION                                 -->
		<!-- ================================================================= -->
		<Tabs.Content value="general" class="space-y-6">
			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<!-- Resolver Status Card -->
				<Card.Root>
					<Card.Header class="pb-3">
						<Card.Title class="text-base flex items-center gap-2">
							<ServerIcon class="h-4 w-4 text-primary" />
							DNS Listener & Bind Address
						</Card.Title>
						<Card.Description>Core UDP and TCP port binding on router network stack.</Card.Description>
					</Card.Header>
					<Card.Content class="space-y-3 text-xs">
						<div class="flex items-center justify-between rounded border p-2.5">
							<div>
								<span class="font-medium text-foreground">Standard Port 53</span>
								<p class="text-muted-foreground">Listens on all LAN interfaces (UDP + TCP fallback)</p>
							</div>
							<Badge variant="outline" class="text-emerald-400 border-emerald-500/20 bg-emerald-500/10">0.0.0.0:53</Badge>
						</div>
						<div class="flex items-center justify-between rounded border p-2.5">
							<div>
								<span class="font-medium text-foreground">Service State</span>
								<p class="text-muted-foreground">Status of the background DNS daemon worker</p>
							</div>
							<Badge class="bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
								{(systemStatus?.services?.dns as any)?.state || "Running"}
							</Badge>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- Local Domain & Lease Resolution Card -->
				<Card.Root>
					<Card.Header class="pb-3">
						<Card.Title class="text-base flex items-center gap-2">
							<GlobeIcon class="h-4 w-4 text-cyan-400" />
							Local Domain & Search Suffixes
						</Card.Title>
						<Card.Description>Internal hostnames resolved authoritatively from LAN state.</Card.Description>
					</Card.Header>
					<Card.Content class="space-y-3 text-xs">
						<div class="flex items-center justify-between rounded border p-2.5">
							<div>
								<span class="font-medium text-foreground">Authoritative Search Suffix</span>
								<p class="text-muted-foreground">Queries matching this domain are resolved locally</p>
							</div>
							<code class="font-mono text-primary font-bold">.lan</code>
						</div>
						<div class="flex items-center justify-between rounded border p-2.5">
							<div>
								<span class="font-medium text-foreground">Default Local Record TTL</span>
								<p class="text-muted-foreground">Time To Live for local DHCP & device names</p>
							</div>
							<span class="font-mono text-foreground font-semibold">60 seconds</span>
						</div>
						<div class="flex items-center justify-between rounded border p-2.5">
							<div>
								<span class="font-medium text-foreground">Inactive Device Threshold</span>
								<p class="text-muted-foreground">Hides offline devices after prolonged inactivity</p>
							</div>
							<span class="font-mono text-foreground font-semibold">7 days</span>
						</div>
					</Card.Content>
				</Card.Root>
			</div>

			<!-- Dynamic Dual-Stack Architecture Explanation -->
			<Card.Root class="bg-muted/10 border-primary/20">
				<Card.Header class="pb-2">
					<div class="flex items-center gap-2">
						<RadioIcon class="h-4 w-4 text-primary" />
						<Card.Title class="text-sm">Dual-Stack Local Host Resolution (A + AAAA)</Card.Title>
					</div>
				</Card.Header>
				<Card.Content class="text-xs text-muted-foreground space-y-2">
					<p>
						Lanforge automatically correlates DHCPv4 allocations, IPv6 SLAAC address notifications, and static host overrides into instant zero-delay DNS entries under your local search domain (e.g. <code class="font-mono text-foreground">my-laptop.lan</code>).
					</p>
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
						<div class="rounded border bg-background/50 p-2.5">
							<span class="font-semibold text-foreground">IPv4 Resolution (A)</span>
							<p class="mt-0.5">Directly maps device hostnames to their active DHCPv4 lease or static IPv4 reservation.</p>
						</div>
						<div class="rounded border bg-background/50 p-2.5">
							<span class="font-semibold text-foreground">IPv6 Resolution (AAAA)</span>
							<p class="mt-0.5">Synthesizes AAAA records combining active router ULA (<code class="font-mono text-foreground">fdxx::/64</code>) and GUA prefixes with the device's hardware interface identifier.</p>
						</div>
					</div>
				</Card.Content>
			</Card.Root>
		</Tabs.Content>

		<!-- ================================================================= -->
		<!-- TAB 3: ENCRYPTED TRANSPORTS                                       -->
		<!-- ================================================================= -->
		<Tabs.Content value="encryption" class="space-y-6">
			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<!-- DNS-over-TLS (DoT) Card -->
				<Card.Root>
					<Card.Header class="pb-3">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<LockIcon class="h-4 w-4 text-purple-400" />
								<Card.Title class="text-base">DNS-over-TLS (DoT)</Card.Title>
							</div>
							<Badge variant="outline" class="text-purple-400 border-purple-500/20 bg-purple-500/10">Port 853 TCP</Badge>
						</div>
						<Card.Description>
							Standard TLS encryption for external and mobile device DNS queries.
						</Card.Description>
					</Card.Header>
					<Card.Content class="space-y-3 text-xs">
						<p class="text-muted-foreground">
							Enables secure DNS resolution for mobile devices, laptops, and Android's native <strong>Private DNS</strong> setting.
						</p>
						<div class="rounded border bg-muted/20 p-2.5 space-y-1 font-mono text-[11px]">
							<span class="text-muted-foreground font-sans font-medium">Certificate Path:</span>
							<p class="text-foreground">/etc/lanforge/tls/cert.pem</p>
							<span class="text-muted-foreground font-sans font-medium pt-1 block">Private Key Path:</span>
							<p class="text-foreground">/etc/lanforge/tls/key.pem</p>
						</div>
						<div class="rounded border bg-purple-500/5 border-purple-500/20 p-2.5">
							<span class="font-semibold text-foreground">Android Private DNS</span>
							<p class="text-muted-foreground mt-0.5">
								On Android, navigate to Settings &rarr; Network &rarr; Private DNS and enter your router's DoT hostname (e.g. <code class="font-mono text-foreground">router.lan</code>).
							</p>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- DNS-over-QUIC (DoQ) Card -->
				<Card.Root>
					<Card.Header class="pb-3">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2">
								<ZapIcon class="h-4 w-4 text-emerald-400" />
								<Card.Title class="text-base">DNS-over-QUIC (DoQ)</Card.Title>
							</div>
							<Badge variant="outline" class="text-emerald-400 border-emerald-500/20 bg-emerald-500/10">Port 853 UDP</Badge>
						</div>
						<Card.Description>
							Next-generation RFC 9250 zero-RTT encrypted DNS transport.
						</Card.Description>
					</Card.Header>
					<Card.Content class="space-y-3 text-xs">
						<p class="text-muted-foreground">
							Ultra low-latency encrypted DNS using QUIC over UDP. Prevents head-of-line blocking and achieves instant zero round-trip connection resumption.
						</p>
						<div class="rounded border bg-muted/20 p-2.5 space-y-1.5">
							<div class="flex items-center justify-between">
								<span class="font-medium text-foreground">QUIC Transport Protocol</span>
								<Badge variant="secondary" class="text-[10px]">RFC 9250</Badge>
							</div>
							<p class="text-muted-foreground">
								Native support for AdGuard, Apple iOS profiles, and modern stub resolvers using QUIC streams.
							</p>
						</div>
					</Card.Content>
				</Card.Root>
			</div>
		</Tabs.Content>

		<!-- ================================================================= -->
		<!-- TAB 4: CACHE & PERFORMANCE                                        -->
		<!-- ================================================================= -->
		<Tabs.Content value="cache" class="space-y-6">
			<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
				<Card.Root>
					<Card.Header class="pb-2">
						<Card.Description class="text-xs">Cached Records</Card.Description>
						<Card.Title class="text-2xl font-bold">
							{cacheStats?.total_entries ?? statsData?.cache_entries ?? 0}
						</Card.Title>
					</Card.Header>
					<Card.Content>
						<p class="text-xs text-muted-foreground">
							Capacity: {(cacheStats?.capacity ?? 10000).toLocaleString()} entries
						</p>
					</Card.Content>
				</Card.Root>

				<Card.Root>
					<Card.Header class="pb-2">
						<Card.Description class="text-xs">Cache Hits</Card.Description>
						<Card.Title class="text-2xl font-bold text-emerald-400">
							{statsData?.cache_hits ?? 0}
						</Card.Title>
					</Card.Header>
					<Card.Content>
						<p class="text-xs text-muted-foreground">
							Served instantly with 0ms latency
						</p>
					</Card.Content>
				</Card.Root>

				<Card.Root>
					<Card.Header class="pb-2">
						<Card.Description class="text-xs">Cache Misses</Card.Description>
						<Card.Title class="text-2xl font-bold text-amber-400">
							{statsData?.cache_misses ?? 0}
						</Card.Title>
					</Card.Header>
					<Card.Content>
						<p class="text-xs text-muted-foreground">
							Forwarded to upstream resolvers
						</p>
					</Card.Content>
				</Card.Root>

				<Card.Root>
					<Card.Header class="pb-2">
						<Card.Description class="text-xs">Min TTL Guardrail</Card.Description>
						<Card.Title class="text-2xl font-bold text-primary">
							{cacheStats?.min_ttl ?? 5}s
						</Card.Title>
					</Card.Header>
					<Card.Content>
						<p class="text-xs text-muted-foreground">
							Prevents excessive upstream queries
						</p>
					</Card.Content>
				</Card.Root>
			</div>

			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex items-center justify-between">
						<div>
							<Card.Title class="text-base">In-Memory Cache Management</Card.Title>
							<Card.Description>
								Evict stale records or purge memory without interrupting DNS service.
							</Card.Description>
						</div>
						<Button
							variant="destructive"
							size="sm"
							onclick={handleFlushCache}
							disabled={flushingCache}
							class="gap-1.5"
						>
							<Trash2Icon class="h-3.5 w-3.5" />
							Purge Entire Cache
						</Button>
					</div>
				</Card.Header>
				<Card.Content class="pt-4 text-xs text-muted-foreground space-y-2">
					<p>
						Lanforge caches upstream query answers in an LRU (Least Recently Used) in-memory table. Expired records are lazily collected, and newly updated upstream configurations will automatically flush stale caches.
					</p>
				</Card.Content>
			</Card.Root>
		</Tabs.Content>

		<!-- ================================================================= -->
		<!-- TAB 5: REVERSE RESOLVERS                                          -->
		<!-- ================================================================= -->
		<Tabs.Content value="reverse" class="space-y-6">
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<div class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
						<div class="flex items-center gap-2">
							<NetworkIcon class="h-4 w-4 text-cyan-400" />
							<div>
								<Card.Title class="text-base">Conditional Reverse DNS (PTR) Forwarders</Card.Title>
								<Card.Description>
									Direct reverse IP lookups (<code class="font-mono text-foreground">in-addr.arpa</code> / <code class="font-mono text-foreground">ip6.arpa</code>) for specific subnets to corporate or branch domain controllers.
								</Card.Description>
							</div>
						</div>
						<Button size="sm" onclick={() => (addReverseOpen = true)} class="gap-1.5">
							<PlusIcon class="h-3.5 w-3.5" />
							Add Reverse Resolver
						</Button>
					</div>
				</Card.Header>
				<Card.Content class="p-0">
					{#if reverseResolvers.length === 0}
						<div class="flex flex-col items-center justify-center p-8 text-center">
							<NetworkIcon class="h-10 w-10 text-muted-foreground/40 mb-2" />
							<p class="font-medium text-foreground">No Reverse Resolvers Configured</p>
							<p class="text-xs text-muted-foreground max-w-sm mt-1">
								Local PTR queries are resolved automatically from DHCP leases. Add custom conditional forwarders if you need to route subnets (e.g. <code class="font-mono text-foreground">10.0.0.0/8</code>) to an internal DNS server.
							</p>
							<Button size="sm" variant="outline" class="mt-4" onclick={() => (addReverseOpen = true)}>
								Add First Subnet
							</Button>
						</div>
					{:else}
						<Table.Root>
							<Table.Header>
								<Table.Row>
									<Table.Head>Subnet CIDR</Table.Head>
									<Table.Head>Target Resolver URI</Table.Head>
									<Table.Head class="text-right">Actions</Table.Head>
								</Table.Row>
							</Table.Header>
							<Table.Body>
								{#each reverseResolvers as item}
									<Table.Row>
										<Table.Cell class="font-mono text-xs font-semibold text-foreground">
											{getSubnetStr(item.subnet)}
										</Table.Cell>
										<Table.Cell class="font-mono text-xs text-muted-foreground">
											{item.resolver_uri || (item as any).resolver || ""}
										</Table.Cell>
										<Table.Cell class="text-right">
											<Button
												size="icon"
												variant="ghost"
												class="h-7 w-7 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
												title="Remove Subnet"
												onclick={() => handleRemoveReverse(getSubnetStr(item.subnet))}
											>
												<Trash2Icon class="h-3.5 w-3.5" />
											</Button>
										</Table.Cell>
									</Table.Row>
								{/each}
							</Table.Body>
						</Table.Root>
					{/if}
				</Card.Content>
			</Card.Root>
		</Tabs.Content>
	</Tabs.Root>
</div>

<!-- ===================================================================== -->
<!-- MODAL: ADD UPSTREAM SERVER                                           -->
<!-- ===================================================================== -->
<Dialog.Root bind:open={addUpstreamOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<ServerIcon class="h-5 w-5 text-primary" />
				Add Upstream DNS Server
			</Dialog.Title>
			<Dialog.Description>
				Forward external queries to this DNS server. Supports IPv4, IPv6, TLS, QUIC, and HTTPS.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleAddUpstream} class="space-y-4 py-2">
			<div class="space-y-1.5">
				<Label for="form_addr">Server IP / Socket Address *</Label>
				<Input
					id="form_addr"
					class="font-mono text-xs"
					placeholder="e.g. 9.9.9.9, 1.1.1.1:53, or 2620:fe::fe"
					bind:value={formUpstreamAddr}
					required
				/>
				<p class="text-[11px] text-muted-foreground">
					Port 53 is automatically appended if not specified.
				</p>
			</div>

			<div class="space-y-1.5">
				<Label for="form_proto">Forwarding Protocol</Label>
				<select
					id="form_proto"
					class="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background"
					bind:value={formUpstreamProto}
				>
					<option value="udp">UDP (Standard DNS with TCP fallback)</option>
					<option value="tls">DoT (DNS-over-TLS - Port 853)</option>
					<option value="quic">DoQ (DNS-over-QUIC - Port 853)</option>
					<option value="https">DoH (DNS-over-HTTPS - Port 443)</option>
				</select>
			</div>

			<div class="space-y-1.5">
				<Label for="form_domain">Domain / Hostname (SNI verification)</Label>
				<Input
					id="form_domain"
					class="text-xs"
					placeholder="e.g. dns.quad9.net or one.one.one.one (Required for DoT/DoQ)"
					bind:value={formUpstreamDomain}
				/>
				<p class="text-[11px] text-muted-foreground">
					Used for TLS certificate and SNI validation when using encrypted protocols.
				</p>
			</div>

			<Dialog.Footer class="pt-2">
				<Button type="button" variant="outline" onclick={() => (addUpstreamOpen = false)}>
					Cancel
				</Button>
				<Button type="submit" disabled={addingUpstream || !formUpstreamAddr.trim()} class="gap-1.5">
					<PlusIcon class="h-4 w-4" />
					Add Upstream
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>

<!-- ===================================================================== -->
<!-- MODAL: ADD REVERSE RESOLVER                                           -->
<!-- ===================================================================== -->
<Dialog.Root bind:open={addReverseOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<NetworkIcon class="h-5 w-5 text-cyan-400" />
				Add Reverse PTR Forwarder
			</Dialog.Title>
			<Dialog.Description>
				Route PTR queries for this subnet to a specific internal DNS server.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleAddReverse} class="space-y-4 py-2">
			<div class="space-y-1.5">
				<Label for="form_subnet">Subnet CIDR *</Label>
				<Input
					id="form_subnet"
					class="font-mono text-xs"
					placeholder="e.g. 10.0.0.0/8 or fd00::/8"
					bind:value={formSubnet}
					required
				/>
			</div>

			<div class="space-y-1.5">
				<Label for="form_uri">Target Resolver URI *</Label>
				<Input
					id="form_uri"
					class="font-mono text-xs"
					placeholder="e.g. udp://10.0.0.2:53 or tls://dc1.corp@10.0.0.2:853"
					bind:value={formResolverUri}
					required
				/>
			</div>

			<Dialog.Footer class="pt-2">
				<Button type="button" variant="outline" onclick={() => (addReverseOpen = false)}>
					Cancel
				</Button>
				<Button type="submit" disabled={addingReverse || !formSubnet.trim() || !formResolverUri.trim()} class="gap-1.5">
					<PlusIcon class="h-4 w-4" />
					Add Subnet
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>

<!-- Dig Lookup Modal -->
<DnsDigModal bind:open={digOpen} />
