<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Tabs from "$lib/components/ui/tabs";
	import * as Table from "$lib/components/ui/table";
	import * as Select from "$lib/components/ui/select";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import {
		raStatus,
		raConfig,
		raUpdateConfig,
		raTrigger,
		getSetupStatus,
	} from "$lib/api/client";
	import type {
		RaServerConfig,
		RaStatusResponse,
		RouterPriority,
		RaPrefix,
		RdnssConfig,
		DnsslConfig,
		PrefixSource,
		NetworkInterfaceInfo,
	} from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount, onDestroy } from "svelte";

	import RadioIcon from "@lucide/svelte/icons/radio";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";

	// Page state
	let status = $state<RaStatusResponse | null>(null);
	let config = $state<RaServerConfig | null>(null);
	let loading = $state(true);
	let saving = $state(false);
	let triggering = $state(false);
	let refreshInterval: ReturnType<typeof setInterval> | null = null;
	let availableInterfaces = $state<NetworkInterfaceInfo[]>([]);

	// Derived list of selectable interfaces ensuring currently selected iface is present
	let interfaceOptions = $derived.by(() => {
		const list = [...availableInterfaces];
		if (formIface && !list.some((i) => i.name === formIface)) {
			list.unshift({
				name: formIface,
				mac: null,
				is_physical: false,
				is_up: true,
				carrier_up: true,
				ips: [],
				bus_type: "configured",
			});
		}
		return list;
	});

	// Editable form fields
	let formEnabled = $state(true);
	let formIface = $state("end0");
	let formManaged = $state(false);
	let formOtherConfig = $state(false);
	let formHopLimit = $state(64);
	let formPriority = $state<RouterPriority>("medium");
	let formMaxInterval = $state(200);
	let formMinInterval = $state<number | null>(null);
	let formLifetime = $state<number | null>(null);
	let formReachableTime = $state(0);
	let formRetransTimer = $state(0);
	let formMtu = $state<number | null>(null);

	// Editable arrays
	let formPrefixes = $state<RaPrefix[]>([]);
	let formRdnss = $state<string[]>([]);
	let formDnssl = $state<string[]>([]);

	// Form helpers for adding new items
	let newPrefixStr = $state("");
	let newPrefixAutonomous = $state(true);
	let newPrefixOnLink = $state(true);
	let newRdnssAddr = $state("");
	let newDnsslDomain = $state("");

	function syncFormFromConfig(c: RaServerConfig) {
		formEnabled = c.enabled;
		formIface = c.iface ?? (availableInterfaces[0]?.name || "end0");
		formManaged = c.managed;
		formOtherConfig = c.other_config;
		formHopLimit = c.hop_limit;
		formPriority = c.priority;
		formMaxInterval = c.max_interval_secs;
		formMinInterval = c.min_interval_secs ?? null;
		formLifetime = c.lifetime_secs ?? null;
		formReachableTime = c.reachable_time_ms;
		formRetransTimer = c.retrans_timer_ms;
		formMtu = c.mtu ?? null;
		formPrefixes = JSON.parse(JSON.stringify(c.prefixes || []));

		// Flatten RDNSS addresses
		const rdnssList: string[] = [];
		for (const r of c.rdnss || []) {
			for (const addr of r.servers || []) {
				if (!rdnssList.includes(addr)) rdnssList.push(addr);
			}
		}
		formRdnss = rdnssList;

		// Flatten DNSSL domains
		const dnsslList: string[] = [];
		for (const d of c.dnssl || []) {
			for (const dom of d.domains || []) {
				if (!dnsslList.includes(dom)) dnsslList.push(dom);
			}
		}
		formDnssl = dnsslList;
	}

	async function loadAll(silent = false) {
		if (!silent) loading = true;
		try {
			const [s, c, setupRes] = await Promise.all([
				raStatus().catch(() => null),
				raConfig().catch(() => null),
				getSetupStatus().catch(() => null),
			]);
			status = s;
			if (setupRes?.interfaces) {
				availableInterfaces = setupRes.interfaces;
			}
			if (c && (!config || !silent)) {
				config = c;
				syncFormFromConfig(c);
			}
		} catch (err) {
			console.error("Failed to load RA data:", err);
			if (!silent) toast.error("Failed to load Router Advertisement details");
		} finally {
			if (!silent) loading = false;
		}
	}


	async function handleSaveConfig() {
		saving = true;
		try {
			const rdnssObj: RdnssConfig[] = formRdnss.length > 0
				? [{ servers: formRdnss, lifetime: null }]
				: [];
			const dnsslObj: DnsslConfig[] = formDnssl.length > 0
				? [{ domains: formDnssl, lifetime: null }]
				: [];

			const payload: RaServerConfig = {
				enabled: formEnabled,
				iface: formIface.trim() || null,
				managed: formManaged,
				other_config: formOtherConfig,
				hop_limit: Number(formHopLimit) || 64,
				priority: formPriority,
				max_interval_secs: Number(formMaxInterval) || 200,
				min_interval_secs: formMinInterval ? Number(formMinInterval) : null,
				lifetime_secs: formLifetime ? Number(formLifetime) : null,
				reachable_time_ms: Number(formReachableTime) || 0,
				retrans_timer_ms: Number(formRetransTimer) || 0,
				mtu: formMtu ? Number(formMtu) : null,
				prefixes: formPrefixes,
				rdnss: rdnssObj,
				dnssl: dnsslObj,
			};

			await raUpdateConfig(payload);
			toast.success("Router Advertisement configuration updated and broadcast");
			await loadAll(true);
		} catch (err: unknown) {
			console.error("Failed to save RA config:", err);
			const msg = err instanceof Error ? err.message : "Save failed";
			toast.error(`Error saving config: ${msg}`);
		} finally {
			saving = false;
		}
	}

	async function handleTriggerBurst() {
		triggering = true;
		try {
			await raTrigger();
			toast.success("Immediate Router Advertisement burst broadcast");
			await loadAll(true);
		} catch (err: unknown) {
			console.error("Failed to trigger RA:", err);
			toast.error("Failed to trigger advertisement burst");
		} finally {
			triggering = false;
		}
	}

	function handleDiscard() {
		if (config) {
			syncFormFromConfig(config);
			toast.info("Changes reverted to active configuration");
		}
	}

	function formatPrefixLabel(pref: RaPrefix): string {
		if (pref.source === "auto_gua") {
			return status?.active_gua_prefix
				? `${status.active_gua_prefix}/${pref.prefix_len || 64}`
				: `dynamic_gua (/${pref.prefix_len || 64})`;
		}
		if (pref.source === "ula" && !pref.address) {
			return status?.active_ula_prefix
				? `${status.active_ula_prefix}/${pref.prefix_len || 64}`
				: `dynamic_ula (/${pref.prefix_len || 64})`;
		}
		if (pref.address) {
			return `${pref.address}/${pref.prefix_len || 64}`;
		}
		return `${pref.source} (/${pref.prefix_len || 64})`;
	}

	function getPrefixKey(pref: RaPrefix, index: number): string {
		return `${index}-${pref.source}-${pref.address ?? "auto"}-${pref.prefix_len}`;
	}

	function addPrefix() {
		const p = newPrefixStr.trim();
		if (!p) {
			toast.error("Prefix cannot be empty");
			return;
		}

		let source: PrefixSource = "static";
		let address: string | null = p;
		let prefixLen = 64;

		if (p.toLowerCase() === "dynamic_gua" || p.toLowerCase() === "auto_gua") {
			source = "auto_gua";
			address = null;
		} else if (p.toLowerCase() === "dynamic_ula" || p.toLowerCase() === "auto_ula") {
			source = "ula";
			address = null;
		} else if (p.includes("/")) {
			const parts = p.split("/");
			address = parts[0];
			prefixLen = Number(parts[1]) || 64;
			if (address.toLowerCase().startsWith("fd") || address.toLowerCase().startsWith("fc")) {
				source = "ula";
			}
		} else if (p.toLowerCase().startsWith("fd") || p.toLowerCase().startsWith("fc")) {
			source = "ula";
		}

		const isDuplicate = formPrefixes.some((x) => {
			if (x.source !== source) return false;
			if (source === "auto_gua" || (source === "ula" && !x.address)) return true;
			return x.address?.toLowerCase() === address?.toLowerCase() && x.prefix_len === prefixLen;
		});

		if (isDuplicate) {
			toast.error("Prefix already configured");
			return;
		}

		formPrefixes = [
			...formPrefixes,
			{
				source,
				address,
				prefix_len: prefixLen,
				autonomous: newPrefixAutonomous,
				on_link: newPrefixOnLink,
				router_addr: false,
				valid_lifetime: "2592000",
				preferred_lifetime: "604800",
			},
		];
		newPrefixStr = "";
	}

	function removePrefix(index: number) {
		formPrefixes = formPrefixes.filter((_, i) => i !== index);
	}

	function addRdnss() {
		const a = newRdnssAddr.trim();
		if (!a) {
			toast.error("DNS address cannot be empty");
			return;
		}
		if (formRdnss.includes(a)) {
			toast.error("DNS server already in list");
			return;
		}
		formRdnss = [...formRdnss, a];
		newRdnssAddr = "";
	}

	function removeRdnss(index: number) {
		formRdnss = formRdnss.filter((_, i) => i !== index);
	}

	function addDnssl() {
		const d = newDnsslDomain.trim().toLowerCase();
		if (!d) {
			toast.error("Domain cannot be empty");
			return;
		}
		if (formDnssl.includes(d)) {
			toast.error("Domain already in search list");
			return;
		}
		formDnssl = [...formDnssl, d];
		newDnsslDomain = "";
	}

	function removeDnssl(index: number) {
		formDnssl = formDnssl.filter((_, i) => i !== index);
	}

	function formatSeconds(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "Never";
		if (sec < 60) return `${sec}s ago`;
		if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s ago`;
		const h = Math.floor(sec / 3600);
		const m = Math.floor((sec % 3600) / 60);
		return `${h}h ${m}m ago`;
	}

	function formatCountdown(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "—";
		if (sec === 0) return "Imminent";
		if (sec < 60) return `in ${sec}s`;
		const m = Math.floor(sec / 60);
		const s = sec % 60;
		return `in ${m}m ${s}s`;
	}

	function formatUptime(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "—";
		const days = Math.floor(sec / 86400);
		const hours = Math.floor((sec % 86400) / 3600);
		const minutes = Math.floor((sec % 3600) / 60);
		const seconds = sec % 60;
		if (days > 0) return `${days}d ${hours}h ${minutes}m`;
		if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
		if (minutes > 0) return `${minutes}m ${seconds}s`;
		return `${seconds}s`;
	}

	onMount(() => {
		loadAll();
		refreshInterval = setInterval(() => {
			loadAll(true);
		}, 5000);
	});

	onDestroy(() => {
		if (refreshInterval) clearInterval(refreshInterval);
	});
</script>

<div class="flex flex-col gap-6 p-6 max-w-7xl mx-auto w-full">
	<!-- Page Header -->
	<div class="flex flex-col md:flex-row md:items-center justify-between gap-4">
		<div class="flex flex-col gap-1">
			<div class="flex items-center gap-2">
				<RadioIcon class="size-6 text-primary" />
				<h1 class="text-2xl font-bold tracking-tight">IPv6 Router Advertisement</h1>
				{#if status?.enabled}
					<Badge variant="outline" class="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 font-medium">
						<span class="size-1.5 rounded-full bg-emerald-500 animate-pulse mr-1.5"></span>
						Active
					</Badge>
				{:else}
					<Badge variant="secondary" class="text-muted-foreground">
						Idle / Disabled
					</Badge>
				{/if}
			</div>
			<p class="text-sm text-muted-foreground">
				Autonomous SLAAC orchestration, RFC 4861/8106 ICMPv6 telemetry, and runtime parameters.
			</p>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={() => loadAll()}
				disabled={loading}
			>
				<RefreshCwIcon class={loading ? "animate-spin" : ""} data-icon="inline-start" />
				Refresh
			</Button>

			<Button
				variant="default"
				size="sm"
				onclick={handleTriggerBurst}
				disabled={triggering || !status?.enabled}
			>
				<ZapIcon class={triggering ? "animate-pulse" : ""} data-icon="inline-start" />
				Trigger RA Burst
			</Button>
		</div>
	</div>

	{#if loading && !status}
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<Skeleton class="h-32 w-full rounded-xl" />
			<Skeleton class="h-32 w-full rounded-xl" />
			<Skeleton class="h-32 w-full rounded-xl" />
		</div>
		<Skeleton class="h-96 w-full rounded-xl" />
	{:else}
		<!-- Overview Metric Cards -->
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<!-- Card 1: Operational State -->
			<Card.Root>
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between">
						<span>Operational State</span>
						<NetworkIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title class="text-lg font-semibold flex items-center gap-2">
						{status?.interface ?? "Not bound"}
					</Card.Title>
				</Card.Header>
				<Card.Content class="flex flex-col gap-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center">
						<span>Link-Local:</span>
						<span class="font-mono text-foreground">{status?.link_local ?? "—"}</span>
					</div>
					<div class="flex justify-between items-center">
						<span>GUA Delegated:</span>
						<span class="font-mono text-foreground">{status?.active_gua_prefix ?? "—"}</span>
					</div>
					<div class="flex justify-between items-center">
						<span>ULA Dynamic:</span>
						<span class="font-mono text-foreground">{status?.active_ula_prefix ?? "—"}</span>
					</div>
				</Card.Content>
			</Card.Root>

			<!-- Card 2: Packet Telemetry -->
			<Card.Root>
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between">
						<span>Packet Telemetry</span>
						<ActivityIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title class="text-lg font-semibold flex items-center gap-2">
						<span>{(status?.sent_multicast_ras ?? 0) + (status?.sent_unicast_ras ?? 0)}</span>
						<span class="text-xs font-normal text-muted-foreground">Total RAs Sent</span>
					</Card.Title>
				</Card.Header>
				<Card.Content class="flex flex-col gap-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center">
						<span>Multicast (ff02::1):</span>
						<span class="font-mono font-medium text-foreground">{status?.sent_multicast_ras ?? 0}</span>
					</div>
					<div class="flex justify-between items-center">
						<span>Unicast Responses:</span>
						<span class="font-mono font-medium text-foreground">{status?.sent_unicast_ras ?? 0}</span>
					</div>
					<div class="flex justify-between items-center">
						<span>Solicitations (RS):</span>
						<span class="font-mono font-medium text-foreground">
							{status?.received_solicitations ?? 0}
							{#if (status?.ignored_solicitations ?? 0) > 0}
								<span class="text-amber-500 font-normal">({status?.ignored_solicitations} dropped)</span>
							{/if}
						</span>
					</div>
				</Card.Content>
			</Card.Root>

			<!-- Card 3: Timing & Schedule -->
			<Card.Root>
				<Card.Header class="pb-2">
					<Card.Description class="flex items-center justify-between">
						<span>Timers & Convergence</span>
						<ClockIcon class="size-4 text-muted-foreground" />
					</Card.Description>
					<Card.Title class="text-lg font-semibold flex items-center gap-2">
						<span>{formatCountdown(status?.next_ra_in_secs)}</span>
						<span class="text-xs font-normal text-muted-foreground">Next Periodic RA</span>
					</Card.Title>
				</Card.Header>
				<Card.Content class="flex flex-col gap-1.5 text-xs text-muted-foreground">
					<div class="flex justify-between items-center">
						<span>Last RA Sent:</span>
						<span class="text-foreground">{formatSeconds(status?.last_ra_sent_secs_ago)}</span>
					</div>
					<div class="flex justify-between items-center">
						<span>Last RS Received:</span>
						<span class="text-foreground">{formatSeconds(status?.last_rs_received_secs_ago)}</span>
					</div>
					<div class="flex justify-between items-center">
						<span>Service Uptime:</span>
						<span class="text-foreground">{formatUptime(status?.uptime_secs)}</span>
					</div>
				</Card.Content>
			</Card.Root>
		</div>

		<!-- Tabs Layout -->
		<Tabs.Root value="status" class="w-full flex flex-col gap-6">
			<Tabs.List class="grid grid-cols-2 max-w-md">
				<Tabs.Trigger value="status" class="flex items-center gap-2">
					<RadioIcon class="size-4" />
					Live State
				</Tabs.Trigger>
				<Tabs.Trigger value="config" class="flex items-center gap-2">
					<SlidersIcon class="size-4" />
					Configuration
				</Tabs.Trigger>
			</Tabs.List>

			<!-- TAB 1: Live Status & Active Options -->
			<Tabs.Content value="status" class="flex flex-col gap-6">
				<!-- Active Prefixes -->
				<Card.Root>
					<Card.Header>
						<Card.Title class="text-base flex items-center justify-between">
							<span class="flex items-center gap-2">
								<GlobeIcon class="size-4 text-primary" />
								Active Advertised Prefixes
							</span>
							<Badge variant="outline" class="font-normal text-xs">
								{(status?.prefixes ?? []).length} Announced
							</Badge>
						</Card.Title>
						<Card.Description>
							Autonomous SLAAC prefixes and on-link routing prefixes broadcast to LAN hosts.
						</Card.Description>
					</Card.Header>
					<Card.Content>
						{#if (status?.prefixes ?? []).length === 0}
							<div class="p-8 text-center text-muted-foreground text-sm flex flex-col items-center justify-center gap-2">
								<AlertCircleIcon class="size-8 text-muted-foreground/50" />
								<span>No prefixes actively advertised. Check configuration or delegated WAN IPv6 state.</span>
							</div>
						{:else}
							<div class="rounded-md border">
								<Table.Root>
									<Table.Header>
										<Table.Row>
											<Table.Head>Prefix</Table.Head>
											<Table.Head>SLAAC (Autonomous)</Table.Head>
											<Table.Head>On-Link</Table.Head>
											<Table.Head>Valid Lifetime</Table.Head>
											<Table.Head>Preferred Lifetime</Table.Head>
										</Table.Row>
									</Table.Header>
									<Table.Body>
										{#each status?.prefixes ?? [] as pref, i (getPrefixKey(pref, i))}
											<Table.Row>
												<Table.Cell class="font-mono font-medium">
													{#if pref.source === "auto_gua"}
														<div class="flex items-center gap-1.5">
															<span>{status?.active_gua_prefix ? `${status.active_gua_prefix}/${pref.prefix_len || 64}` : "dynamic_gua"}</span>
															<Badge variant="secondary" class="text-[10px] px-1 py-0 font-normal">GUA</Badge>
														</div>
													{:else if pref.source === "ula" && !pref.address}
														<div class="flex items-center gap-1.5">
															<span>{status?.active_ula_prefix ? `${status.active_ula_prefix}/${pref.prefix_len || 64}` : "dynamic_ula"}</span>
															<Badge variant="secondary" class="text-[10px] px-1 py-0 font-normal">ULA</Badge>
														</div>
													{:else}
														<div class="flex items-center gap-1.5">
															<span>{pref.address ? `${pref.address}/${pref.prefix_len || 64}` : `${pref.source} (/${pref.prefix_len || 64})`}</span>
															<Badge variant="outline" class="text-[10px] px-1 py-0 font-normal capitalize">{pref.source}</Badge>
														</div>
													{/if}
												</Table.Cell>
												<Table.Cell>
													{#if pref.autonomous ?? true}
														<Badge variant="outline" class="bg-emerald-500/10 text-emerald-600 border-emerald-500/20 text-xs">
															Enabled (A=1)
														</Badge>
													{:else}
														<Badge variant="secondary" class="text-xs">Disabled (A=0)</Badge>
													{/if}
												</Table.Cell>
												<Table.Cell>
													{#if pref.on_link ?? true}
														<Badge variant="outline" class="bg-blue-500/10 text-blue-600 border-blue-500/20 text-xs">
															On-Link (L=1)
														</Badge>
													{:else}
														<Badge variant="secondary" class="text-xs">Off-Link (L=0)</Badge>
													{/if}
												</Table.Cell>
												<Table.Cell class="text-muted-foreground text-xs font-mono">
													{pref.valid_lifetime ? `${pref.valid_lifetime}` : "Default (30 days)"}
												</Table.Cell>
												<Table.Cell class="text-muted-foreground text-xs font-mono">
													{pref.preferred_lifetime ? `${pref.preferred_lifetime}` : "Default (7 days)"}
												</Table.Cell>
											</Table.Row>
										{/each}
									</Table.Body>
								</Table.Root>
							</div>
						{/if}

						{#if (status?.deprecated_prefixes ?? []).length > 0}
							<div class="mt-4 p-4 rounded-lg bg-amber-500/10 border border-amber-500/20 flex flex-col gap-2">
								<div class="flex items-center gap-2 text-amber-600 font-semibold text-sm">
									<AlertCircleIcon class="size-4" />
									<span>Deprecated Prefixes (RFC 9096 Graceful Invalidation)</span>
								</div>
								<p class="text-xs text-amber-700 dark:text-amber-400">
									The following obsolete prefixes are broadcast with Preferred Lifetime = 0 to rapidly revoke them from client routing tables:
								</p>
								<div class="flex flex-wrap gap-2 pt-1">
									{#each status?.deprecated_prefixes ?? [] as [pfx, remaining], i (`deprecated-${i}-${pfx}`)}
										<Badge variant="outline" class="font-mono text-xs border-amber-500/30 text-amber-600 bg-background">
											{pfx} ({remaining}s remaining)
										</Badge>
									{/each}
								</div>
							</div>
						{/if}
					</Card.Content>
				</Card.Root>

				<!-- DNS & Timing Parameters Grid -->
				<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
					<!-- Card: RDNSS and DNSSL -->
					<Card.Root>
						<Card.Header>
							<Card.Title class="text-base flex items-center gap-2">
								<ServerIcon class="size-4 text-primary" />
								DNS Options Announced (RFC 8106)
							</Card.Title>
							<Card.Description>
								Recursive DNS servers (RDNSS) and search lists (DNSSL) distributed in RA packets.
							</Card.Description>
						</Card.Header>
						<Card.Content class="flex flex-col gap-4">
							<div class="flex flex-col gap-2">
								<Label class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">RDNSS Servers</Label>
								{#if (status?.rdnss ?? []).flatMap(r => r.servers || []).length === 0}
									<span class="text-xs text-muted-foreground italic">None configured (clients fall back to local link-local or DHCPv6)</span>
								{:else}
									<div class="flex flex-wrap gap-1.5">
										{#each (status?.rdnss ?? []).flatMap(r => r.servers || []) as addr, i (`rdnss-${i}-${addr}`)}
											<Badge variant="secondary" class="font-mono text-xs">
												{addr}
											</Badge>
										{/each}
									</div>
								{/if}
							</div>

							<Separator />

							<div class="flex flex-col gap-2">
								<Label class="text-xs font-semibold text-muted-foreground uppercase tracking-wider">DNSSL Search Domains</Label>
								{#if (status?.dnssl ?? []).flatMap(d => d.domains || []).length === 0}
									<span class="text-xs text-muted-foreground italic">None configured</span>
								{:else}
									<div class="flex flex-wrap gap-1.5">
										{#each (status?.dnssl ?? []).flatMap(d => d.domains || []) as domain, i (`dnssl-${i}-${domain}`)}
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
						<Card.Header>
							<Card.Title class="text-base flex items-center gap-2">
								<SlidersIcon class="size-4 text-primary" />
								Protocol Parameters
							</Card.Title>
							<Card.Description>
								Timing intervals, hop limit, and router priority currently enforced by daemon.
							</Card.Description>
						</Card.Header>
						<Card.Content class="flex flex-col gap-2.5 text-sm">
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
								<span class="font-mono text-xs">{status?.min_interval_secs ?? 66}s – {status?.max_interval_secs ?? 200}s</span>
							</div>
							<div class="flex justify-between items-center">
								<span class="text-muted-foreground">Default Router Lifetime:</span>
								<span class="font-mono text-xs">{status?.router_lifetime_secs ?? 600}s</span>
							</div>
							<div class="flex justify-between items-center">
								<span class="text-muted-foreground">Current Hop Limit:</span>
								<span class="font-mono text-xs">{status?.hop_limit ?? 64}</span>
							</div>
							<div class="flex justify-between items-center">
								<span class="text-muted-foreground">Link MTU:</span>
								<span class="font-mono text-xs">{status?.mtu ?? "Unspecified (Interface MTU)"}</span>
							</div>
						</Card.Content>
					</Card.Root>
				</div>
			</Tabs.Content>

			<!-- TAB 2: Runtime Configuration -->
			<Tabs.Content value="config" class="flex flex-col gap-6">
				<!-- General Settings -->
				<Card.Root>
					<Card.Header>
						<Card.Title class="text-base">General Service Settings</Card.Title>
						<Card.Description>
							Global operational state and primary flags controlling client IPv6 address auto-configuration.
						</Card.Description>
					</Card.Header>
					<Card.Content class="flex flex-col gap-6">
						<div class="flex items-center justify-between">
							<div class="flex flex-col gap-0.5">
								<Label class="text-sm font-medium">Service Enabled</Label>
								<p class="text-xs text-muted-foreground">
									Start the ICMPv6 listener and periodic broadcast engine on target interface.
								</p>
							</div>
							<Switch bind:checked={formEnabled} />
						</div>

						<Separator />

						<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
							<div class="flex flex-col gap-1.5">
								<Label class="text-xs font-medium">Network Interface</Label>
								{#if interfaceOptions.length > 0}
									<Select.Root
										type="single"
										value={formIface}
										onValueChange={(val) => {
											if (val) formIface = val;
										}}
									>
										<Select.Trigger class="h-9 text-xs font-mono">
											{formIface || "Select interface..."}
										</Select.Trigger>
										<Select.Content>
											{#each interfaceOptions as iface (iface.name)}
												<Select.Item value={iface.name} class="text-xs">
													<div class="flex items-center justify-between w-full gap-3">
														<div class="flex items-center gap-2">
															<span class="font-mono font-medium">{iface.name}</span>
															{#if iface.carrier_up}
																<span class="size-1.5 rounded-full bg-emerald-500" title="Link active"></span>
															{:else}
																<span class="size-1.5 rounded-full bg-muted-foreground/40" title="Link down"></span>
															{/if}
														</div>
														<div class="flex items-center gap-1.5 text-[10px] text-muted-foreground">
															{#if iface.is_physical}
																<Badge variant="secondary" class="text-[9px] px-1 py-0 font-normal">Physical</Badge>
															{/if}
															{#if iface.ips && iface.ips.length > 0}
																<span class="truncate max-w-[120px] font-mono text-[10px]">{iface.ips[0]}</span>
															{/if}
														</div>
													</div>
												</Select.Item>
											{/each}
										</Select.Content>
									</Select.Root>
								{:else}
									<Input
										id="ra-iface"
										bind:value={formIface}
										placeholder="end0"
										class="h-9 font-mono text-xs"
									/>
								{/if}
								<p class="text-[11px] text-muted-foreground">LAN interface to bind raw ICMPv6 socket to.</p>
							</div>


							<div class="flex flex-col gap-1.5">
								<Label class="text-xs font-medium">Router Priority (RFC 4191)</Label>
								<Select.Root
									type="single"
									value={formPriority}
									onValueChange={(val) => (formPriority = (val as RouterPriority) ?? "medium")}
								>
									<Select.Trigger class="h-9 text-xs capitalize">
										{formPriority}
									</Select.Trigger>
									<Select.Content>
										<Select.Item value="high" class="text-xs">High (Preferred Default Router)</Select.Item>
										<Select.Item value="medium" class="text-xs">Medium (Default)</Select.Item>
										<Select.Item value="low" class="text-xs">Low (Secondary / Backup)</Select.Item>
									</Select.Content>
								</Select.Root>
								<p class="text-[11px] text-muted-foreground">Influences client default router preference.</p>
							</div>
						</div>

						<Separator />

						<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
							<div class="flex items-start justify-between gap-4">
								<div class="flex flex-col gap-0.5">
									<Label class="text-sm font-medium">Managed Flag (M-Flag)</Label>
									<p class="text-xs text-muted-foreground">
										Instructs hosts to use stateful DHCPv6 for IP addresses instead of SLAAC.
									</p>
								</div>
								<Switch bind:checked={formManaged} />
							</div>

							<div class="flex items-start justify-between gap-4">
								<div class="flex flex-col gap-0.5">
									<Label class="text-sm font-medium">Other Config Flag (O-Flag)</Label>
									<p class="text-xs text-muted-foreground">
										Instructs hosts to query DHCPv6 for non-address parameters (DNS, NTP, domain search).
									</p>
								</div>
								<Switch bind:checked={formOtherConfig} />
							</div>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- Timing & Lifetime Parameters -->
				<Card.Root>
					<Card.Header>
						<Card.Title class="text-base">Timing & Intervals (RFC 4861 §6.2.1)</Card.Title>
						<Card.Description>
							Broadcast intervals, client default gateway lifetime, and neighbor discovery timers.
						</Card.Description>
					</Card.Header>
					<Card.Content class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
						<div class="flex flex-col gap-1.5">
							<Label for="ra-max-interval" class="text-xs font-medium">Max Adv Interval (s)</Label>
							<Input
								id="ra-max-interval"
								type="number"
								min="4"
								max="1800"
								bind:value={formMaxInterval}
								class="h-9 font-mono text-xs"
							/>
							<p class="text-[11px] text-muted-foreground">Maximum time between periodic RAs (default 200s).</p>
						</div>

						<div class="flex flex-col gap-1.5">
							<Label for="ra-min-interval" class="text-xs font-medium">Min Adv Interval (s)</Label>
							<Input
								id="ra-min-interval"
								type="number"
								min="3"
								placeholder="Automatic (1/3 of max)"
								value={formMinInterval ?? ""}
								oninput={(e) => {
									const val = e.currentTarget.value;
									formMinInterval = val ? Number(val) : null;
								}}
								class="h-9 font-mono text-xs"
							/>
							<p class="text-[11px] text-muted-foreground">Leave empty for automatic RFC 4861 ratio.</p>
						</div>

						<div class="flex flex-col gap-1.5">
							<Label for="ra-lifetime" class="text-xs font-medium">Router Lifetime (s)</Label>
							<Input
								id="ra-lifetime"
								type="number"
								min="0"
								max="9000"
								placeholder="Automatic (3x max)"
								value={formLifetime ?? ""}
								oninput={(e) => {
									const val = e.currentTarget.value;
									formLifetime = val ? Number(val) : null;
								}}
								class="h-9 font-mono text-xs"
							/>
							<p class="text-[11px] text-muted-foreground">0 = do not use as default router.</p>
						</div>

						<div class="flex flex-col gap-1.5">
							<Label for="ra-hop-limit" class="text-xs font-medium">Suggested Hop Limit</Label>
							<Input
								id="ra-hop-limit"
								type="number"
								min="0"
								max="255"
								bind:value={formHopLimit}
								class="h-9 font-mono text-xs"
							/>
							<p class="text-[11px] text-muted-foreground">Default is 64. 0 = unspecified.</p>
						</div>

						<div class="flex flex-col gap-1.5">
							<Label for="ra-mtu" class="text-xs font-medium">Advertised MTU</Label>
							<Input
								id="ra-mtu"
								type="number"
								min="1280"
								max="9000"
								placeholder="Automatic"
								value={formMtu ?? ""}
								oninput={(e) => {
									const val = e.currentTarget.value;
									formMtu = val ? Number(val) : null;
								}}
								class="h-9 font-mono text-xs"
							/>
							<p class="text-[11px] text-muted-foreground">Useful for 1492 over PPPoE.</p>
						</div>

						<div class="flex flex-col gap-1.5">
							<Label for="ra-reachable" class="text-xs font-medium">Reachable Time (ms)</Label>
							<Input
								id="ra-reachable"
								type="number"
								min="0"
								bind:value={formReachableTime}
								class="h-9 font-mono text-xs"
							/>
							<p class="text-[11px] text-muted-foreground">0 = unspecified by this router.</p>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- Prefix Information Options (PIO) Manager -->
				<Card.Root>
					<Card.Header>
						<Card.Title class="text-base">Prefix Information Options (PIO)</Card.Title>
						<Card.Description>
							Announced IPv6 prefixes. Use <span class="font-mono text-foreground font-semibold">dynamic_gua</span> for WAN DHCPv6-PD delegated prefix, and <span class="font-mono text-foreground font-semibold">dynamic_ula</span> for stable internal addresses.
						</Card.Description>
					</Card.Header>
					<Card.Content class="flex flex-col gap-4">
						<div class="flex flex-col sm:flex-row items-end gap-3 p-3 rounded-lg border bg-muted/40">
							<div class="flex-1 flex flex-col gap-1.5 w-full">
								<Label for="new-prefix" class="text-xs font-medium">Add Prefix</Label>
								<Input
									id="new-prefix"
									bind:value={newPrefixStr}
									placeholder="dynamic_gua or 2001:db8:1::/64"
									class="h-9 font-mono text-xs"
								/>
							</div>

							<div class="flex items-center gap-4">
								<div class="flex items-center gap-2">
									<Switch id="auto-slaac" bind:checked={newPrefixAutonomous} />
									<Label for="auto-slaac" class="text-xs">SLAAC (A)</Label>
								</div>
								<div class="flex items-center gap-2">
									<Switch id="on-link" bind:checked={newPrefixOnLink} />
									<Label for="on-link" class="text-xs">On-link (L)</Label>
								</div>
							</div>

							<Button size="sm" variant="secondary" onclick={addPrefix} class="h-9">
								<PlusIcon class="size-4" data-icon="inline-start" />
								Add
							</Button>
						</div>

						<div class="rounded-md border overflow-hidden">
							<Table.Root>
								<Table.Header>
									<Table.Row>
										<Table.Head>Prefix</Table.Head>
										<Table.Head>SLAAC (A-flag)</Table.Head>
										<Table.Head>On-Link (L-flag)</Table.Head>
										<Table.Head class="text-right">Actions</Table.Head>
									</Table.Row>
								</Table.Header>
								<Table.Body>
									{#if formPrefixes.length === 0}
										<Table.Row>
											<Table.Cell colspan={4} class="text-center text-xs text-muted-foreground py-6">
												No prefixes defined. RA daemon will stay idle.
											</Table.Cell>
										</Table.Row>
									{:else}
										{#each formPrefixes as pref, i (getPrefixKey(pref, i))}
											<Table.Row>
												<Table.Cell class="font-mono text-xs font-medium">
													{formatPrefixLabel(pref)}
												</Table.Cell>
												<Table.Cell>
													<Switch
														checked={pref.autonomous ?? true}
														onCheckedChange={(c) => (pref.autonomous = c)}
													/>
												</Table.Cell>
												<Table.Cell>
													<Switch
														checked={pref.on_link ?? true}
														onCheckedChange={(c) => (pref.on_link = c)}
													/>
												</Table.Cell>
												<Table.Cell class="text-right">
													<Button
														variant="ghost"
														size="icon"
														class="size-8 text-destructive hover:text-destructive"
														onclick={() => removePrefix(i)}
													>
														<Trash2Icon class="size-4" />
													</Button>
												</Table.Cell>
											</Table.Row>
										{/each}
									{/if}
								</Table.Body>
							</Table.Root>
						</div>
					</Card.Content>
				</Card.Root>

				<!-- RDNSS and DNSSL Config -->
				<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
					<!-- RDNSS Input -->
					<Card.Root>
						<Card.Header>
							<Card.Title class="text-base">Recursive DNS Servers (RDNSS)</Card.Title>
							<Card.Description>
								IPv6 addresses of recursive DNS nameservers advertised directly via RA.
							</Card.Description>
						</Card.Header>
						<Card.Content class="flex flex-col gap-3">
							<div class="flex gap-2">
								<Input
									bind:value={newRdnssAddr}
									placeholder="2001:4860:4860::8888 or fe80::1"
									class="h-9 font-mono text-xs"
									onkeydown={(e) => e.key === "Enter" && addRdnss()}
								/>
								<Button size="sm" variant="secondary" onclick={addRdnss} class="h-9">
									<PlusIcon class="size-4" data-icon="inline-start" />
									Add
								</Button>
							</div>

							<div class="flex flex-wrap gap-2 pt-2">
								{#if formRdnss.length === 0}
									<span class="text-xs text-muted-foreground italic">No specific RDNSS servers added.</span>
								{:else}
									{#each formRdnss as addr, i (`form-rdnss-${i}-${addr}`)}
										<Badge variant="secondary" class="font-mono text-xs flex items-center gap-1.5 py-1">
											<span>{addr}</span>
											<button
												type="button"
												class="text-muted-foreground hover:text-destructive transition-colors ml-1"
												onclick={() => removeRdnss(i)}
											>
												&times;
											</button>
										</Badge>
									{/each}
								{/if}
							</div>
						</Card.Content>
					</Card.Root>

					<!-- DNSSL Input -->
					<Card.Root>
						<Card.Header>
							<Card.Title class="text-base">Domain Search List (DNSSL)</Card.Title>
							<Card.Description>
								DNS search suffix domains distributed to IPv6 clients.
							</Card.Description>
						</Card.Header>
						<Card.Content class="flex flex-col gap-3">
							<div class="flex gap-2">
								<Input
									bind:value={newDnsslDomain}
									placeholder="lan or home.arpa"
									class="h-9 font-mono text-xs"
									onkeydown={(e) => e.key === "Enter" && addDnssl()}
								/>
								<Button size="sm" variant="secondary" onclick={addDnssl} class="h-9">
									<PlusIcon class="size-4" data-icon="inline-start" />
									Add
								</Button>
							</div>

							<div class="flex flex-wrap gap-2 pt-2">
								{#if formDnssl.length === 0}
									<span class="text-xs text-muted-foreground italic">No search domains added.</span>
								{:else}
									{#each formDnssl as dom, i (`form-dnssl-${i}-${dom}`)}
										<Badge variant="outline" class="text-xs flex items-center gap-1.5 py-1">
											<span>{dom}</span>
											<button
												type="button"
												class="text-muted-foreground hover:text-destructive transition-colors ml-1"
												onclick={() => removeDnssl(i)}
											>
												&times;
											</button>
										</Badge>
									{/each}
								{/if}
							</div>
						</Card.Content>
					</Card.Root>
				</div>

				<!-- Save Action Bar -->
				<div class="flex items-center justify-end gap-3 pt-2">
					<Button
						variant="outline"
						onclick={handleDiscard}
						disabled={saving}
					>
						<RotateCcwIcon data-icon="inline-start" />
						Discard Changes
					</Button>

					<Button
						variant="default"
						onclick={handleSaveConfig}
						disabled={saving}
					>
						<SaveIcon class={saving ? "animate-spin" : ""} data-icon="inline-start" />
						{saving ? "Applying..." : "Save Configuration"}
					</Button>
				</div>
			</Tabs.Content>
		</Tabs.Root>
	{/if}
</div>
