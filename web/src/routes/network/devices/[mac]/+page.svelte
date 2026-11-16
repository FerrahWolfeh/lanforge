<script lang="ts">
	import { page } from "$app/state";
	import { goto } from "$app/navigation";
	import { onDestroy, onMount, type Snippet } from "svelte";
	import { toast } from "svelte-sonner";
	import { auth } from "$lib/stores/auth.svelte";
	import {
		whois,
		deviceDns,
		wol,
		purge,
		deviceRules,
		dnsAdblockGroups,
		dnsBlock,
		dnsAllow,
		hostList,
		hostSet,
		eventsUrl,
		leaseRenew,
		leaseRelease,
	} from "$lib/api/client";
	import {
		formatRewriteAnswer,
		type DeviceDnsResponse,
		type DeviceEntry,
		type HostConfigEntry,
		type DevicePortForward,
		type DeviceRulesResponse,
		type PortForwardRule,
	} from "$lib/api/types";
	import { createDebounce, formatTimeAgo, copyToClipboard } from "$lib/utils";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import StatusLine from "$lib/components/StatusLine.svelte";
	import StatStrip, { type StatStripItem } from "$lib/components/StatStrip.svelte";
	import DeviceAdblockModal from "../components/DeviceAdblockModal.svelte";
	import DeviceLinkedModal from "../components/DeviceLinkedModal.svelte";
	import DeviceDnsPanel from "./components/DeviceDnsPanel.svelte";
	import DeviceHostSheet from "./components/DeviceHostSheet.svelte";
	import DeviceRecentQueries from "./components/DeviceRecentQueries.svelte";

	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import ChevronRightIcon from "@lucide/svelte/icons/chevron-right";
	import PowerIcon from "@lucide/svelte/icons/power";
	import BookmarkIcon from "@lucide/svelte/icons/bookmark";
	import PencilIcon from "@lucide/svelte/icons/pencil";
	import EllipsisIcon from "@lucide/svelte/icons/ellipsis";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import FingerprintIcon from "@lucide/svelte/icons/fingerprint";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ShieldBanIcon from "@lucide/svelte/icons/shield-ban";

	const mac = $derived(page.params.mac ?? "");

	let device = $state<DeviceEntry | null>(null);
	let notFound = $state(false);
	let dns = $state<DeviceDnsResponse | null>(null);
	let dnsLoading = $state(true);
	let rules = $state<DeviceRulesResponse | null>(null);
	let adblock = $state<string | null>(null);

	let hostOpen = $state(false);
	/** The device already has a static host rule (the sheet then edits it and can remove it). */
	let hostReserved = $state(false);
	/** What the reservation sheet starts from: the existing rule, or the device as it is now. */
	let hostEntry = $state<HostConfigEntry | null>(null);
	let adblockOpen = $state(false);
	let linkedOpen = $state(false);
	let eventSource: EventSource | null = null;
	let dnsTimer: ReturnType<typeof setInterval> | undefined;

	async function loadDevice() {
		try {
			device = (await whois(mac)).entry;
			notFound = false;
		} catch (err: any) {
			if (err?.status === 404) notFound = true;
			else toast.error(err?.message ?? "Failed to load the device");
		}
	}

	/** `quiet` refreshes in place: no skeleton, and the last data is kept on failure. */
	async function loadDns(quiet = false) {
		if (!quiet) dnsLoading = true;
		try {
			dns = await deviceDns(mac);
		} catch {
			if (!quiet) dns = null;
		} finally {
			if (!quiet) dnsLoading = false;
		}
	}

	async function loadAdblock() {
		try {
			const res = await dnsAdblockGroups();
			const m = mac.toLowerCase();
			const has = (clients: { devices: { mac: string }[] }[]) =>
				clients.some((c) => c.devices.some((d) => d.mac.toLowerCase() === m));
			if (has(res.bypass)) adblock = "bypassed, never filtered";
			else {
				const groups = res.groups.filter((g) => has(g.clients)).map((g) => g.name);
				adblock = groups.length ? groups.join(", ") : "global lists only";
			}
		} catch {
			adblock = null;
		}
	}

	async function loadRules() {
		try {
			rules = await deviceRules(mac);
		} catch {
			rules = null;
		}
	}

	function loadAll() {
		loadDevice();
		loadDns();
		loadAdblock();
		loadRules();
	}

	// Name bindings and forward targets move with the device's addresses and names.
	const debouncedDevice = createDebounce(() => {
		loadDevice();
		loadRules();
	}, 500);

	onMount(() => {
		try {
			eventSource = new EventSource(eventsUrl({ filter: "device" }));
			eventSource.onmessage = (event) => {
				// Other devices' events are not for this page.
				if (String(event.data).toLowerCase().includes(mac.toLowerCase())) debouncedDevice();
			};
		} catch {
			// no live updates
		}
		dnsTimer = setInterval(() => loadDns(true), 60_000);
	});
	onDestroy(() => {
		debouncedDevice.cancel();
		eventSource?.close();
		eventSource = null;
		clearInterval(dnsTimer);
	});

	$effect(() => {
		if (mac) loadAll();
	});

	// --- what the page shows -------------------------------------------------------------

	/** The daemon sends "?" for a device that never told its name. */
	const named = $derived(Boolean(device?.hostname) && device?.hostname !== "?");
	const name = $derived(named ? (device?.hostname as string) : "Unnamed device");
	const v4 = $derived(device?.v4?.ip ?? device?.primary_v4 ?? null);
	const v4Reserved = $derived(Boolean(device?.v4?.reserved));
	const myForwards = $derived(rules?.port_forwards ?? []);
	const myRewrites = $derived(rules?.rewrites ?? []);

	/** The families a forward asks for: a `dev:` rule both unless limited, an address its own. */
	function families(f: DevicePortForward): { v4: boolean; v6: boolean } {
		if (!f.by_device) return { v4: !f.rule.internal_ip.includes(":"), v6: f.rule.internal_ip.includes(":") };
		return { v4: f.rule.family !== "ipv6", v6: f.rule.family !== "ipv4" };
	}
	/** "both" is TCP and UDP; the daemon's protocol names are otherwise shown upper-cased. */
	const protocolLabel = (p: PortForwardRule["protocol"]) => {
		const s = String(p).toLowerCase();
		return s === "both" ? "TCP+UDP" : s.toUpperCase();
	};
	const port = (r: PortForwardRule) => `${protocolLabel(r.protocol)} ${r.external_port}`;

	/** Only what is wrong: nothing is shown when the device is fine. */
	const problems = $derived.by(() => {
		const out: { title: string; text: string; action?: "reserve" }[] = [];
		if (!device) return out;
		if (rules?.refused_name) {
			out.push({
				title: `Announced the name ${rules.refused_name.name},`,
				text: ` but rules bind that name to ${rules.refused_name.owner}, so this device keeps its own name.`,
			});
		}
		const pinned = myForwards.filter((f) => !f.by_device && f.rule.internal_ip === v4);
		if (pinned.length && !v4Reserved) {
			out.push({
				title: `${pinned.map((f) => port(f.rule)).join(", ")} forwards to ${v4},`,
				text: " but that address is a dynamic lease: it can move to another device. Reserve it, or point the rule at the device.",
				action: "reserve",
			});
		}
		// Where the daemon sends them: a side with no target reaches nothing.
		const noV4 = myForwards.filter((f) => f.by_device && families(f).v4 && !rules?.forward_v4);
		if (noV4.length) {
			out.push({
				title: "No IPv4 lease or reservation:",
				text: ` the IPv4 side of ${noV4.map((f) => port(f.rule)).join(", ")} reaches nothing.`,
				action: "reserve",
			});
		}
		const noV6 = myForwards.filter((f) => f.by_device && families(f).v6 && !rules?.forward_v6.length);
		if (noV6.length && device.online) {
			out.push({
				title: "No stable IPv6 address:",
				text: ` the IPv6 side of ${noV6.map((f) => port(f.rule)).join(", ")} reaches nothing. Pinholes need a DHCPv6 lease or a reserved suffix; temporary (SLAAC) addresses are never used.`,
			});
		}
		if (!device.online && myForwards.length) {
			out.push({
				title: `Offline since ${formatTimeAgo(device.last_seen)}:`,
				text: ` ${myForwards.length === 1 ? "the port forwarded" : `the ${myForwards.length} ports forwarded`} to it get no answer.`,
			});
		}
		return out;
	});

	const strip = $derived.by((): StatStripItem[] => {
		const off = dns?.logging_off;
		const total = dnsLoading && !dns ? null : off || !dns ? "—" : dns.total;
		const blocked = dnsLoading && !dns ? null : off || !dns ? "—" : dns.blocked;
		return [
			{ label: off ? "DNS not logged" : "DNS queries, 24 h", value: total, icon: GlobeIcon },
			{
				label: "blocked, 24 h",
				value: blocked,
				icon: ShieldBanIcon,
				...(dns && !off && dns.total > 0 ? { bar: dns.blocked / dns.total, barTone: "danger" as const } : {}),
			},
			{ label: "ports open from the internet", value: device ? myForwards.length : null, icon: ArrowRightLeftIcon },
		];
	});

	function leaseText(): string {
		if (!device?.v4) return "";
		const expires = Number(device.v4.expires);
		if (device.origin === "Static" && v4Reserved) return "reserved in lanforge.toml";
		if (v4Reserved) return "reserved";
		if (expires > 0) {
			const left = expires - Date.now() / 1000;
			if (left > 0) {
				const h = Math.floor(left / 3600);
				const m = Math.floor((left % 3600) / 60);
				return `dynamic lease, ${h > 0 ? `${h}h ${m}m` : `${m}m`} left`;
			}
			return "dynamic lease, expired";
		}
		return "seen on the network, not leased";
	}

	const seenVia = $derived(
		[device?.learning_method, device?.iface, device?.vlan_id ? `VLAN ${device.vlan_id}` : null]
			.filter(Boolean)
			.join(" · ")
	);

	// --- actions ---------------------------------------------------------------------------

	async function wake() {
		try {
			await wol(mac);
			toast.success(`Wake-on-LAN sent to ${name}`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to send Wake-on-LAN");
		}
	}

	async function openHost() {
		if (!device) return;
		let existing: HostConfigEntry | null = null;
		if (device.origin === "Static") {
			try {
				const hosts = await hostList();
				existing = hosts.find((h) => h.mac.toLowerCase() === mac.toLowerCase()) ?? null;
			} catch (err: any) {
				toast.error(err?.message ?? "Failed to load the static host");
				return;
			}
		}
		hostReserved = existing !== null;
		hostEntry = existing ?? {
			mac: device.mac,
			hostname: named ? device.hostname : "",
			v4_fixed: v4 ?? undefined,
			v6_suffix: undefined,
			ignore_dns_log: device.ignore_dns_log,
			ignored_log_domains: device.ignored_log_domains,
		};
		hostOpen = true;
	}

	async function forget() {
		if (!confirm(`Forget ${name}? Its addresses and history are removed; it comes back when seen again.`)) return;
		try {
			await purge(mac);
			toast.success(`${name} forgotten`);
			goto("/network/devices");
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to forget the device");
		}
	}

	async function setLogging(off: boolean) {
		try {
			await hostSet(mac, "ignore_dns_log", off ? "true" : "false");
			toast.success(off ? `Queries of ${name} are no longer logged` : `Queries of ${name} are logged again`);
			await Promise.all([loadDevice(), loadDns()]);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to change DNS logging");
		}
	}

	const dynamicLease = $derived(Boolean(device?.v4) && !v4Reserved && Number(device?.v4?.expires ?? 0) > 0);

	async function leaseAction(kind: "renew" | "release") {
		if (kind === "release" && !confirm(`Release the IPv4 lease of ${name}? The device loses the address until it asks again.`)) return;
		try {
			if (kind === "renew") {
				await leaseRenew(mac, "V4");
				toast.success(`IPv4 lease of ${name} renewed`);
			} else {
				await leaseRelease(mac, "V4");
				toast.success(`IPv4 lease of ${name} released`);
			}
			await loadDevice();
		} catch (err: any) {
			toast.error(err?.message ?? `Failed to ${kind} the IPv4 lease`);
		}
	}

	async function dnsRule(domain: string, action: "block" | "allow") {
		try {
			if (action === "block") {
				await dnsBlock(domain);
				toast.success(`${domain} blocked for every device`);
			} else {
				await dnsAllow(domain);
				toast.success(`${domain} allowed for every device`);
			}
			await loadDns();
		} catch (err: any) {
			toast.error(err?.message ?? `Failed to ${action} ${domain}`);
		}
	}

	const canDevice = $derived(auth.can("device_write"));
	const canDns = $derived(auth.can("dns_write"));
	const canFirewall = $derived(auth.can("config_write"));
	/** A new forward targets the device by name (by MAC when it has none), so it follows the device. */
	const forwardHref = $derived(
		`/firewall?forward_to=${encodeURIComponent(`dev:${named ? device?.hostname : mac}`)}` +
			(named ? `&forward_name=${encodeURIComponent(name)}` : "")
	);
	const kindLabel: Record<string, string> = { Gua: "global", Ula: "local", LinkLocal: "link-local" };
</script>

<svelte:head>
	<title>{name} — Devices — Lanforge</title>
</svelte:head>

{#snippet row(key: string, value: string, sub?: string, mono = false, actions?: Snippet)}
	<div class="grid grid-cols-[96px_minmax(0,1fr)] items-start gap-3 px-3 py-2 text-sm">
		<span class="pt-0.5 text-xs text-muted-foreground">{key}</span>
		<span class="min-w-0 break-words">
			<span class={mono ? "font-mono text-xs" : ""}>{value}</span>
			{#if sub}<span class="block text-xs text-muted-foreground">{sub}</span>{/if}
			{#if actions}<span class="mt-1 flex gap-1">{@render actions()}</span>{/if}
		</span>
	</div>
{/snippet}

{#snippet leaseActions()}
	<Button variant="ghost" size="xs" onclick={() => leaseAction("renew")}>Renew</Button>
	<Button variant="ghost" size="xs" onclick={() => leaseAction("release")}>Release</Button>
{/snippet}

<div class="flex flex-col gap-4">
	<nav class="flex items-center gap-1.5 text-sm text-muted-foreground" aria-label="Breadcrumb">
		<a href="/network/devices" class="hover:text-foreground">Devices</a>
		<ChevronRightIcon class="size-3.5" />
		<span class="truncate text-foreground">{device ? name : mac}</span>
	</nav>

	{#if notFound}
		<StatusLine tone="warning" title="Device not found:" text=" {mac} is not known to the router (it may have been forgotten)." href="/network/devices" linkLabel="All devices" />
	{:else if !device}
		<div class="flex flex-col gap-3">
			<Skeleton class="h-11 w-64" />
			<Skeleton class="h-16 w-full" />
			<Skeleton class="h-64 w-full" />
		</div>
	{:else}
		<!-- Header -->
		<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div class="flex min-w-0 items-center gap-3">
				<span class="relative flex size-11 shrink-0 items-center justify-center rounded-lg border border-border bg-muted">
					<MonitorIcon class="size-5" />
					<span
						class="absolute -right-1 -bottom-1 size-3 rounded-full border-2 border-background {device.online ? 'bg-success' : 'bg-muted-foreground'}"
					></span>
				</span>
				<div class="flex min-w-0 flex-col">
					<h1 class="truncate text-xl font-semibold tracking-tight">{name}</h1>
					<div class="flex flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs text-muted-foreground">
						<span>{device.online ? "Online" : "Offline"} · seen {formatTimeAgo(device.last_seen).toLowerCase()}</span>
						<span aria-hidden="true">·</span>
						<span class="font-mono">{device.mac}</span>
						{#if device.origin === "Static"}
							<span class="rounded bg-selected px-1.5 py-0.5 text-selected-foreground">static host</span>
						{/if}
					</div>
				</div>
			</div>
			<div class="flex items-center gap-2">
				{#if canDevice}
					<Button variant="outline" size="sm" onclick={wake} title="Wake-on-LAN">
						<PowerIcon /><span class="max-sm:hidden">Wake</span>
					</Button>
					<Button size="sm" onclick={openHost} class="max-sm:flex-1">
						{#if device.origin === "Static"}<PencilIcon />Edit name and address{:else}<BookmarkIcon />Reserve{/if}
					</Button>
				{/if}
				<DropdownMenu.Root>
					<DropdownMenu.Trigger
						class="inline-flex size-8 items-center justify-center rounded-md border border-border hover:bg-muted"
						aria-label="More actions"
					>
						<EllipsisIcon class="size-4" />
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="end" class="w-48 text-xs">
						<DropdownMenu.Item onclick={() => copyToClipboard(device?.mac ?? "", "MAC")} class="gap-2">
							<CopyIcon class="size-3.5" />Copy MAC address
						</DropdownMenu.Item>
						{#if v4}
							<DropdownMenu.Item onclick={() => copyToClipboard(v4 ?? "", "IPv4")} class="gap-2">
								<CopyIcon class="size-3.5" />Copy IPv4 address
							</DropdownMenu.Item>
						{/if}
						{#if canDevice}
							<DropdownMenu.Separator />
							<DropdownMenu.Item onclick={forget} class="gap-2 text-danger">
								<Trash2Icon class="size-3.5" />Forget device
							</DropdownMenu.Item>
						{/if}
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</div>
		</div>

		{#each problems as p (p.title)}
			<StatusLine tone="warning" title={p.title}>
				{p.text}
				{#if p.action === "reserve" && canDevice}
					<Button size="xs" variant="outline" class="ml-2" onclick={openHost}>{v4 ? `Reserve ${v4}` : "Reserve an address"}</Button>
				{/if}
			</StatusLine>
		{/each}

		<StatStrip items={strip} />

		<div class="grid gap-4 lg:grid-cols-2 lg:items-start">
			<div class="flex min-w-0 flex-col gap-4">
				<!-- Addresses -->
				<section class="rounded-lg border border-border bg-card">
					<header class="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
						<h2 class="flex items-center gap-2 text-sm font-semibold">
							<NetworkIcon class="size-4 text-muted-foreground" />Addresses
						</h2>
					</header>
					<div class="divide-y divide-border">
						{#if v4}
							{@render row("IPv4", v4, leaseText(), true, canDevice && dynamicLease ? leaseActions : undefined)}
						{/if}
						{#each device.ipv6_addrs ?? [] as a (a.addr)}
							{@render row(`IPv6 ${kindLabel[a.kind] ?? a.kind.toLowerCase()}`, a.addr, undefined, true)}
						{/each}
						{#if !v4 && !(device.ipv6_addrs ?? []).length}
							<p class="px-3 py-2 text-sm text-muted-foreground">No address known right now.</p>
						{/if}
						<div class="grid grid-cols-[96px_minmax(0,1fr)_auto] items-start gap-3 px-3 py-2 text-sm">
							<span class="pt-0.5 text-xs text-muted-foreground">Linked</span>
							<span class="min-w-0">
								{#each device.linked_addresses ?? [] as a (a)}
									<span class="block font-mono text-xs">{a}</span>
								{:else}
									<span class="text-xs text-muted-foreground">none</span>
								{/each}
								<span class="block text-xs text-muted-foreground">VPN or tailnet addresses counted as this device</span>
							</span>
							{#if canDevice}
								<Button variant="ghost" size="xs" onclick={() => (linkedOpen = true)}><PencilIcon />Edit</Button>
							{/if}
						</div>
					</div>
				</section>

				<!-- Port forwards and pinholes -->
				<section class="rounded-lg border border-border bg-card">
					<header class="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
						<h2 class="flex items-center gap-2 text-sm font-semibold">
							<ArrowRightLeftIcon class="size-4 text-muted-foreground" />Reachable from the internet
						</h2>
					</header>
					{#if myForwards.length === 0}
						<p class="px-3 py-2.5 text-sm text-muted-foreground">No port is forwarded to this device.</p>
					{:else}
						<ul class="divide-y divide-border">
							{#each myForwards as f (f.index)}
								{@const fam = families(f)}
								<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
									<span class="flex min-w-32 items-center gap-1 font-mono text-xs font-medium">
										{port(f.rule)}<ArrowRightIcon class="size-3 text-muted-foreground" />{f.rule.internal_port}
									</span>
									<span class="min-w-0 flex-1">
										{f.rule.comment || "Port forward"}
										<span class="block text-xs text-muted-foreground">
											{f.by_device ? `to ${f.rule.internal_ip}, follows the device` : `to ${f.rule.internal_ip} only`}{f.rule.enable_hairpin ? " · hairpin" : ""}
										</span>
									</span>
									<span class="rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground">
										{fam.v4 && fam.v6 ? "IPv4 + IPv6" : fam.v6 ? "IPv6" : "IPv4"}
									</span>
								</li>
							{/each}
						</ul>
					{/if}
					<footer class="flex justify-end gap-4 border-t border-border px-3 py-2 text-xs">
						{#if canFirewall}
							<a href={forwardHref} class="font-medium text-selected-foreground hover:underline">Forward a port</a>
						{/if}
						<a href="/firewall" class="font-medium text-selected-foreground hover:underline">Firewall →</a>
					</footer>
				</section>

				<!-- Name and identity -->
				<section class="rounded-lg border border-border bg-card">
					<header class="flex items-center justify-between gap-2 border-b border-border px-3 py-2.5">
						<h2 class="flex items-center gap-2 text-sm font-semibold">
							<FingerprintIcon class="size-4 text-muted-foreground" />Name and identity
						</h2>
					</header>
					<div class="divide-y divide-border">
						{@render row(
							"Name",
							name,
							device.origin === "Static"
								? "set in lanforge.toml"
								: rules?.bound_names.length
									? `bound to this device by rules naming dev:${rules.bound_names.join(", dev:")}`
									: "as the device announces it"
						)}
						{#each myRewrites as r (`${r.domain}-${r.rtype}`)}
							{@render row("DNS name", r.domain, `${r.rtype} → ${formatRewriteAnswer(r.answer)}`, true)}
						{/each}
						{#if device.class && device.class !== "None" && device.class !== "Unknown"}
							{@render row("Type", device.class)}
						{/if}
						{#if device.duid}
							{@render row("DUID", device.duid, undefined, true)}
						{/if}
						{#if seenVia}
							{@render row("Seen via", seenVia)}
						{/if}
					</div>
				</section>
			</div>

			<div class="flex min-w-0 flex-col gap-4">
				<DeviceDnsPanel
					{dns}
					loading={dnsLoading}
					{adblock}
					onEditAdblock={canDns ? () => (adblockOpen = true) : undefined}
					onRule={canDns ? dnsRule : undefined}
				/>
				<DeviceRecentQueries
					{mac}
					loggingOff={Boolean(device.ignore_dns_log)}
					ignoredDomains={device.ignored_log_domains ?? []}
					canEdit={canDevice}
					onChanged={loadDevice}
					onToggleLogging={canDevice ? setLogging : undefined}
				/>
			</div>
		</div>
	{/if}
</div>

{#if device && hostEntry}
	<DeviceHostSheet
		bind:open={hostOpen}
		mac={device.mac}
		name={named ? name : device.mac}
		reserved={hostReserved}
		initial={hostEntry}
		onSaved={async () => {
			await Promise.all([loadDevice(), loadRules()]);
		}}
	/>
{/if}
<DeviceAdblockModal bind:open={adblockOpen} {device} onSaved={loadAdblock} />
<DeviceLinkedModal bind:open={linkedOpen} {device} onSaved={loadDevice} />
