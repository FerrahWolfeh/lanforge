<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import LayersIcon from "@lucide/svelte/icons/layers";

	import {
		dhcpOptionsGet,
		dhcpOptionsUpdate,
		dhcpPoolsConfigGet,
		dhcpPoolsConfigUpdate,
	} from "$lib/api/client";
	import type {
		DhcpOptionsConfig,
		Dhcpv4PoolConfig,
		Dhcpv6PoolConfig,
	} from "$lib/api/types";

	let loading = $state(true);
	let saving = $state(false);

	// Original pristine copies for dirty checking
	let pristineOptionsJson = $state("");
	let pristinePoolsJson = $state("");

	// Working state
	let v4Pools = $state<Dhcpv4PoolConfig[]>([]);
	let v6Pools = $state<Dhcpv6PoolConfig[]>([]);
	let activeUlaPrefix = $state<string | null>(null);
	let activeGuaPrefix = $state<string | null>(null);

	// Global / Fallback Options
	let globalV4Enabled = $state(true);
	let globalV4LeaseTime = $state(86400);
	let globalV4Router = $state("192.168.0.1");
	let globalV4SubnetMask = $state("255.255.255.0");
	let globalV4DnsStr = $state("192.168.0.1");
	let globalV4DomainName = $state("");
	let globalV4SearchDomainsStr = $state("");
	let globalV4NtpStr = $state("162.159.200.1, 216.239.35.0");
	let globalV4TftpServer = $state("");
	let globalV4BootFile = $state("");

	let globalV6Enabled = $state(true);
	let globalV6LeaseTime = $state(86400);
	let globalV6DnsStr = $state("");
	let globalV6SearchDomainsStr = $state("");
	let globalV6NtpStr = $state("time.cloudflare.com, time.google.com");
	let globalV6BootFile = $state("");

	// Custom Raw Options
	let v4RawOptions = $state<Array<{ code: number; value: string }>>([]);
	let v6RawOptions = $state<Array<{ code: number; value: string }>>([]);
	let newRawV4Code = $state<number | "">("");
	let newRawV4Value = $state("");
	let newRawV6Code = $state<number | "">("");
	let newRawV6Value = $state("");

	// Modals
	let addV4ModalOpen = $state(false);
	let newV4Name = $state("");
	let newV4Start = $state("");
	let newV4End = $state("");
	let newV4Router = $state("");
	let newV4SubnetMask = $state("255.255.255.0");
	let newV4Dns = $state("");
	let newV4Lease = $state<number | "">(86400);

	let addV6ModalOpen = $state(false);
	let newV6Name = $state("");
	let newV6Start = $state("");
	let newV6End = $state("");
	let newV6Addr = $state("");
	let newV6Dns = $state("");
	let newV6Lease = $state<number | "">(86400);

	function parseList(str: string): string[] {
		return str
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
	}

	function currentOptionsPayload(): DhcpOptionsConfig {
		const v4RawMap: Record<number, string> = {};
		for (const opt of v4RawOptions) {
			if (opt.code && opt.value) v4RawMap[opt.code] = opt.value;
		}
		const v6RawMap: Record<number, string> = {};
		for (const opt of v6RawOptions) {
			if (opt.code && opt.value) v6RawMap[opt.code] = opt.value;
		}

		return {
			v4: {
				enabled: globalV4Enabled,
				lease_time: Number(globalV4LeaseTime) || 86400,
				router: globalV4Router.trim() || null,
				subnet_mask: globalV4SubnetMask.trim() || null,
				dns_servers: parseList(globalV4DnsStr),
				domain_name: globalV4DomainName.trim() || null,
				search_domains: parseList(globalV4SearchDomainsStr),
				ntp_servers: parseList(globalV4NtpStr),
				tftp_server: globalV4TftpServer.trim() || null,
				boot_file: globalV4BootFile.trim() || null,
				raw_options: v4RawMap,
			},
			v6: {
				enabled: globalV6Enabled,
				lease_time: Number(globalV6LeaseTime) || 86400,
				dns_servers: parseList(globalV6DnsStr),
				search_domains: parseList(globalV6SearchDomainsStr),
				ntp_servers: parseList(globalV6NtpStr),
				boot_file: globalV6BootFile.trim() || null,
				raw_options: v6RawMap,
			},
			tftp: {
				enabled: false,
				listen_addr: "0.0.0.0:69",
				root_dir: "/var/lib/lanforge/tftp",
				block_size: 512,
				timeout: 5,
				max_retries: 3,
			},
		};
	}

	// Dirty tracking
	const isDirty = $derived.by(() => {
		if (loading) return false;
		const currentOptStr = JSON.stringify(currentOptionsPayload());
		const currentPoolStr = JSON.stringify({
			v4_pools: v4Pools,
			v6_pools: v6Pools,
		});
		return (
			currentOptStr !== pristineOptionsJson ||
			currentPoolStr !== pristinePoolsJson
		);
	});

	async function loadConfig() {
		loading = true;
		try {
			const [opts, pools] = await Promise.all([
				dhcpOptionsGet(),
				dhcpPoolsConfigGet(),
			]);

			v4Pools = JSON.parse(JSON.stringify(pools.v4_pools));
			v6Pools = JSON.parse(JSON.stringify(pools.v6_pools));
			activeUlaPrefix = pools.active_ula_prefix ?? "fd00::/64";
			activeGuaPrefix = pools.active_gua_prefix ?? null;

			// Populate global options
			globalV4Enabled = opts.v4?.enabled ?? true;
			globalV4LeaseTime = opts.v4?.lease_time ?? 86400;
			globalV4Router = opts.v4?.router ?? "";
			globalV4SubnetMask = opts.v4?.subnet_mask ?? "255.255.255.0";
			globalV4DnsStr = (opts.v4?.dns_servers ?? []).join(", ");
			globalV4DomainName = opts.v4?.domain_name ?? "";
			globalV4SearchDomainsStr = (opts.v4?.search_domains ?? []).join(
				", ",
			);
			globalV4NtpStr = (opts.v4?.ntp_servers ?? []).join(", ");
			globalV4TftpServer = opts.v4?.tftp_server ?? "";
			globalV4BootFile = opts.v4?.boot_file ?? "";

			v4RawOptions = Object.entries(opts.v4?.raw_options ?? {}).map(
				([k, v]) => ({
					code: Number(k),
					value: v,
				}),
			);

			globalV6Enabled = opts.v6?.enabled ?? true;
			globalV6LeaseTime = opts.v6?.lease_time ?? 86400;
			globalV6DnsStr = (opts.v6?.dns_servers ?? []).join(", ");
			globalV6SearchDomainsStr = (opts.v6?.search_domains ?? []).join(
				", ",
			);
			globalV6NtpStr = (opts.v6?.ntp_servers ?? []).join(", ");
			globalV6BootFile = opts.v6?.boot_file ?? "";

			v6RawOptions = Object.entries(opts.v6?.raw_options ?? {}).map(
				([k, v]) => ({
					code: Number(k),
					value: v,
				}),
			);

			pristineOptionsJson = JSON.stringify(currentOptionsPayload());
			pristinePoolsJson = JSON.stringify({
				v4_pools: v4Pools,
				v6_pools: v6Pools,
			});
		} catch (err: any) {
			toast.error(`Failed to load DHCP scopes: ${err.message}`);
		} finally {
			loading = false;
		}
	}

	async function saveAll() {
		saving = true;
		try {
			const optionsPayload = currentOptionsPayload();
			await Promise.all([
				dhcpOptionsUpdate(optionsPayload),
				dhcpPoolsConfigUpdate(v4Pools, v6Pools),
			]);

			pristineOptionsJson = JSON.stringify(optionsPayload);
			pristinePoolsJson = JSON.stringify({
				v4_pools: v4Pools,
				v6_pools: v6Pools,
			});
			toast.success("DHCP scopes and parameters saved successfully");
		} catch (err: any) {
			toast.error(`Failed to save configuration: ${err.message}`);
		} finally {
			saving = false;
		}
	}

	function discardChanges() {
		loadConfig();
		toast.info("Changes discarded");
	}

	// Add IPv4 Scope
	function openAddV4() {
		newV4Name = `LAN Scope ${v4Pools.length + 1}`;
		newV4Start = "";
		newV4End = "";
		newV4Router = globalV4Router;
		newV4SubnetMask = globalV4SubnetMask;
		newV4Dns = globalV4DnsStr;
		newV4Lease = 86400;
		addV4ModalOpen = true;
	}

	function submitAddV4() {
		if (!newV4Start.trim() || !newV4End.trim()) {
			toast.error("Range start and range end are required");
			return;
		}
		const pool: Dhcpv4PoolConfig = {
			name: newV4Name.trim() || null,
			range_start: newV4Start.trim(),
			range_end: newV4End.trim(),
			subnet_mask: newV4SubnetMask.trim() || null,
			router: newV4Router.trim() || null,
			dns_servers: parseList(newV4Dns),
			lease_time: newV4Lease ? Number(newV4Lease) : null,
		};
		v4Pools = [...v4Pools, pool];
		addV4ModalOpen = false;
		toast.info("Added new IPv4 scope. Click 'Save Scopes' to apply.");
	}

	function deleteV4Pool(index: number) {
		v4Pools = v4Pools.filter((_, i) => i !== index);
		toast.info("Removed IPv4 scope. Click 'Save Scopes' to apply.");
	}

	// Add IPv6 Scope
	function openAddV6() {
		newV6Name = `IPv6 Scope ${v6Pools.length + 1}`;
		newV6Start = "::100";
		newV6End = "::1fff";
		newV6Addr = "";
		newV6Dns = globalV6DnsStr;
		newV6Lease = 86400;
		addV6ModalOpen = true;
	}

	function submitAddV6() {
		if (!newV6Addr.trim() && (!newV6Start.trim() || !newV6End.trim())) {
			toast.error(
				"Either start/end suffix or static CIDR address is required",
			);
			return;
		}
		const pool: Dhcpv6PoolConfig = {
			name: newV6Name.trim() || null,
			range_start: newV6Start.trim() || null,
			range_end: newV6End.trim() || null,
			address: newV6Addr.trim() || null,
			dns_servers: parseList(newV6Dns),
			lease_time: newV6Lease ? Number(newV6Lease) : null,
		};
		v6Pools = [...v6Pools, pool];
		addV6ModalOpen = false;
		toast.info("Added new IPv6 scope. Click 'Save Scopes' to apply.");
	}

	function deleteV6Pool(index: number) {
		v6Pools = v6Pools.filter((_, i) => i !== index);
		toast.info("Removed IPv6 scope. Click 'Save Scopes' to apply.");
	}

	// Raw Options
	function addV4Raw() {
		if (!newRawV4Code || !newRawV4Value.trim()) return;
		v4RawOptions = [
			...v4RawOptions,
			{ code: Number(newRawV4Code), value: newRawV4Value.trim() },
		];
		newRawV4Code = "";
		newRawV4Value = "";
	}

	function removeV4Raw(index: number) {
		v4RawOptions = v4RawOptions.filter((_, i) => i !== index);
	}

	function addV6Raw() {
		if (!newRawV6Code || !newRawV6Value.trim()) return;
		v6RawOptions = [
			...v6RawOptions,
			{ code: Number(newRawV6Code), value: newRawV6Value.trim() },
		];
		newRawV6Code = "";
		newRawV6Value = "";
	}

	function removeV6Raw(index: number) {
		v6RawOptions = v6RawOptions.filter((_, i) => i !== index);
	}

	function formatPrefixSuffix(
		prefix: string | null,
		suffix: string | null,
	): string {
		if (!prefix || !suffix) return "—";
		const base = prefix.split("/")[0].replace(/::$/, "");
		const suf = suffix.replace(/^::/, "");
		return `${base}::${suf}`;
	}

	onMount(() => {
		loadConfig();
	});
</script>

<svelte:head>
	<title>Options & Scopes — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6 relative">
	<!-- Top Sticky Unsaved Changes Bar -->
	{#if isDirty}
		<div
			class="sticky top-2 z-30 flex items-center justify-between gap-4 p-3 px-4 rounded-xl border border-amber-500/40 bg-amber-500/10 backdrop-blur shadow-lg animate-in fade-in slide-in-from-top-2 duration-200"
		>
			<div class="flex items-center gap-2 text-amber-500">
				<AlertTriangleIcon class="h-4 w-4 shrink-0" />
				<span class="text-xs sm:text-sm font-medium">
					You have unsaved changes in your DHCP scope configuration.
				</span>
			</div>
			<div class="flex items-center gap-2">
				<Button
					variant="ghost"
					size="sm"
					class="h-8 text-xs text-muted-foreground hover:text-foreground"
					onclick={discardChanges}
					disabled={saving}
				>
					Discard
				</Button>
				<Button
					size="sm"
					class="h-8 text-xs bg-amber-600 hover:bg-amber-700 text-white shadow"
					onclick={saveAll}
					disabled={saving}
				>
					{#if saving}
						<RefreshCwIcon
							class="h-3.5 w-3.5 animate-spin mr-1.5"
						/>
						Saving...
					{:else}
						<SaveIcon class="h-3.5 w-3.5 mr-1.5" />
						Save Scopes
					{/if}
				</Button>
			</div>
		</div>
	{/if}

	<!-- Section Header -->
	<div
		class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
	>
		<div>
			<h2 class="text-xl font-bold tracking-tight">
				Scope & Option Management
			</h2>
			<p class="text-muted-foreground text-sm">
				Configure independent IPv4/IPv6 DHCP scopes, subnet parameters,
				DNS resolvers, and network boot options.
			</p>
		</div>

		<div class="flex items-center gap-2">
			<Button variant="outline" size="sm" onclick={openAddV4}>
				<PlusIcon data-icon="inline-start" />
				Add IPv4 Scope
			</Button>
			<Button variant="outline" size="sm" onclick={openAddV6}>
				<PlusIcon data-icon="inline-start" />
				Add IPv6 Scope
			</Button>
			<Button
				size="sm"
				onclick={saveAll}
				disabled={loading || saving || !isDirty}
			>
				{#if saving}
					<RefreshCwIcon
						class="animate-spin"
						data-icon="inline-start"
					/>
					Saving...
				{:else}
					<SaveIcon data-icon="inline-start" />
					Save All
				{/if}
			</Button>
		</div>
	</div>

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
			{#each { length: 4 } as _, i (i)}
				<Card.Root>
					<Card.Header>
						<Skeleton class="h-6 w-48" />
						<Skeleton class="h-4 w-64 mt-2" />
					</Card.Header>
					<Card.Content class="space-y-4">
						<Skeleton class="h-10 w-full" />
						<Skeleton class="h-10 w-full" />
					</Card.Content>
				</Card.Root>
			{/each}
		</div>
	{:else}
		<!-- 1. IPv4 SCOPES -->
		<div class="space-y-4">
			<div class="flex items-center justify-between border-b pb-2">
				<div class="flex items-center gap-2">
					<ServerIcon class="h-5 w-5 text-blue-500" />
					<h3 class="text-base font-bold tracking-tight">
						IPv4 Address Scopes
					</h3>
					<Badge variant="outline" class="font-mono text-xs"
						>{v4Pools.length} Scope{v4Pools.length === 1
							? ""
							: "s"}</Badge
					>
				</div>
				<label
					class="flex items-center gap-2 cursor-pointer text-xs font-medium"
				>
					<input
						type="checkbox"
						class="rounded border-border text-primary focus:ring-primary h-4 w-4"
						bind:checked={globalV4Enabled}
					/>
					<span>DHCPv4 Server Active</span>
				</label>
			</div>

			{#if v4Pools.length === 0}
				<Card.Root class="border-dashed bg-muted/10">
					<Card.Content class="p-8 text-center space-y-3">
						<NetworkIcon
							class="h-8 w-8 text-muted-foreground/40 mx-auto"
						/>
						<div class="text-sm font-semibold">
							No Dynamic IPv4 Scopes Configured
						</div>
						<p
							class="text-xs text-muted-foreground max-w-md mx-auto"
						>
							The server is currently operating with static
							reservations only. Add an IPv4 address scope to
							start handing out dynamic leases.
						</p>
						<Button size="sm" onclick={openAddV4}>
							<PlusIcon class="h-4 w-4 mr-1.5" />
							Add Primary IPv4 Scope
						</Button>
					</Card.Content>
				</Card.Root>
			{:else}
				<div class="grid grid-cols-1 xl:grid-cols-2 gap-5">
					{#each v4Pools as pool, idx (idx)}
						<Card.Root
							class="overflow-hidden border-border/80 shadow-sm hover:border-primary/40 transition-colors"
						>
							<Card.Header class="bg-muted/30 border-b pb-3.5">
								<div class="flex items-center justify-between">
									<div class="space-y-0.5">
										<div class="flex items-center gap-2">
											<Badge
												variant="outline"
												class="font-mono text-[10px] text-blue-500 border-blue-500/30"
											>
												IPv4 Scope #{idx + 1}
											</Badge>
											<span
												class="font-bold text-sm text-foreground"
											>
												{pool.name ||
													`${pool.range_start} – ${pool.range_end}`}
											</span>
										</div>
										<p
											class="text-xs text-muted-foreground font-mono"
										>
											Dynamic Range: <span
												class="text-emerald-400 font-medium"
												>{pool.range_start}</span
											>
											to
											<span
												class="text-emerald-400 font-medium"
												>{pool.range_end}</span
											>
										</p>
									</div>

									<Button
										variant="ghost"
										size="icon"
										class="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10"
										onclick={() => deleteV4Pool(idx)}
										title="Delete Scope"
									>
										<Trash2Icon class="h-4 w-4" />
									</Button>
								</div>
							</Card.Header>

							<Card.Content class="p-4 space-y-4">
								<div
									class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"
								>
									<div class="space-y-1">
										<Label class="text-xs">Scope Name</Label
										>
										<Input
											bind:value={pool.name}
											placeholder="e.g. Primary LAN Scope"
											class="text-xs"
										/>
									</div>
									<div class="space-y-1">
										<Label class="text-xs"
											>Subnet Mask</Label
										>
										<Input
											bind:value={pool.subnet_mask}
											placeholder={globalV4SubnetMask ||
												"255.255.255.0"}
											class="font-mono text-xs"
										/>
									</div>
								</div>

								<div
									class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"
								>
									<div class="space-y-1">
										<Label class="text-xs"
											>Range Start</Label
										>
										<Input
											bind:value={pool.range_start}
											placeholder="192.168.0.100"
											class="font-mono text-xs"
										/>
									</div>
									<div class="space-y-1">
										<Label class="text-xs">Range End</Label>
										<Input
											bind:value={pool.range_end}
											placeholder="192.168.0.240"
											class="font-mono text-xs"
										/>
									</div>
								</div>

								<div
									class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"
								>
									<div class="space-y-1">
										<Label class="text-xs"
											>Default Gateway (Option 3)</Label
										>
										<Input
											bind:value={pool.router}
											placeholder={globalV4Router ||
												"192.168.0.1"}
											class="font-mono text-xs"
										/>
									</div>
									<div class="space-y-1">
										<Label class="text-xs"
											>Lease Duration (Seconds)</Label
										>
										<Input
											type="number"
											bind:value={pool.lease_time}
											placeholder={String(
												globalV4LeaseTime,
											)}
											class="font-mono text-xs"
										/>
									</div>
								</div>

								<!-- DNS & Domain -->
								<div class="space-y-1">
									<Label class="text-xs"
										>DNS Servers (Option 6)</Label
									>
									<Input
										value={(pool.dns_servers ?? []).join(
											", ",
										)}
										oninput={(e) =>
											(pool.dns_servers = parseList(
												(e.target as HTMLInputElement)
													.value,
											))}
										placeholder={globalV4DnsStr ||
											"192.168.0.1"}
										class="font-mono text-xs"
									/>
								</div>

								<!-- Boot Options -->
								<div
									class="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-2 border-t text-xs"
								>
									<div class="space-y-1">
										<Label
											class="text-xs text-muted-foreground"
											>Boot File (Opt 67)</Label
										>
										<Input
											bind:value={pool.boot_file}
											placeholder="ipxe.efi, pxelinux.0"
											class="font-mono text-xs"
										/>
									</div>
									<div class="space-y-1">
										<Label
											class="text-xs text-muted-foreground"
											>Next Server (Opt 66)</Label
										>
										<Input
											bind:value={pool.tftp_server}
											placeholder="192.168.0.1"
											class="font-mono text-xs"
										/>
									</div>
								</div>
							</Card.Content>
						</Card.Root>
					{/each}
				</div>
			{/if}
		</div>

		<!-- 2. IPv6 SCOPES WITH DYNAMIC ULA & GUA PREVIEW -->
		<div class="space-y-4 pt-4">
			<div class="flex items-center justify-between border-b pb-2">
				<div class="flex items-center gap-2">
					<GlobeIcon class="h-5 w-5 text-purple-500" />
					<h3 class="text-base font-bold tracking-tight">
						IPv6 Address Scopes
					</h3>
					<Badge variant="outline" class="font-mono text-xs"
						>{v6Pools.length} Scope{v6Pools.length === 1
							? ""
							: "s"}</Badge
					>
				</div>
				<label
					class="flex items-center gap-2 cursor-pointer text-xs font-medium"
				>
					<input
						type="checkbox"
						class="rounded border-border text-primary focus:ring-primary h-4 w-4"
						bind:checked={globalV6Enabled}
					/>
					<span>DHCPv6 Server Active</span>
				</label>
			</div>

			{#if v6Pools.length === 0}
				<Card.Root class="border-dashed bg-muted/10">
					<Card.Content class="p-8 text-center space-y-3">
						<GlobeIcon
							class="h-8 w-8 text-muted-foreground/40 mx-auto"
						/>
						<div class="text-sm font-semibold">
							No Dynamic IPv6 Scopes Configured
						</div>
						<p
							class="text-xs text-muted-foreground max-w-md mx-auto"
						>
							Clients will use SLAAC autonomous address
							configuration only. Add an IPv6 suffix scope to
							enable stateful IA_NA/IA_PD leases.
						</p>
						<Button size="sm" onclick={openAddV6}>
							<PlusIcon class="h-4 w-4 mr-1.5" />
							Add Floating IPv6 Suffix Scope
						</Button>
					</Card.Content>
				</Card.Root>
			{:else}
				<div class="grid grid-cols-1 xl:grid-cols-2 gap-5">
					{#each v6Pools as pool, idx (idx)}
						{@const isSuffixPool = Boolean(
							pool.range_start || pool.range_end,
						)}
						<Card.Root
							class="overflow-hidden border-border/80 shadow-sm hover:border-primary/40 transition-colors"
						>
							<Card.Header class="bg-muted/30 border-b pb-3.5">
								<div class="flex items-center justify-between">
									<div class="space-y-0.5">
										<div class="flex items-center gap-2">
											<Badge
												variant="outline"
												class="font-mono text-[10px] text-purple-500 border-purple-500/30"
											>
												{isSuffixPool
													? "Floating Suffix Scope"
													: "Static CIDR Scope"}
											</Badge>
											<span
												class="font-bold text-sm text-foreground"
											>
												{pool.name ||
													(isSuffixPool
														? `${pool.range_start} – ${pool.range_end}`
														: pool.address)}
											</span>
										</div>
										<p
											class="text-xs text-muted-foreground font-mono"
										>
											{#if isSuffixPool}
												Suffix Bounds: <span
													class="text-sky-400 font-medium"
													>{pool.range_start}</span
												>
												to
												<span
													class="text-sky-400 font-medium"
													>{pool.range_end}</span
												>
											{:else}
												Static CIDR: <span
													class="text-sky-400 font-medium"
													>{pool.address}</span
												>
											{/if}
										</p>
									</div>

									<Button
										variant="ghost"
										size="icon"
										class="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10"
										onclick={() => deleteV6Pool(idx)}
										title="Delete Scope"
									>
										<Trash2Icon class="h-4 w-4" />
									</Button>
								</div>
							</Card.Header>

							<Card.Content class="p-4 space-y-4">
								<!-- Multi-Prefix Resolution Banner for Suffix Pools -->
								{#if isSuffixPool}
									<div
										class="rounded-lg p-3 bg-muted/40 border text-xs space-y-2"
									>
										<div
											class="font-semibold text-foreground flex items-center gap-1.5"
										>
											<LayersIcon
												class="h-3.5 w-3.5 text-primary"
											/>
											Active Dual-Prefix Range Resolution:
										</div>
										<div
											class="grid grid-cols-1 sm:grid-cols-2 gap-2 font-mono text-[11px]"
										>
											<div
												class="bg-background/80 p-2 rounded border space-y-0.5"
											>
												<div
													class="text-muted-foreground text-[10px] uppercase font-sans font-semibold"
												>
													🏠 Local ULA Scope ({activeUlaPrefix ||
														"fd00::/64"})
												</div>
												<div
													class="text-sky-400 font-medium truncate"
												>
													{formatPrefixSuffix(
														activeUlaPrefix ||
															"fd00::/64",
														pool.range_start ??
															"::100",
													)} → {formatPrefixSuffix(
														activeUlaPrefix ||
															"fd00::/64",
														pool.range_end ??
															"::1fff",
													)}
												</div>
											</div>
											<div
												class="bg-background/80 p-2 rounded border space-y-0.5"
											>
												<div
													class="text-muted-foreground text-[10px] uppercase font-sans font-semibold"
												>
													🌐 Global GUA Scope ({activeGuaPrefix ||
														"Dynamic Upstream"})
												</div>
												<div
													class="text-purple-400 font-medium truncate"
												>
													{#if activeGuaPrefix}
														{formatPrefixSuffix(
															activeGuaPrefix,
															pool.range_start ??
																"::100",
														)} → {formatPrefixSuffix(
															activeGuaPrefix,
															pool.range_end ??
																"::1fff",
														)}
													{:else}
														Follows Delegated WAN
														/64 Prefix
													{/if}
												</div>
											</div>
										</div>
									</div>
								{/if}

								<div
									class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"
								>
									<div class="space-y-1">
										<Label class="text-xs">Scope Name</Label
										>
										<Input
											bind:value={pool.name}
											placeholder="e.g. Primary IPv6 Scope"
											class="text-xs"
										/>
									</div>
									<div class="space-y-1">
										<Label class="text-xs"
											>Lease Duration (Seconds)</Label
										>
										<Input
											type="number"
											bind:value={pool.lease_time}
											placeholder={String(
												globalV6LeaseTime,
											)}
											class="font-mono text-xs"
										/>
									</div>
								</div>

								{#if isSuffixPool}
									<div
										class="grid grid-cols-1 sm:grid-cols-2 gap-3.5"
									>
										<div class="space-y-1">
											<Label class="text-xs"
												>Lower Suffix Bound</Label
											>
											<Input
												bind:value={pool.range_start}
												placeholder="::100"
												class="font-mono text-xs"
											/>
										</div>
										<div class="space-y-1">
											<Label class="text-xs"
												>Upper Suffix Bound</Label
											>
											<Input
												bind:value={pool.range_end}
												placeholder="::1fff"
												class="font-mono text-xs"
											/>
										</div>
									</div>
								{:else}
									<div class="space-y-1">
										<Label class="text-xs"
											>Static Subnet CIDR</Label
										>
										<Input
											bind:value={pool.address}
											placeholder="2001:db8:1::/64"
											class="font-mono text-xs"
										/>
									</div>
								{/if}

								<!-- DNS & Boot -->
								<div class="space-y-1">
									<Label class="text-xs"
										>DNS Servers (Option 23)</Label
									>
									<Input
										value={(pool.dns_servers ?? []).join(
											", ",
										)}
										oninput={(e) =>
											(pool.dns_servers = parseList(
												(e.target as HTMLInputElement)
													.value,
											))}
										placeholder={globalV6DnsStr ||
											"fd00::1"}
										class="font-mono text-xs"
									/>
								</div>

								<div class="space-y-1 pt-2 border-t">
									<Label class="text-xs text-muted-foreground"
										>IPv6 Boot File URL (Option 59)</Label
									>
									<Input
										bind:value={pool.boot_file}
										placeholder="tftp://[fd00::1]/ipxe.efi"
										class="font-mono text-xs"
									/>
								</div>
							</Card.Content>
						</Card.Root>
					{/each}
				</div>
			{/if}
		</div>

		<!-- 3. DHCP BOOT PARAMETERS & CUSTOM RAW OPTIONS -->
		<Card.Root class="border-border/80 shadow-sm mt-2">
			<Card.Header class="pb-3 border-b bg-muted/20">
				<div class="flex items-center gap-2">
					<SlidersIcon class="h-5 w-5 text-primary" />
					<div>
						<Card.Title class="text-base"
							>DHCP Boot Parameters & Custom Raw Options</Card.Title
						>
						<Card.Description>
							Global network boot options (Options 66/67/59) and
							arbitrary DHCP option code payloads
						</Card.Description>
					</div>
				</div>
			</Card.Header>

			<Card.Content class="p-5 space-y-6">
				<!-- Global Boot Params -->
				<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
					<div class="space-y-1.5">
						<Label class="text-xs"
							>Default Next-Server / siaddr (Opt 66)</Label
						>
						<Input
							bind:value={globalV4TftpServer}
							placeholder="192.168.0.1"
							class="font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">
							Advertised TFTP server IP for PXE netboot clients.
						</p>
					</div>

					<div class="space-y-1.5">
						<Label class="text-xs"
							>Default IPv4 Boot File (Opt 67)</Label
						>
						<Input
							bind:value={globalV4BootFile}
							placeholder="ipxe.efi, pxelinux.0"
							class="font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">
							Default NBP bootloader filename.
						</p>
					</div>

					<div class="space-y-1.5">
						<Label class="text-xs"
							>Default IPv6 Boot URL (Opt 59)</Label
						>
						<Input
							bind:value={globalV6BootFile}
							placeholder="tftp://[fd00::1]/ipxe.efi"
							class="font-mono text-xs"
						/>
						<p class="text-[10px] text-muted-foreground">
							DHCPv6 network boot URL.
						</p>
					</div>
				</div>

				<!-- Custom Raw Options Table -->
				<div
					class="grid grid-cols-1 lg:grid-cols-2 gap-6 pt-4 border-t"
				>
					<!-- IPv4 Custom Raw Options -->
					<div class="space-y-3">
						<div class="flex items-center gap-2">
							<Badge
								variant="outline"
								class="font-mono text-[10px] text-blue-500 border-blue-500/30"
								>IPv4</Badge
							>
							<span class="text-xs font-bold text-foreground"
								>Custom Raw Option Codes</span
							>
						</div>

						{#if v4RawOptions.length > 0}
							<div
								class="border rounded-lg overflow-hidden font-mono text-xs"
							>
								<Table.Root>
									<Table.Header class="bg-muted/40">
										<Table.Row>
											<Table.Head class="w-[110px]"
												>Option Code</Table.Head
											>
											<Table.Head
												>Payload / String</Table.Head
											>
											<Table.Head
												class="w-[50px] text-right"
											></Table.Head>
										</Table.Row>
									</Table.Header>
									<Table.Body>
										{#each v4RawOptions as opt, idx}
											<Table.Row>
												<Table.Cell class="font-bold"
													>Option {opt.code}</Table.Cell
												>
												<Table.Cell
													>{opt.value}</Table.Cell
												>
												<Table.Cell class="text-right">
													<Button
														variant="ghost"
														size="icon"
														class="h-6 w-6 text-destructive hover:text-destructive"
														onclick={() =>
															removeV4Raw(idx)}
													>
														<Trash2Icon
															class="h-3.5 w-3.5"
														/>
													</Button>
												</Table.Cell>
											</Table.Row>
										{/each}
									</Table.Body>
								</Table.Root>
							</div>
						{/if}

						<div class="flex items-center gap-2">
							<Input
								type="number"
								placeholder="Code (e.g. 43)"
								class="w-32 font-mono text-xs"
								bind:value={newRawV4Code}
							/>
							<Input
								placeholder="Option payload / string..."
								class="flex-1 font-mono text-xs"
								bind:value={newRawV4Value}
								onkeydown={(e) =>
									e.key === "Enter" && addV4Raw()}
							/>
							<Button
								size="sm"
								variant="outline"
								onclick={addV4Raw}
							>
								<PlusIcon class="h-3.5 w-3.5 mr-1" />
								Add
							</Button>
						</div>
					</div>

					<!-- IPv6 Custom Raw Options -->
					<div class="space-y-3">
						<div class="flex items-center gap-2">
							<Badge
								variant="outline"
								class="font-mono text-[10px] text-purple-500 border-purple-500/30"
								>IPv6</Badge
							>
							<span class="text-xs font-bold text-foreground"
								>Custom Raw Option Codes</span
							>
						</div>

						{#if v6RawOptions.length > 0}
							<div
								class="border rounded-lg overflow-hidden font-mono text-xs"
							>
								<Table.Root>
									<Table.Header class="bg-muted/40">
										<Table.Row>
											<Table.Head class="w-[110px]"
												>Option Code</Table.Head
											>
											<Table.Head
												>Payload / String</Table.Head
											>
											<Table.Head
												class="w-[50px] text-right"
											></Table.Head>
										</Table.Row>
									</Table.Header>
									<Table.Body>
										{#each v6RawOptions as opt, idx}
											<Table.Row>
												<Table.Cell class="font-bold"
													>Option {opt.code}</Table.Cell
												>
												<Table.Cell
													>{opt.value}</Table.Cell
												>
												<Table.Cell class="text-right">
													<Button
														variant="ghost"
														size="icon"
														class="h-6 w-6 text-destructive hover:text-destructive"
														onclick={() =>
															removeV6Raw(idx)}
													>
														<Trash2Icon
															class="h-3.5 w-3.5"
														/>
													</Button>
												</Table.Cell>
											</Table.Row>
										{/each}
									</Table.Body>
								</Table.Root>
							</div>
						{/if}

						<div class="flex items-center gap-2">
							<Input
								type="number"
								placeholder="Code (e.g. 56)"
								class="w-32 font-mono text-xs"
								bind:value={newRawV6Code}
							/>
							<Input
								placeholder="Option payload / string..."
								class="flex-1 font-mono text-xs"
								bind:value={newRawV6Value}
								onkeydown={(e) =>
									e.key === "Enter" && addV6Raw()}
							/>
							<Button
								size="sm"
								variant="outline"
								onclick={addV6Raw}
							>
								<PlusIcon class="h-3.5 w-3.5 mr-1" />
								Add
							</Button>
						</div>
					</div>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}
</div>

<!-- Modal: Add IPv4 Scope -->
<Dialog.Root bind:open={addV4ModalOpen}>
	<Dialog.Content class="sm:max-w-[460px]">
		<Dialog.Header>
			<Dialog.Title>Add New IPv4 Scope</Dialog.Title>
			<Dialog.Description>
				Configure a new dynamic address range with subnet parameters.
			</Dialog.Description>
		</Dialog.Header>

		<div class="grid gap-3.5 py-3">
			<div class="space-y-1">
				<Label for="addV4Name" class="text-xs">Scope Name</Label>
				<Input
					id="addV4Name"
					bind:value={newV4Name}
					placeholder="e.g. Primary LAN Scope"
					class="text-xs"
				/>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-1">
					<Label for="addV4Start" class="text-xs">Range Start</Label>
					<Input
						id="addV4Start"
						bind:value={newV4Start}
						placeholder="192.168.0.100"
						class="font-mono text-xs"
					/>
				</div>
				<div class="space-y-1">
					<Label for="addV4End" class="text-xs">Range End</Label>
					<Input
						id="addV4End"
						bind:value={newV4End}
						placeholder="192.168.0.240"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-1">
					<Label for="addV4Router" class="text-xs"
						>Default Gateway</Label
					>
					<Input
						id="addV4Router"
						bind:value={newV4Router}
						placeholder="192.168.0.1"
						class="font-mono text-xs"
					/>
				</div>
				<div class="space-y-1">
					<Label for="addV4Subnet" class="text-xs">Subnet Mask</Label>
					<Input
						id="addV4Subnet"
						bind:value={newV4SubnetMask}
						placeholder="255.255.255.0"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-1">
					<Label for="addV4Dns" class="text-xs">DNS Resolvers</Label>
					<Input
						id="addV4Dns"
						bind:value={newV4Dns}
						placeholder="192.168.0.1"
						class="font-mono text-xs"
					/>
				</div>
				<div class="space-y-1">
					<Label for="addV4Lease" class="text-xs"
						>Lease Duration (s)</Label
					>
					<Input
						id="addV4Lease"
						type="number"
						bind:value={newV4Lease}
						placeholder="86400"
						class="font-mono text-xs"
					/>
				</div>
			</div>
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (addV4ModalOpen = false)}
				>Cancel</Button
			>
			<Button onclick={submitAddV4}>Create Scope</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>

<!-- Modal: Add IPv6 Scope -->
<Dialog.Root bind:open={addV6ModalOpen}>
	<Dialog.Content class="sm:max-w-[460px]">
		<Dialog.Header>
			<Dialog.Title>Add New IPv6 Scope</Dialog.Title>
			<Dialog.Description>
				Define a floating suffix range (e.g. ::100 – ::1fff) or a static
				subnet CIDR.
			</Dialog.Description>
		</Dialog.Header>

		<div class="grid gap-3.5 py-3">
			<div class="space-y-1">
				<Label for="addV6Name" class="text-xs">Scope Name</Label>
				<Input
					id="addV6Name"
					bind:value={newV6Name}
					placeholder="e.g. Main Suffix Scope"
					class="text-xs"
				/>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-1">
					<Label for="addV6Start" class="text-xs"
						>Lower Suffix Bound</Label
					>
					<Input
						id="addV6Start"
						bind:value={newV6Start}
						placeholder="::100"
						class="font-mono text-xs"
					/>
				</div>
				<div class="space-y-1">
					<Label for="addV6End" class="text-xs"
						>Upper Suffix Bound</Label
					>
					<Input
						id="addV6End"
						bind:value={newV6End}
						placeholder="::1fff"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<div class="space-y-1">
				<Label for="addV6Addr" class="text-xs"
					>Static Subnet CIDR (Alternative)</Label
				>
				<Input
					id="addV6Addr"
					bind:value={newV6Addr}
					placeholder="2001:db8:1::/64"
					class="font-mono text-xs"
				/>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="space-y-1">
					<Label for="addV6Dns" class="text-xs"
						>DNS Servers (Opt 23)</Label
					>
					<Input
						id="addV6Dns"
						bind:value={newV6Dns}
						placeholder="fd00::1"
						class="font-mono text-xs"
					/>
				</div>
				<div class="space-y-1">
					<Label for="addV6Lease" class="text-xs"
						>Lease Duration (s)</Label
					>
					<Input
						id="addV6Lease"
						type="number"
						bind:value={newV6Lease}
						placeholder="86400"
						class="font-mono text-xs"
					/>
				</div>
			</div>
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (addV6ModalOpen = false)}
				>Cancel</Button
			>
			<Button onclick={submitAddV6}>Create Scope</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
