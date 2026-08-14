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
	import EditIcon from "@lucide/svelte/icons/pencil";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";

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

	// Original pristine state for reset
	let pristineOptions = $state<DhcpOptionsConfig | null>(null);
	let pristineV4Pools = $state<Dhcpv4PoolConfig[]>([]);
	let pristineV6Pools = $state<Dhcpv6PoolConfig[]>([]);

	// Active working state
	let v4Enabled = $state(true);
	let v4LeaseTime = $state(86400);
	let v4Router = $state("192.168.0.1");
	let v4SubnetMask = $state("255.255.255.0");
	let v4DnsStr = $state("192.168.0.1");
	let v4DomainName = $state("");
	let v4SearchDomainsStr = $state("");
	let v4NtpStr = $state("162.159.200.1, 216.239.35.0");
	let v4TftpServer = $state("");
	let v4BootFile = $state("");

	let v6Enabled = $state(true);
	let v6LeaseTime = $state(86400);
	let v6DnsStr = $state("");
	let v6SearchDomainsStr = $state("");
	let v6NtpStr = $state("time.cloudflare.com, time.google.com");
	let v6BootFile = $state("");

	let tftpEnabled = $state(false);
	let tftpListenAddr = $state("0.0.0.0:69");
	let tftpRootDir = $state("/var/lib/lanforge/tftp");
	let tftpBlockSize = $state(512);
	let tftpTimeout = $state(5);
	let tftpMaxRetries = $state(3);

	let v4Pools = $state<Dhcpv4PoolConfig[]>([]);
	let v6Pools = $state<Dhcpv6PoolConfig[]>([]);

	// Custom Raw Options
	let v4RawOptions = $state<Array<{ code: number; value: string }>>([]);
	let v6RawOptions = $state<Array<{ code: number; value: string }>>([]);

	// Modals state
	let v4PoolDialogOpen = $state(false);
	let editingV4PoolIndex = $state<number | null>(null);
	let v4PoolStart = $state("");
	let v4PoolEnd = $state("");
	let v4PoolLease = $state<number | "">("");

	let v6PoolDialogOpen = $state(false);
	let editingV6PoolIndex = $state<number | null>(null);
	let v6PoolStart = $state("");
	let v6PoolEnd = $state("");
	let v6PoolAddr = $state("");
	let v6PoolLease = $state<number | "">("");

	let newRawV4Code = $state<number | "">("");
	let newRawV4Value = $state("");
	let newRawV6Code = $state<number | "">("");
	let newRawV6Value = $state("");

	async function loadConfig() {
		loading = true;
		try {
			const [opts, pools] = await Promise.all([
				dhcpOptionsGet(),
				dhcpPoolsConfigGet(),
			]);

			pristineOptions = JSON.parse(JSON.stringify(opts));
			pristineV4Pools = JSON.parse(JSON.stringify(pools.v4_pools));
			pristineV6Pools = JSON.parse(JSON.stringify(pools.v6_pools));

			// Populate IPv4
			v4Enabled = opts.v4?.enabled ?? true;
			v4LeaseTime = opts.v4?.lease_time ?? 86400;
			v4Router = opts.v4?.router ?? "";
			v4SubnetMask = opts.v4?.subnet_mask ?? "255.255.255.0";
			v4DnsStr = (opts.v4?.dns_servers ?? []).join(", ");
			v4DomainName = opts.v4?.domain_name ?? "";
			v4SearchDomainsStr = (opts.v4?.search_domains ?? []).join(", ");
			v4NtpStr = (opts.v4?.ntp_servers ?? []).join(", ");
			v4TftpServer = opts.v4?.tftp_server ?? "";
			v4BootFile = opts.v4?.boot_file ?? "";

			v4RawOptions = Object.entries(opts.v4?.raw_options ?? {}).map(
				([k, v]) => ({
					code: Number(k),
					value: v,
				}),
			);

			// Populate IPv6
			v6Enabled = opts.v6?.enabled ?? true;
			v6LeaseTime = opts.v6?.lease_time ?? 86400;
			v6DnsStr = (opts.v6?.dns_servers ?? []).join(", ");
			v6SearchDomainsStr = (opts.v6?.search_domains ?? []).join(", ");
			v6NtpStr = (opts.v6?.ntp_servers ?? []).join(", ");
			v6BootFile = opts.v6?.boot_file ?? "";

			v6RawOptions = Object.entries(opts.v6?.raw_options ?? {}).map(
				([k, v]) => ({
					code: Number(k),
					value: v,
				}),
			);

			// Populate TFTP
			tftpEnabled = opts.tftp?.enabled ?? false;
			tftpListenAddr = opts.tftp?.listen_addr ?? "0.0.0.0:69";
			tftpRootDir = opts.tftp?.root_dir ?? "/var/lib/lanforge/tftp";
			tftpBlockSize = opts.tftp?.block_size ?? 512;
			tftpTimeout = opts.tftp?.timeout ?? 5;
			tftpMaxRetries = opts.tftp?.max_retries ?? 3;

			// Populate Pools
			v4Pools = JSON.parse(JSON.stringify(pools.v4_pools));
			v6Pools = JSON.parse(JSON.stringify(pools.v6_pools));
		} catch (err: any) {
			toast.error(`Failed to load DHCP options: ${err.message}`);
		} finally {
			loading = false;
		}
	}

	function parseList(str: string): string[] {
		return str
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
	}

	async function handleSave() {
		saving = true;
		try {
			const v4RawMap: Record<number, string> = {};
			for (const opt of v4RawOptions) {
				if (opt.code && opt.value) v4RawMap[opt.code] = opt.value;
			}

			const v6RawMap: Record<number, string> = {};
			for (const opt of v6RawOptions) {
				if (opt.code && opt.value) v6RawMap[opt.code] = opt.value;
			}

			const payloadOptions: DhcpOptionsConfig = {
				v4: {
					enabled: v4Enabled,
					lease_time: Number(v4LeaseTime) || 86400,
					router: v4Router.trim() || null,
					subnet_mask: v4SubnetMask.trim() || null,
					dns_servers: parseList(v4DnsStr),
					domain_name: v4DomainName.trim() || null,
					search_domains: parseList(v4SearchDomainsStr),
					ntp_servers: parseList(v4NtpStr),
					tftp_server: v4TftpServer.trim() || null,
					boot_file: v4BootFile.trim() || null,
					raw_options: v4RawMap,
				},
				v6: {
					enabled: v6Enabled,
					lease_time: Number(v6LeaseTime) || 86400,
					dns_servers: parseList(v6DnsStr),
					search_domains: parseList(v6SearchDomainsStr),
					ntp_servers: parseList(v6NtpStr),
					boot_file: v6BootFile.trim() || null,
					raw_options: v6RawMap,
				},
				tftp: {
					enabled: tftpEnabled,
					listen_addr: tftpListenAddr.trim() || "0.0.0.0:69",
					root_dir: tftpRootDir.trim() || "/var/lib/lanforge/tftp",
					block_size: Number(tftpBlockSize) || 512,
					timeout: Number(tftpTimeout) || 5,
					max_retries: Number(tftpMaxRetries) || 3,
				},
			};

			await Promise.all([
				dhcpOptionsUpdate(payloadOptions),
				dhcpPoolsConfigUpdate(v4Pools, v6Pools),
			]);

			toast.success("DHCP & TFTP configuration saved successfully");
			await loadConfig();
		} catch (err: any) {
			toast.error(`Failed to save configuration: ${err.message}`);
		} finally {
			saving = false;
		}
	}

	function handleReset() {
		loadConfig();
		toast.info("Configuration reset to last saved state");
	}

	// IPv4 Pool CRUD
	function openAddV4Pool() {
		editingV4PoolIndex = null;
		v4PoolStart = "";
		v4PoolEnd = "";
		v4PoolLease = "";
		v4PoolDialogOpen = true;
	}

	function openEditV4Pool(index: number) {
		editingV4PoolIndex = index;
		const p = v4Pools[index];
		v4PoolStart = p.range_start;
		v4PoolEnd = p.range_end;
		v4PoolLease = p.lease_time ?? "";
		v4PoolDialogOpen = true;
	}

	function saveV4Pool() {
		if (!v4PoolStart.trim() || !v4PoolEnd.trim()) {
			toast.error("Range start and end are required for IPv4 pool");
			return;
		}
		const pool: Dhcpv4PoolConfig = {
			range_start: v4PoolStart.trim(),
			range_end: v4PoolEnd.trim(),
			lease_time: v4PoolLease ? Number(v4PoolLease) : null,
		};
		if (editingV4PoolIndex !== null) {
			v4Pools[editingV4PoolIndex] = pool;
		} else {
			v4Pools = [...v4Pools, pool];
		}
		v4PoolDialogOpen = false;
	}

	function deleteV4Pool(index: number) {
		v4Pools = v4Pools.filter((_, i) => i !== index);
	}

	// IPv6 Pool CRUD
	function openAddV6Pool() {
		editingV6PoolIndex = null;
		v6PoolStart = "";
		v6PoolEnd = "";
		v6PoolAddr = "";
		v6PoolLease = "";
		v6PoolDialogOpen = true;
	}

	function openEditV6Pool(index: number) {
		editingV6PoolIndex = index;
		const p = v6Pools[index];
		v6PoolStart = p.range_start ?? "";
		v6PoolEnd = p.range_end ?? "";
		v6PoolAddr = p.address ?? "";
		v6PoolLease = p.lease_time ?? "";
		v6PoolDialogOpen = true;
	}

	function saveV6Pool() {
		if (!v6PoolAddr.trim() && (!v6PoolStart.trim() || !v6PoolEnd.trim())) {
			toast.error(
				"Either Start/End suffix or static CIDR address is required for IPv6 pool",
			);
			return;
		}
		const pool: Dhcpv6PoolConfig = {
			range_start: v6PoolStart.trim() || null,
			range_end: v6PoolEnd.trim() || null,
			address: v6PoolAddr.trim() || null,
			lease_time: v6PoolLease ? Number(v6PoolLease) : null,
		};
		if (editingV6PoolIndex !== null) {
			v6Pools[editingV6PoolIndex] = pool;
		} else {
			v6Pools = [...v6Pools, pool];
		}
		v6PoolDialogOpen = false;
	}

	function deleteV6Pool(index: number) {
		v6Pools = v6Pools.filter((_, i) => i !== index);
	}

	// Raw Options
	function addV4RawOption() {
		if (!newRawV4Code || !newRawV4Value.trim()) return;
		v4RawOptions = [
			...v4RawOptions,
			{ code: Number(newRawV4Code), value: newRawV4Value.trim() },
		];
		newRawV4Code = "";
		newRawV4Value = "";
	}

	function removeV4RawOption(index: number) {
		v4RawOptions = v4RawOptions.filter((_, i) => i !== index);
	}

	function addV6RawOption() {
		if (!newRawV6Code || !newRawV6Value.trim()) return;
		v6RawOptions = [
			...v6RawOptions,
			{ code: Number(newRawV6Code), value: newRawV6Value.trim() },
		];
		newRawV6Code = "";
		newRawV6Value = "";
	}

	function removeV6RawOption(index: number) {
		v6RawOptions = v6RawOptions.filter((_, i) => i !== index);
	}

	onMount(() => {
		loadConfig();
	});
</script>

<svelte:head>
	<title>Scope Options & Scopes — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Page Header Actions -->
	<div
		class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
	>
		<div>
			<h2 class="text-xl font-bold tracking-tight">
				Scope Options & Pools
			</h2>
			<p class="text-muted-foreground text-sm">
				Configure advertised router options, DNS servers, TFTP / PXE
				boot parameters, and dynamic address pools.
			</p>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={handleReset}
				disabled={loading || saving}
			>
				<RotateCcwIcon data-icon="inline-start" />
				Reset
			</Button>
			<Button size="sm" onclick={handleSave} disabled={loading || saving}>
				{#if saving}
					<RefreshCwIcon
						data-icon="inline-start"
						class="animate-spin"
					/>
					Saving...
				{:else}
					<SaveIcon data-icon="inline-start" />
					Save Configuration
				{/if}
			</Button>
		</div>
	</div>

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
			{#each { length: 4 } as _, i (i)}
				<Card.Root>
					<Card.Header>
						<Skeleton class="h-6 w-40" />
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
		<!-- 1. MULTIPLE POOLS MANAGER -->
		<Card.Root class="overflow-hidden border-border/80 shadow-sm">
			<Card.Header
				class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b bg-muted/20 pb-4"
			>
				<div class="flex items-center gap-2.5">
					<NetworkIcon class="h-5 w-5 text-primary" />
					<div>
						<Card.Title class="text-lg"
							>Dynamic Address Pools</Card.Title
						>
						<Card.Description>
							Manage active dynamic address ranges for IPv4 and
							IPv6
						</Card.Description>
					</div>
				</div>
				<div class="flex items-center gap-2">
					<Button variant="outline" size="sm" onclick={openAddV4Pool}>
						<PlusIcon data-icon="inline-start" />
						Add IPv4 Pool
					</Button>
					<Button variant="outline" size="sm" onclick={openAddV6Pool}>
						<PlusIcon data-icon="inline-start" />
						Add IPv6 Pool
					</Button>
				</div>
			</Card.Header>

			<Card.Content class="p-0">
				<div
					class="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x"
				>
					<!-- IPv4 Pools Table -->
					<div class="p-4 space-y-3">
						<div class="flex items-center justify-between">
							<span
								class="text-sm font-semibold text-foreground flex items-center gap-2"
							>
								<Badge
									variant="outline"
									class="font-mono text-blue-500 border-blue-500/30 text-xs"
									>IPv4</Badge
								>
								Configured Pools ({v4Pools.length})
							</span>
						</div>

						{#if v4Pools.length === 0}
							<div
								class="py-8 text-center text-muted-foreground text-xs border border-dashed rounded-lg bg-muted/10"
							>
								No dynamic IPv4 pools configured. Server will
								operate with static hosts only.
							</div>
						{:else}
							<div
								class="border rounded-lg overflow-hidden font-mono text-xs"
							>
								<Table.Root>
									<Table.Header class="bg-muted/40">
										<Table.Row>
											<Table.Head>Start Range</Table.Head>
											<Table.Head>End Range</Table.Head>
											<Table.Head class="w-[80px]"
												>Lease</Table.Head
											>
											<Table.Head
												class="w-[70px] text-right"
												>Actions</Table.Head
											>
										</Table.Row>
									</Table.Header>
									<Table.Body>
										{#each v4Pools as pool, index}
											<Table.Row
												class="hover:bg-muted/50"
											>
												<Table.Cell
													class="text-emerald-400 font-medium"
													>{pool.range_start}</Table.Cell
												>
												<Table.Cell
													class="text-emerald-400 font-medium"
													>{pool.range_end}</Table.Cell
												>
												<Table.Cell
													class="font-sans text-muted-foreground"
												>
													{pool.lease_time
														? `${pool.lease_time}s`
														: "Default"}
												</Table.Cell>
												<Table.Cell
													class="text-right font-sans"
												>
													<div
														class="flex items-center justify-end gap-1"
													>
														<Button
															variant="ghost"
															size="icon"
															class="h-7 w-7"
															onclick={() =>
																openEditV4Pool(
																	index,
																)}
														>
															<EditIcon
																class="h-3.5 w-3.5"
															/>
														</Button>
														<Button
															variant="ghost"
															size="icon"
															class="h-7 w-7 text-destructive hover:text-destructive"
															onclick={() =>
																deleteV4Pool(
																	index,
																)}
														>
															<Trash2Icon
																class="h-3.5 w-3.5"
															/>
														</Button>
													</div>
												</Table.Cell>
											</Table.Row>
										{/each}
									</Table.Body>
								</Table.Root>
							</div>
						{/if}
					</div>

					<!-- IPv6 Pools Table -->
					<div class="p-4 space-y-3">
						<div class="flex items-center justify-between">
							<span
								class="text-sm font-semibold text-foreground flex items-center gap-2"
							>
								<Badge
									variant="outline"
									class="font-mono text-purple-500 border-purple-500/30 text-xs"
									>IPv6</Badge
								>
								Configured Pools ({v6Pools.length})
							</span>
						</div>

						{#if v6Pools.length === 0}
							<div
								class="py-8 text-center text-muted-foreground text-xs border border-dashed rounded-lg bg-muted/10"
							>
								No dynamic IPv6 pools configured.
							</div>
						{:else}
							<div
								class="border rounded-lg overflow-hidden font-mono text-xs"
							>
								<Table.Root>
									<Table.Header class="bg-muted/40">
										<Table.Row>
											<Table.Head
												>Start Suffix / CIDR</Table.Head
											>
											<Table.Head>End Suffix</Table.Head>
											<Table.Head class="w-[80px]"
												>Lease</Table.Head
											>
											<Table.Head
												class="w-[70px] text-right"
												>Actions</Table.Head
											>
										</Table.Row>
									</Table.Header>
									<Table.Body>
										{#each v6Pools as pool, index}
											<Table.Row
												class="hover:bg-muted/50"
											>
												<Table.Cell
													class="text-sky-400 font-medium"
												>
													{pool.address ||
														pool.range_start ||
														"—"}
												</Table.Cell>
												<Table.Cell
													class="text-sky-400 font-medium"
												>
													{pool.range_end || "—"}
												</Table.Cell>
												<Table.Cell
													class="font-sans text-muted-foreground"
												>
													{pool.lease_time
														? `${pool.lease_time}s`
														: "Default"}
												</Table.Cell>
												<Table.Cell
													class="text-right font-sans"
												>
													<div
														class="flex items-center justify-end gap-1"
													>
														<Button
															variant="ghost"
															size="icon"
															class="h-7 w-7"
															onclick={() =>
																openEditV6Pool(
																	index,
																)}
														>
															<EditIcon
																class="h-3.5 w-3.5"
															/>
														</Button>
														<Button
															variant="ghost"
															size="icon"
															class="h-7 w-7 text-destructive hover:text-destructive"
															onclick={() =>
																deleteV6Pool(
																	index,
																)}
														>
															<Trash2Icon
																class="h-3.5 w-3.5"
															/>
														</Button>
													</div>
												</Table.Cell>
											</Table.Row>
										{/each}
									</Table.Body>
								</Table.Root>
							</div>
						{/if}
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- 2. SCOPE PARAMETERS (IPv4 & IPv6) -->
		<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
			<!-- IPv4 Scope Card -->
			<Card.Root>
				<Card.Header class="pb-3 border-b">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<ServerIcon class="h-5 w-5 text-blue-500" />
							<Card.Title class="text-base"
								>IPv4 Scope Options</Card.Title
							>
						</div>
						<label
							class="flex items-center gap-2 cursor-pointer text-xs font-medium"
						>
							<input
								type="checkbox"
								class="rounded border-border text-primary focus:ring-primary h-4 w-4"
								bind:checked={v4Enabled}
							/>
							<span>DHCPv4 Active</span>
						</label>
					</div>
					<Card.Description
						>Core IPv4 gateway, subnet mask, and DNS options</Card.Description
					>
				</Card.Header>

				<Card.Content class="p-5 space-y-4">
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
						<div class="space-y-1.5">
							<Label for="v4Router" class="text-xs"
								>Default Gateway (Option 3)</Label
							>
							<Input
								id="v4Router"
								bind:value={v4Router}
								placeholder="192.168.0.1"
								class="font-mono text-sm"
							/>
						</div>

						<div class="space-y-1.5">
							<Label for="v4SubnetMask" class="text-xs"
								>Subnet Mask (Option 1)</Label
							>
							<Input
								id="v4SubnetMask"
								bind:value={v4SubnetMask}
								placeholder="255.255.255.0"
								class="font-mono text-sm"
							/>
						</div>
					</div>

					<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
						<div class="space-y-1.5">
							<Label for="v4LeaseTime" class="text-xs"
								>Default Lease Duration (Seconds)</Label
							>
							<Input
								id="v4LeaseTime"
								type="number"
								bind:value={v4LeaseTime}
								placeholder="86400"
								class="font-mono text-sm"
							/>
						</div>

						<div class="space-y-1.5">
							<Label for="v4DomainName" class="text-xs"
								>Domain Name (Option 15)</Label
							>
							<Input
								id="v4DomainName"
								bind:value={v4DomainName}
								placeholder="lan / home.arpa"
								class="text-sm"
							/>
						</div>
					</div>

					<div class="space-y-1.5">
						<Label for="v4Dns" class="text-xs"
							>DNS Servers (Option 6)</Label
						>
						<Input
							id="v4Dns"
							bind:value={v4DnsStr}
							placeholder="192.168.0.1, 1.1.1.1"
							class="font-mono text-sm"
						/>
						<p class="text-[11px] text-muted-foreground">
							Comma-separated list of IPv4 DNS resolvers
							advertised to clients.
						</p>
					</div>

					<div class="space-y-1.5">
						<Label for="v4SearchDomains" class="text-xs"
							>Domain Search List (Option 119)</Label
						>
						<Input
							id="v4SearchDomains"
							bind:value={v4SearchDomainsStr}
							placeholder="lan, internal.net"
							class="text-sm"
						/>
					</div>

					<div class="space-y-1.5">
						<Label for="v4Ntp" class="text-xs"
							>NTP Time Servers (Option 42)</Label
						>
						<Input
							id="v4Ntp"
							bind:value={v4NtpStr}
							placeholder="162.159.200.1, 216.239.35.0"
							class="font-mono text-sm"
						/>
					</div>
				</Card.Content>
			</Card.Root>

			<!-- IPv6 Scope Card -->
			<Card.Root>
				<Card.Header class="pb-3 border-b">
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<GlobeIcon class="h-5 w-5 text-purple-500" />
							<Card.Title class="text-base"
								>IPv6 Scope Options</Card.Title
							>
						</div>
						<label
							class="flex items-center gap-2 cursor-pointer text-xs font-medium"
						>
							<input
								type="checkbox"
								class="rounded border-border text-primary focus:ring-primary h-4 w-4"
								bind:checked={v6Enabled}
							/>
							<span>DHCPv6 Active</span>
						</label>
					</div>
					<Card.Description
						>Stateful address, prefix delegation, and Option 23 DNS</Card.Description
					>
				</Card.Header>

				<Card.Content class="p-5 space-y-4">
					<div class="space-y-1.5">
						<Label for="v6LeaseTime" class="text-xs"
							>Default Lease Duration (Seconds)</Label
						>
						<Input
							id="v6LeaseTime"
							type="number"
							bind:value={v6LeaseTime}
							placeholder="86400"
							class="font-mono text-sm"
						/>
					</div>

					<div class="space-y-1.5">
						<Label for="v6Dns" class="text-xs"
							>DNS Resolvers (Option 23)</Label
						>
						<Input
							id="v6Dns"
							bind:value={v6DnsStr}
							placeholder="fd00::1, 2606:4700:4700::1111"
							class="font-mono text-sm"
						/>
						<p class="text-[11px] text-muted-foreground">
							Comma-separated list of IPv6 recursive DNS servers.
						</p>
					</div>

					<div class="space-y-1.5">
						<Label for="v6SearchDomains" class="text-xs"
							>Domain Search List (Option 24)</Label
						>
						<Input
							id="v6SearchDomains"
							bind:value={v6SearchDomainsStr}
							placeholder="lan, local"
							class="text-sm"
						/>
					</div>

					<div class="space-y-1.5">
						<Label for="v6Ntp" class="text-xs"
							>NTP Servers (Option 56)</Label
						>
						<Input
							id="v6Ntp"
							bind:value={v6NtpStr}
							placeholder="time.cloudflare.com, time.google.com"
							class="font-mono text-sm"
						/>
					</div>
				</Card.Content>
			</Card.Root>
		</div>

		<!-- 3. TFTP & PXE NETWORK BOOT INTEGRATION -->
		<Card.Root>
			<Card.Header class="pb-3 border-b">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<HardDriveIcon class="h-5 w-5 text-amber-500" />
						<div>
							<Card.Title class="text-base"
								>TFTP & Network Boot (PXE)</Card.Title
							>
							<Card.Description>
								Network boot options (DHCP Options 66/67/59) and
								built-in TFTP service
							</Card.Description>
						</div>
					</div>
					<label
						class="flex items-center gap-2 cursor-pointer text-xs font-medium"
					>
						<input
							type="checkbox"
							class="rounded border-border text-primary focus:ring-primary h-4 w-4"
							bind:checked={tftpEnabled}
						/>
						<span>TFTP Service Enabled</span>
					</label>
				</div>
			</Card.Header>

			<Card.Content class="p-5">
				<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
					<!-- Boot Options in DHCP -->
					<div class="space-y-4">
						<h4
							class="text-xs font-semibold uppercase tracking-wider text-muted-foreground"
						>
							DHCP Advertised Boot Parameters
						</h4>

						<div class="space-y-1.5">
							<Label for="v4TftpServer" class="text-xs"
								>TFTP Next-Server / siaddr (Option 66)</Label
							>
							<Input
								id="v4TftpServer"
								bind:value={v4TftpServer}
								placeholder="192.168.0.1"
								class="font-mono text-sm"
							/>
							<p class="text-[11px] text-muted-foreground">
								IP address of the TFTP server for netboot
								clients.
							</p>
						</div>

						<div class="space-y-1.5">
							<Label for="v4BootFile" class="text-xs"
								>IPv4 Boot File Name (Option 67)</Label
							>
							<Input
								id="v4BootFile"
								bind:value={v4BootFile}
								placeholder="ipxe.efi, pxelinux.0"
								class="font-mono text-sm"
							/>
						</div>

						<div class="space-y-1.5">
							<Label for="v6BootFile" class="text-xs"
								>IPv6 Boot File URL / Name (Option 59)</Label
							>
							<Input
								id="v6BootFile"
								bind:value={v6BootFile}
								placeholder="tftp://[fd00::1]/ipxe.efi"
								class="font-mono text-sm"
							/>
						</div>
					</div>

					<!-- TFTP Server Daemon Config -->
					<div class="space-y-4 md:border-l md:pl-6">
						<h4
							class="text-xs font-semibold uppercase tracking-wider text-muted-foreground"
						>
							Built-in TFTP Daemon Parameters
						</h4>

						<div class="space-y-1.5">
							<Label for="tftpListenAddr" class="text-xs"
								>Listen Address & Port</Label
							>
							<Input
								id="tftpListenAddr"
								bind:value={tftpListenAddr}
								placeholder="0.0.0.0:69"
								class="font-mono text-sm"
							/>
						</div>

						<div class="space-y-1.5">
							<Label for="tftpRootDir" class="text-xs"
								>TFTP Root Directory</Label
							>
							<Input
								id="tftpRootDir"
								bind:value={tftpRootDir}
								placeholder="/var/lib/lanforge/tftp"
								class="font-mono text-sm"
							/>
							<p class="text-[11px] text-muted-foreground">
								Local path where PXE kernels and bootloaders are
								hosted.
							</p>
						</div>

						<div class="grid grid-cols-3 gap-3">
							<div class="space-y-1">
								<Label for="tftpBlockSize" class="text-xs"
									>Block Size</Label
								>
								<Input
									id="tftpBlockSize"
									type="number"
									bind:value={tftpBlockSize}
									placeholder="512"
									class="font-mono text-xs"
								/>
							</div>
							<div class="space-y-1">
								<Label for="tftpTimeout" class="text-xs"
									>Timeout (s)</Label
								>
								<Input
									id="tftpTimeout"
									type="number"
									bind:value={tftpTimeout}
									placeholder="5"
									class="font-mono text-xs"
								/>
							</div>
							<div class="space-y-1">
								<Label for="tftpMaxRetries" class="text-xs"
									>Retries</Label
								>
								<Input
									id="tftpMaxRetries"
									type="number"
									bind:value={tftpMaxRetries}
									placeholder="3"
									class="font-mono text-xs"
								/>
							</div>
						</div>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- 4. CUSTOM RAW DHCP OPTIONS -->
		<Card.Root>
			<Card.Header class="pb-3 border-b">
				<div class="flex items-center gap-2">
					<SlidersIcon class="h-5 w-5 text-primary" />
					<div>
						<Card.Title class="text-base"
							>Custom Raw DHCP Options</Card.Title
						>
						<Card.Description
							>Inject custom option IDs and string/hex payloads
							(e.g. Option 43 Vendor Info, Option 121 Static
							Routes)</Card.Description
						>
					</div>
				</div>
			</Card.Header>

			<Card.Content class="p-5 space-y-6">
				<!-- IPv4 Custom Options -->
				<div class="space-y-3">
					<h4
						class="text-xs font-semibold text-foreground flex items-center gap-2"
					>
						<Badge
							variant="outline"
							class="font-mono text-blue-500 border-blue-500/30 text-[10px]"
							>IPv4</Badge
						>
						Custom Option Codes
					</h4>

					{#if v4RawOptions.length > 0}
						<div
							class="border rounded-lg overflow-hidden font-mono text-xs"
						>
							<Table.Root>
								<Table.Header class="bg-muted/40">
									<Table.Row>
										<Table.Head class="w-[120px]"
											>Option Code</Table.Head
										>
										<Table.Head
											>Payload / String Value</Table.Head
										>
										<Table.Head class="w-[60px] text-right"
										></Table.Head>
									</Table.Row>
								</Table.Header>
								<Table.Body>
									{#each v4RawOptions as opt, idx}
										<Table.Row>
											<Table.Cell
												class="font-bold text-foreground"
												>Option {opt.code}</Table.Cell
											>
											<Table.Cell>{opt.value}</Table.Cell>
											<Table.Cell class="text-right">
												<Button
													variant="ghost"
													size="icon"
													class="h-7 w-7 text-destructive hover:text-destructive"
													onclick={() =>
														removeV4RawOption(idx)}
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

					<!-- Add IPv4 Raw Option Form -->
					<div class="flex items-center gap-2">
						<Input
							type="number"
							placeholder="Option ID (e.g. 43)"
							class="w-36 font-mono text-xs"
							bind:value={newRawV4Code}
						/>
						<Input
							placeholder="Option payload or string..."
							class="flex-1 font-mono text-xs"
							bind:value={newRawV4Value}
							onkeydown={(e) =>
								e.key === "Enter" && addV4RawOption()}
						/>
						<Button
							size="sm"
							variant="outline"
							onclick={addV4RawOption}
						>
							<PlusIcon class="h-4 w-4" />
							Add
						</Button>
					</div>
				</div>

				<!-- IPv6 Custom Options -->
				<div class="space-y-3 pt-4 border-t">
					<h4
						class="text-xs font-semibold text-foreground flex items-center gap-2"
					>
						<Badge
							variant="outline"
							class="font-mono text-purple-500 border-purple-500/30 text-[10px]"
							>IPv6</Badge
						>
						Custom Option Codes
					</h4>

					{#if v6RawOptions.length > 0}
						<div
							class="border rounded-lg overflow-hidden font-mono text-xs"
						>
							<Table.Root>
								<Table.Header class="bg-muted/40">
									<Table.Row>
										<Table.Head class="w-[120px]"
											>Option Code</Table.Head
										>
										<Table.Head
											>Payload / String Value</Table.Head
										>
										<Table.Head class="w-[60px] text-right"
										></Table.Head>
									</Table.Row>
								</Table.Header>
								<Table.Body>
									{#each v6RawOptions as opt, idx}
										<Table.Row>
											<Table.Cell
												class="font-bold text-foreground"
												>Option {opt.code}</Table.Cell
											>
											<Table.Cell>{opt.value}</Table.Cell>
											<Table.Cell class="text-right">
												<Button
													variant="ghost"
													size="icon"
													class="h-7 w-7 text-destructive hover:text-destructive"
													onclick={() =>
														removeV6RawOption(idx)}
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

					<!-- Add IPv6 Raw Option Form -->
					<div class="flex items-center gap-2">
						<Input
							type="number"
							placeholder="Option ID (e.g. 56)"
							class="w-36 font-mono text-xs"
							bind:value={newRawV6Code}
						/>
						<Input
							placeholder="Option payload or string..."
							class="flex-1 font-mono text-xs"
							bind:value={newRawV6Value}
							onkeydown={(e) =>
								e.key === "Enter" && addV6RawOption()}
						/>
						<Button
							size="sm"
							variant="outline"
							onclick={addV6RawOption}
						>
							<PlusIcon class="h-4 w-4" />
							Add
						</Button>
					</div>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}
</div>

<!-- IPv4 Pool Dialog -->
<Dialog.Root bind:open={v4PoolDialogOpen}>
	<Dialog.Content class="sm:max-w-[425px]">
		<Dialog.Header>
			<Dialog.Title>
				{editingV4PoolIndex !== null
					? "Edit IPv4 Pool"
					: "Add Dynamic IPv4 Pool"}
			</Dialog.Title>
			<Dialog.Description>
				Configure a contiguous range of IPv4 addresses for dynamic DHCP
				allocation.
			</Dialog.Description>
		</Dialog.Header>

		<div class="grid gap-4 py-4">
			<div class="space-y-1.5">
				<Label for="modalV4Start">Range Start (Inclusive)</Label>
				<Input
					id="modalV4Start"
					bind:value={v4PoolStart}
					placeholder="192.168.0.100"
					class="font-mono text-sm"
				/>
			</div>

			<div class="space-y-1.5">
				<Label for="modalV4End">Range End (Inclusive)</Label>
				<Input
					id="modalV4End"
					bind:value={v4PoolEnd}
					placeholder="192.168.0.240"
					class="font-mono text-sm"
				/>
			</div>

			<div class="space-y-1.5">
				<Label for="modalV4Lease"
					>Custom Lease Time (Seconds, Optional)</Label
				>
				<Input
					id="modalV4Lease"
					type="number"
					bind:value={v4PoolLease}
					placeholder="Leave blank to use default (86400)"
					class="font-mono text-sm"
				/>
			</div>
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (v4PoolDialogOpen = false)}
				>Cancel</Button
			>
			<Button onclick={saveV4Pool}>
				{editingV4PoolIndex !== null ? "Update Pool" : "Add Pool"}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>

<!-- IPv6 Pool Dialog -->
<Dialog.Root bind:open={v6PoolDialogOpen}>
	<Dialog.Content class="sm:max-w-[425px]">
		<Dialog.Header>
			<Dialog.Title>
				{editingV6PoolIndex !== null
					? "Edit IPv6 Pool"
					: "Add Dynamic IPv6 Pool"}
			</Dialog.Title>
			<Dialog.Description>
				Specify lower and upper suffixes (e.g. ::1000 to ::2000) or a
				static CIDR prefix.
			</Dialog.Description>
		</Dialog.Header>

		<div class="grid gap-4 py-4">
			<div class="space-y-1.5">
				<Label for="modalV6Start">Start Suffix (e.g. ::1000)</Label>
				<Input
					id="modalV6Start"
					bind:value={v6PoolStart}
					placeholder="::1000"
					class="font-mono text-sm"
				/>
			</div>

			<div class="space-y-1.5">
				<Label for="modalV6End">End Suffix (e.g. ::2000)</Label>
				<Input
					id="modalV6End"
					bind:value={v6PoolEnd}
					placeholder="::2000"
					class="font-mono text-sm"
				/>
			</div>

			<div class="space-y-1.5">
				<Label for="modalV6Addr"
					>Static CIDR (Alternative to Suffix)</Label
				>
				<Input
					id="modalV6Addr"
					bind:value={v6PoolAddr}
					placeholder="2001:db8:1::/64"
					class="font-mono text-sm"
				/>
			</div>

			<div class="space-y-1.5">
				<Label for="modalV6Lease"
					>Custom Lease Time (Seconds, Optional)</Label
				>
				<Input
					id="modalV6Lease"
					type="number"
					bind:value={v6PoolLease}
					placeholder="Leave blank to use default"
					class="font-mono text-sm"
				/>
			</div>
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => (v6PoolDialogOpen = false)}
				>Cancel</Button
			>
			<Button onclick={saveV6Pool}>
				{editingV6PoolIndex !== null ? "Update Pool" : "Add Pool"}
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
