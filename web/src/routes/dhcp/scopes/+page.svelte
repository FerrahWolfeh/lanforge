<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
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
	import ServerIcon from "@lucide/svelte/icons/server";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import LayersIcon from "@lucide/svelte/icons/layers";
	import AlertTriangleIcon from "@lucide/svelte/icons/alert-triangle";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";

	import {
		dhcpOptionsGet,
		dhcpPoolsConfigGet,
		dhcpPoolsConfigUpdate,
		dhcpReconcile,
	} from "$lib/api/client";
	import type {
		Dhcpv4PoolConfig,
		Dhcpv6PoolConfig,
	} from "$lib/api/types";

	let loading = $state(true);
	let saving = $state(false);
	let reconciling = $state(false);

	let pristinePoolsJson = $state("");

	let v4Pools = $state<Dhcpv4PoolConfig[]>([]);
	let v6Pools = $state<Dhcpv6PoolConfig[]>([]);
	let activeUlaPrefix = $state<string | null>(null);
	let activeGuaPrefix = $state<string | null>(null);

	// Global Fallback Option Placeholders
	let globalV4Router = $state("192.168.0.1");
	let globalV4SubnetMask = $state("255.255.255.0");
	let globalV4DnsStr = $state("192.168.0.1");
	let globalV4LeaseTime = $state(86400);

	let globalV6DnsStr = $state("");
	let globalV6LeaseTime = $state(86400);

	// Modals
	let addV4ModalOpen = $state(false);
	let newV4Name = $state("");
	let newV4Start = $state("");
	let newV4End = $state("");
	let newV4Router = $state("");
	let newV4SubnetMask = $state("");
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

	const isDirty = $derived.by(() => {
		if (loading) return false;
		const currentPoolStr = JSON.stringify({
			v4_pools: v4Pools,
			v6_pools: v6Pools,
		});
		return currentPoolStr !== pristinePoolsJson;
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

			globalV4Router = opts.v4?.router ?? "";
			globalV4SubnetMask = opts.v4?.subnet_mask ?? "255.255.255.0";
			globalV4DnsStr = (opts.v4?.dns_servers ?? []).join(", ");
			globalV4LeaseTime = opts.v4?.lease_time ?? 86400;

			globalV6DnsStr = (opts.v6?.dns_servers ?? []).join(", ");
			globalV6LeaseTime = opts.v6?.lease_time ?? 86400;

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

	async function saveScopes() {
		saving = true;
		try {
			await dhcpPoolsConfigUpdate(v4Pools, v6Pools);
			pristinePoolsJson = JSON.stringify({
				v4_pools: v4Pools,
				v6_pools: v6Pools,
			});
			toast.success("DHCP address scopes saved successfully");
		} catch (err: any) {
			toast.error(`Failed to save scopes: ${err.message}`);
		} finally {
			saving = false;
		}
	}

	function discardChanges() {
		loadConfig();
		toast.info("Scope changes discarded");
	}

	async function reconcileLeases() {
		reconciling = true;
		try {
			const res = await dhcpReconcile();
			if (res.invalidated_v4_leases.length === 0) {
				toast.success(
					`DHCP Sanity Check: All dynamic leases are valid (${res.valid_v4_leases} active, ${res.preserved_static_leases} static preserved)`,
				);
			} else {
				toast.warning(
					`Sanity Check: Invalidated ${res.invalidated_v4_leases.length} out-of-range dynamic lease(s). ForceRenew sent.`,
					{
						description:
							res.invalidated_v4_leases
								.map((l) => `${l.mac} (${l.ip})`)
								.slice(0, 3)
								.join(", ") +
							(res.invalidated_v4_leases.length > 3 ? "..." : ""),
						duration: 8000,
					},
				);
			}
		} catch (err: any) {
			toast.error(`Failed to reconcile leases: ${err.message}`);
		} finally {
			reconciling = false;
		}
	}

	function openAddV4() {
		newV4Name = `LAN Scope ${v4Pools.length + 1}`;
		newV4Start = "";
		newV4End = "";
		newV4Router = "";
		newV4SubnetMask = globalV4SubnetMask;
		newV4Dns = "";
		newV4Lease = globalV4LeaseTime;
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

	function openAddV6() {
		newV6Name = `IPv6 Scope ${v6Pools.length + 1}`;
		newV6Start = "::100";
		newV6End = "::1fff";
		newV6Addr = "";
		newV6Dns = "";
		newV6Lease = globalV6LeaseTime;
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

<div class="flex flex-col gap-6 relative">
	<!-- Action Header -->
	<div
		class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-muted/30 border rounded-xl p-4 shadow-sm"
	>
		<div class="flex items-center gap-3">
			<div class="p-2.5 rounded-lg bg-primary/10 text-primary">
				<LayersIcon class="size-6" />
			</div>
			<div>
				<div class="flex items-center gap-2">
					<h2 class="text-lg font-bold tracking-tight">
						DHCP Address Scopes
					</h2>
					{#if isDirty}
						<Badge
							variant="outline"
							class="text-amber-500 border-amber-500/30 bg-amber-500/10 text-xs font-semibold animate-pulse"
						>
							Unsaved Changes
						</Badge>
					{/if}
				</div>
				<p class="text-xs text-muted-foreground mt-0.5">
					Define dynamic address allocation ranges for local devices.
				</p>
			</div>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				href="/dhcp/server"
				class="text-xs"
			>
				<SlidersIcon class="size-3.5 mr-1.5" />
				Server Options
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={reconcileLeases}
				disabled={reconciling || loading || saving}
				class="text-xs"
				title="Audit active dynamic leases against current subnet & pools. Invalidates out-of-range leases and prompts clients to re-authenticate (RFC 3203 ForceRenew)."
			>
				<ShieldCheckIcon
					class={`size-3.5 mr-1.5 ${reconciling ? "animate-spin text-primary" : "text-emerald-500"}`}
				/>
				{reconciling ? "Auditing..." : "Reconcile Leases"}
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={openAddV4}
				class="text-xs"
			>
				<PlusIcon class="size-3.5 mr-1" />
				Add IPv4 Scope
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={openAddV6}
				class="text-xs"
			>
				<PlusIcon class="size-3.5 mr-1" />
				Add IPv6 Scope
			</Button>

			{#if isDirty}
				<Button
					variant="ghost"
					size="sm"
					onclick={discardChanges}
					disabled={saving}
				>
					<RotateCcwIcon class="size-3.5 mr-1" />
					Discard
				</Button>
			{/if}

			<Button
				size="sm"
				onclick={saveScopes}
				disabled={!isDirty || saving || loading}
			>
				<SaveIcon class="size-3.5 mr-1" />
				{saving ? "Saving..." : "Save Scopes"}
			</Button>
		</div>
	</div>

	<!-- Info banner linking to Server Options -->
	<div
		class="flex items-center justify-between p-3.5 px-4 rounded-xl border border-primary/20 bg-primary/[0.04] text-xs"
	>
		<div class="flex items-center gap-2.5">
			<SlidersIcon class="size-4 text-primary shrink-0" />
			<span>
				Scopes inherit default gateway (<code class="font-mono font-bold text-primary"
					>{globalV4Router || "none"}</code
				>) and subnet mask (<code class="font-mono font-bold text-primary"
					>{globalV4SubnetMask || "255.255.255.0"}</code
				>) from global Server Options unless overridden per scope.
			</span>
		</div>
		<Button
			variant="link"
			size="sm"
			href="/dhcp/server"
			class="h-auto p-0 font-semibold text-primary"
		>
			Edit Server Options <ArrowRightIcon class="size-3 ml-1" />
		</Button>
	</div>

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-5">
			<Skeleton class="h-64 rounded-xl" />
			<Skeleton class="h-64 rounded-xl" />
		</div>
	{:else}
		<!-- IPv4 Scopes -->
		<div class="flex flex-col gap-4">
			<div class="flex items-center justify-between border-b pb-2">
				<div class="flex items-center gap-2">
					<ServerIcon class="size-5 text-blue-500" />
					<h3 class="text-base font-bold tracking-tight">
						IPv4 Address Scopes
					</h3>
					<Badge variant="outline" class="font-mono text-xs">
						{v4Pools.length} Scope{v4Pools.length === 1 ? "" : "s"}
					</Badge>
				</div>
			</div>

			{#if v4Pools.length === 0}
				<Card.Root class="border-dashed bg-muted/10">
					<Card.Content class="p-8 text-center flex flex-col items-center gap-3">
						<NetworkIcon
							class="size-8 text-muted-foreground/40"
						/>
						<div class="text-sm font-semibold">
							No Dynamic IPv4 Scopes Configured
						</div>
						<p class="text-xs text-muted-foreground max-w-md">
							Lanforge is currently not handing out dynamic IPv4 leases. Add an address scope to start serving dynamic IP ranges.
						</p>
						<Button size="sm" onclick={openAddV4}>
							<PlusIcon class="size-4 mr-1.5" />
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
									<div class="flex flex-col gap-0.5">
										<div class="flex items-center gap-2">
											<Badge
												variant="outline"
												class="font-mono text-[10px] text-blue-500 border-blue-500/30"
											>
												Scope #{idx + 1}
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
												class="text-emerald-500 font-semibold"
												>{pool.range_start}</span
											>
											to
											<span
												class="text-emerald-500 font-semibold"
												>{pool.range_end}</span
											>
										</p>
									</div>

									<Button
										variant="ghost"
										size="icon"
										class="size-8 text-destructive hover:text-destructive hover:bg-destructive/10"
										onclick={() => deleteV4Pool(idx)}
										title="Delete Scope"
									>
										<Trash2Icon class="size-4" />
									</Button>
								</div>
							</Card.Header>

							<Card.Content class="p-4 flex flex-col gap-4">
								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Scope Name</Label>
										<Input
											bind:value={pool.name}
											placeholder="e.g. Primary LAN Scope"
											class="text-xs"
										/>
									</div>
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Subnet Mask Override</Label>
										<Input
											bind:value={pool.subnet_mask}
											placeholder={globalV4SubnetMask || "255.255.255.0"}
											class="font-mono text-xs"
										/>
									</div>
								</div>

								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Range Start</Label>
										<Input
											bind:value={pool.range_start}
											placeholder="10.0.0.100"
											class="font-mono text-xs"
										/>
									</div>
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Range End</Label>
										<Input
											bind:value={pool.range_end}
											placeholder="10.0.3.240"
											class="font-mono text-xs"
										/>
									</div>
								</div>

								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Default Gateway (Option 3 Override)</Label>
										<Input
											bind:value={pool.router}
											placeholder={globalV4Router || "10.0.0.1"}
											class="font-mono text-xs"
										/>
									</div>
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Lease Duration Override (s)</Label>
										<Input
											type="number"
											bind:value={pool.lease_time}
											placeholder={String(globalV4LeaseTime)}
											class="font-mono text-xs"
										/>
									</div>
								</div>

								<div class="flex flex-col gap-1">
									<Label class="text-xs">DNS Servers (Option 6 Override)</Label>
									<Input
										value={(pool.dns_servers ?? []).join(", ")}
										oninput={(e) =>
											(pool.dns_servers = parseList(
												(e.target as HTMLInputElement).value,
											))}
										placeholder={globalV4DnsStr || "10.0.0.1"}
										class="font-mono text-xs"
									/>
								</div>
							</Card.Content>
						</Card.Root>
					{/each}
				</div>
			{/if}
		</div>

		<!-- IPv6 Scopes -->
		<div class="flex flex-col gap-4 mt-4">
			<div class="flex items-center justify-between border-b pb-2">
				<div class="flex items-center gap-2">
					<GlobeIcon class="size-5 text-purple-500" />
					<h3 class="text-base font-bold tracking-tight">
						IPv6 Address Scopes
					</h3>
					<Badge variant="outline" class="font-mono text-xs">
						{v6Pools.length} Scope{v6Pools.length === 1 ? "" : "s"}
					</Badge>
				</div>
			</div>

			{#if v6Pools.length === 0}
				<Card.Root class="border-dashed bg-muted/10">
					<Card.Content class="p-8 text-center flex flex-col items-center gap-3">
						<GlobeIcon
							class="size-8 text-muted-foreground/40"
						/>
						<div class="text-sm font-semibold">
							No Dynamic IPv6 Scopes Configured
						</div>
						<p class="text-xs text-muted-foreground max-w-md">
							Configure dynamic prefix suffix ranges (e.g. ::100 – ::1fff) or static CIDR subnets for stateful DHCPv6 clients.
						</p>
						<Button size="sm" onclick={openAddV6}>
							<PlusIcon class="size-4 mr-1.5" />
							Add IPv6 Suffix Scope
						</Button>
					</Card.Content>
				</Card.Root>
			{:else}
				<div class="grid grid-cols-1 xl:grid-cols-2 gap-5">
					{#each v6Pools as pool, idx (idx)}
						<Card.Root
							class="overflow-hidden border-border/80 shadow-sm hover:border-primary/40 transition-colors"
						>
							<Card.Header class="bg-muted/30 border-b pb-3.5">
								<div class="flex items-center justify-between">
									<div class="flex flex-col gap-0.5">
										<div class="flex items-center gap-2">
											<Badge
												variant="outline"
												class="font-mono text-[10px] text-purple-500 border-purple-500/30"
											>
												Scope #{idx + 1}
											</Badge>
											<span class="font-bold text-sm text-foreground">
												{pool.name || (pool.address ? pool.address : `${pool.range_start} – ${pool.range_end}`)}
											</span>
										</div>
									</div>

									<Button
										variant="ghost"
										size="icon"
										class="size-8 text-destructive hover:text-destructive hover:bg-destructive/10"
										onclick={() => deleteV6Pool(idx)}
										title="Delete Scope"
									>
										<Trash2Icon class="size-4" />
									</Button>
								</div>
							</Card.Header>

							<Card.Content class="p-4 flex flex-col gap-4">
								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Scope Name</Label>
										<Input
											bind:value={pool.name}
											placeholder="e.g. Main Suffix Scope"
											class="text-xs"
										/>
									</div>
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Static CIDR (Optional)</Label>
										<Input
											bind:value={pool.address}
											placeholder="fd00::/64"
											class="font-mono text-xs"
										/>
									</div>
								</div>

								<div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Suffix Range Start</Label>
										<Input
											bind:value={pool.range_start}
											placeholder="::100"
											class="font-mono text-xs"
										/>
									</div>
									<div class="flex flex-col gap-1">
										<Label class="text-xs">Suffix Range End</Label>
										<Input
											bind:value={pool.range_end}
											placeholder="::1fff"
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

		<div class="flex flex-col gap-3.5 py-3">
			<div class="flex flex-col gap-1">
				<Label for="addV4Name" class="text-xs">Scope Name</Label>
				<Input
					id="addV4Name"
					bind:value={newV4Name}
					placeholder="e.g. Primary LAN Scope"
					class="text-xs"
				/>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1">
					<Label for="addV4Start" class="text-xs">Range Start</Label>
					<Input
						id="addV4Start"
						bind:value={newV4Start}
						placeholder="10.0.0.100"
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1">
					<Label for="addV4End" class="text-xs">Range End</Label>
					<Input
						id="addV4End"
						bind:value={newV4End}
						placeholder="10.0.3.240"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1">
					<Label for="addV4Router" class="text-xs"
						>Default Gateway Override</Label
					>
					<Input
						id="addV4Router"
						bind:value={newV4Router}
						placeholder={globalV4Router || "10.0.0.1"}
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1">
					<Label for="addV4Subnet" class="text-xs">Subnet Mask Override</Label>
					<Input
						id="addV4Subnet"
						bind:value={newV4SubnetMask}
						placeholder={globalV4SubnetMask || "255.255.252.0"}
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1">
					<Label for="addV4Dns" class="text-xs">DNS Resolvers Override</Label>
					<Input
						id="addV4Dns"
						bind:value={newV4Dns}
						placeholder={globalV4DnsStr || "10.0.0.1"}
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1">
					<Label for="addV4Lease" class="text-xs"
						>Lease Duration (s)</Label
					>
					<Input
						id="addV4Lease"
						type="number"
						bind:value={newV4Lease}
						placeholder={String(globalV4LeaseTime)}
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

		<div class="flex flex-col gap-3.5 py-3">
			<div class="flex flex-col gap-1">
				<Label for="addV6Name" class="text-xs">Scope Name</Label>
				<Input
					id="addV6Name"
					bind:value={newV6Name}
					placeholder="e.g. Main Suffix Scope"
					class="text-xs"
				/>
			</div>

			<div class="grid grid-cols-2 gap-3">
				<div class="flex flex-col gap-1">
					<Label for="addV6Start" class="text-xs">Range Start Suffix</Label>
					<Input
						id="addV6Start"
						bind:value={newV6Start}
						placeholder="::100"
						class="font-mono text-xs"
					/>
				</div>
				<div class="flex flex-col gap-1">
					<Label for="addV6End" class="text-xs">Range End Suffix</Label>
					<Input
						id="addV6End"
						bind:value={newV6End}
						placeholder="::1fff"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<div class="flex flex-col gap-1">
				<Label for="addV6Addr" class="text-xs"
					>Static CIDR Segment (Optional)</Label
				>
				<Input
					id="addV6Addr"
					bind:value={newV6Addr}
					placeholder="fd00::/64"
					class="font-mono text-xs"
				/>
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
