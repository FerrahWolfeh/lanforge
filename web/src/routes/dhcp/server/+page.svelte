<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";

	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";

	import { dhcpOptionsGet, dhcpOptionsUpdate, dhcpReconcile } from "$lib/api/client";
	import type { DhcpOptionsConfig } from "$lib/api/types";

	let loading = $state(true);
	let saving = $state(false);
	let reconciling = $state(false);
	let pristineJson = $state("");

	// IPv4 Global Settings
	let v4Enabled = $state(true);
	let v4Router = $state("192.168.0.1");
	let v4SubnetMask = $state("255.255.255.0");
	let v4DnsStr = $state("192.168.0.1");
	let v4DomainName = $state("");
	let v4SearchDomainsStr = $state("");
	let v4NtpStr = $state("162.159.200.1, 216.239.35.0");
	let v4LeaseTime = $state(86400);
	let v4TftpServer = $state("");
	let v4BootFile = $state("");

	// IPv6 Global Settings
	let v6Enabled = $state(true);
	let v6LeaseTime = $state(86400);
	let v6DnsStr = $state("");
	let v6SearchDomainsStr = $state("");
	let v6NtpStr = $state("time.cloudflare.com, time.google.com");
	let v6BootFile = $state("");

	// Custom Raw Options
	let v4RawOptions = $state<Array<{ code: number; value: string }>>([]);
	let v6RawOptions = $state<Array<{ code: number; value: string }>>([]);
	let newRawV4Code = $state<number | "">("");
	let newRawV4Value = $state("");
	let newRawV6Code = $state<number | "">("");
	let newRawV6Value = $state("");

	function parseList(str: string): string[] {
		return str
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean);
	}

	function currentPayload(): DhcpOptionsConfig {
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
				enabled: false,
				listen_addr: "0.0.0.0:69",
				root_dir: "/var/lib/lanforge/tftp",
				block_size: 512,
				timeout: 5,
				max_retries: 3,
			},
		};
	}

	const isDirty = $derived.by(() => {
		if (loading) return false;
		return JSON.stringify(currentPayload()) !== pristineJson;
	});

	// Subnet Mask calculation helper
	const subnetInfo = $derived.by(() => {
		const trimmed = v4SubnetMask.trim();
		const parts = trimmed.split(".").map(Number);
		if (
			parts.length === 4 &&
			parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)
		) {
			const u32 =
				((parts[0] << 24) |
					(parts[1] << 16) |
					(parts[2] << 8) |
					parts[3]) >>>
				0;
			// check contiguous ones
			let ones = 0;
			let bit = 31;
			while (bit >= 0 && (u32 & (1 << bit)) !== 0) {
				ones++;
				bit--;
			}
			// check remaining bits are zero
			let valid = true;
			while (bit >= 0) {
				if ((u32 & (1 << bit)) !== 0) {
					valid = false;
					break;
				}
				bit--;
			}

			if (valid) {
				const totalHosts = Math.pow(2, 32 - ones);
				const usable = Math.max(0, totalHosts - 2);
				return {
					valid: true,
					cidr: `/${ones}`,
					totalHosts,
					usableHosts: usable,
				};
			}
		}
		return { valid: false, cidr: "", totalHosts: 0, usableHosts: 0 };
	});

	// Human-readable lease duration
	const humanLeaseDuration = $derived.by(() => {
		const secs = Number(v4LeaseTime) || 0;
		if (secs <= 0) return "Indefinite / Unspecified";
		const d = Math.floor(secs / 86400);
		const h = Math.floor((secs % 86400) / 3600);
		const m = Math.floor((secs % 3600) / 60);

		const parts: string[] = [];
		if (d > 0) parts.push(`${d} ${d === 1 ? "day" : "days"}`);
		if (h > 0) parts.push(`${h} ${h === 1 ? "hour" : "hours"}`);
		if (m > 0 && d === 0) parts.push(`${m} ${m === 1 ? "min" : "mins"}`);
		return parts.join(", ") || `${secs}s`;
	});

	async function loadOptions() {
		loading = true;
		try {
			const opts = await dhcpOptionsGet();
			v4Enabled = opts.v4?.enabled ?? true;
			v4Router = opts.v4?.router ?? "";
			v4SubnetMask = opts.v4?.subnet_mask ?? "255.255.255.0";
			v4DnsStr = (opts.v4?.dns_servers ?? []).join(", ");
			v4DomainName = opts.v4?.domain_name ?? "";
			v4SearchDomainsStr = (opts.v4?.search_domains ?? []).join(", ");
			v4NtpStr = (opts.v4?.ntp_servers ?? []).join(", ");
			v4LeaseTime = opts.v4?.lease_time ?? 86400;
			v4TftpServer = opts.v4?.tftp_server ?? "";
			v4BootFile = opts.v4?.boot_file ?? "";

			v4RawOptions = Object.entries(opts.v4?.raw_options ?? {}).map(
				([k, v]) => ({
					code: Number(k),
					value: v,
				}),
			);

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

			pristineJson = JSON.stringify(currentPayload());
		} catch (err: any) {
			toast.error(`Failed to load DHCP server options: ${err.message}`);
		} finally {
			loading = false;
		}
	}

	async function saveOptions() {
		saving = true;
		try {
			const payload = currentPayload();
			await dhcpOptionsUpdate(payload);
			pristineJson = JSON.stringify(payload);
			toast.success(
				"DHCP server options saved and propagated successfully",
			);
		} catch (err: any) {
			toast.error(`Failed to save options: ${err.message}`);
		} finally {
			saving = false;
		}
	}

	function discardChanges() {
		loadOptions();
		toast.info("Changes discarded");
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

	function addV4Raw() {
		if (
			typeof newRawV4Code === "number" &&
			newRawV4Code > 0 &&
			newRawV4Value.trim()
		) {
			v4RawOptions = [
				...v4RawOptions.filter((o) => o.code !== newRawV4Code),
				{ code: newRawV4Code, value: newRawV4Value.trim() },
			];
			newRawV4Code = "";
			newRawV4Value = "";
		}
	}

	function removeV4Raw(idx: number) {
		v4RawOptions = v4RawOptions.filter((_, i) => i !== idx);
	}

	function addV6Raw() {
		if (
			typeof newRawV6Code === "number" &&
			newRawV6Code > 0 &&
			newRawV6Value.trim()
		) {
			v6RawOptions = [
				...v6RawOptions.filter((o) => o.code !== newRawV6Code),
				{ code: newRawV6Code, value: newRawV6Value.trim() },
			];
			newRawV6Code = "";
			newRawV6Value = "";
		}
	}

	function removeV6Raw(idx: number) {
		v6RawOptions = v6RawOptions.filter((_, i) => i !== idx);
	}

	onMount(() => {
		loadOptions();
	});
</script>

<div class="flex flex-col gap-6">
	<!-- Action Header -->
	<div
		class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 bg-muted/30 border rounded-xl p-4 shadow-sm"
	>
		<div class="flex items-center gap-3">
			<div class="p-2.5 rounded-lg bg-primary/10 text-primary">
				<SlidersIcon class="size-6" />
			</div>
			<div>
				<div class="flex items-center gap-2">
					<h2 class="text-lg font-bold tracking-tight">
						DHCP Server Options
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
					Global parameters broadcasted to all DHCP clients on your
					network link.
				</p>
			</div>
		</div>

		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={reconcileLeases}
				disabled={reconciling || loading || saving}
				title="Audit active dynamic leases against current subnet & pools. Invalidates out-of-range leases and prompts clients to re-authenticate (RFC 3203 ForceRenew)."
			>
				<ShieldCheckIcon
					class={`size-4 mr-1.5 ${reconciling ? "animate-spin text-primary" : "text-emerald-500"}`}
				/>
				{reconciling ? "Auditing..." : "Reconcile Leases"}
			</Button>

			<Button
				variant="outline"
				size="sm"
				onclick={loadOptions}
				disabled={loading || saving || reconciling}
				title="Reload from server"
			>
				<RefreshCwIcon
					class={`size-4 mr-1.5 ${loading ? "animate-spin" : ""}`}
				/>
				Refresh
			</Button>

			{#if isDirty}
				<Button
					variant="ghost"
					size="sm"
					onclick={discardChanges}
					disabled={saving}
				>
					<RotateCcwIcon class="size-4 mr-1.5" />
					Discard
				</Button>
			{/if}

			<Button
				size="sm"
				onclick={saveOptions}
				disabled={!isDirty || saving || loading}
			>
				<SaveIcon class="size-4 mr-1.5" />
				{saving ? "Saving..." : "Save Server Options"}
			</Button>
		</div>
	</div>

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
			<Skeleton class="h-96 rounded-xl" />
			<Skeleton class="h-96 rounded-xl" />
		</div>
	{:else}
		<!-- 1. PRIMARY IPv4 SERVER OPTIONS -->
		<Card.Root class="border-border/80 shadow-sm overflow-hidden">
			<Card.Header class="bg-muted/20 border-b pb-4">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2.5">
						<NetworkIcon class="size-5 text-blue-500" />
						<div>
							<Card.Title class="text-base font-bold"
								>IPv4 Network Parameters</Card.Title
							>
							<Card.Description class="text-xs">
								Core DHCPv4 options advertised to all dynamic
								leases (RFC 2132)
							</Card.Description>
						</div>
					</div>

					<div class="flex items-center gap-2">
						<Label for="v4-enable-toggle" class="text-xs font-medium"
							>DHCPv4 Service</Label
						>
						<Switch
							id="v4-enable-toggle"
							bind:checked={v4Enabled}
						/>
					</div>
				</div>
			</Card.Header>

			<Card.Content class="p-6 flex flex-col gap-6">
				<!-- Highlighted: Default Gateway (Option 3) -->
				<div
					class="p-4 rounded-xl border border-primary/20 bg-primary/[0.03] flex flex-col gap-3"
				>
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<Label
								for="v4-router"
								class="text-sm font-bold text-foreground"
							>
								Default Gateway (Option 3 — Router)
							</Label>
							{#if v4Router.trim()}
								<Badge
									variant="outline"
									class="text-[10px] text-emerald-500 border-emerald-500/30 bg-emerald-500/10 font-mono"
								>
									Active Gateway
								</Badge>
							{:else}
								<Badge
									variant="outline"
									class="text-[10px] text-amber-500 border-amber-500/30 bg-amber-500/10 font-mono"
								>
									Not Advertised
								</Badge>
							{/if}
						</div>
					</div>

					<div class="flex flex-col sm:flex-row gap-3">
						<div class="flex-1">
							<Input
								id="v4-router"
								bind:value={v4Router}
								placeholder="e.g. 10.0.0.1 or 192.168.1.1"
								class="font-mono text-sm font-semibold h-10 border-primary/30 focus-visible:ring-primary"
							/>
						</div>
					</div>
					<p class="text-xs text-muted-foreground">
						This IP is advertised to all DHCP clients as their
						default router. Clients send all default/internet
						traffic through this address.
					</p>
				</div>

				<!-- Subnet Mask (Option 1) with CIDR calculation & quick presets -->
				<div class="flex flex-col gap-2.5">
					<div class="flex items-center justify-between">
						<Label for="v4-subnet-mask" class="text-xs font-semibold">
							Subnet Mask (Option 1)
						</Label>
						{#if subnetInfo.valid}
							<span
								class="text-xs font-mono font-medium text-primary"
							>
								{subnetInfo.cidr} · {subnetInfo.usableHosts.toLocaleString()}
								usable hosts
							</span>
						{/if}
					</div>

					<div class="flex flex-col sm:flex-row gap-3">
						<Input
							id="v4-subnet-mask"
							bind:value={v4SubnetMask}
							placeholder="255.255.252.0"
							class="font-mono text-xs sm:w-64"
						/>

						<!-- Quick Presets -->
						<div class="flex flex-wrap items-center gap-1.5">
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9 px-2.5"
								onclick={() => (v4SubnetMask = "255.255.255.0")}
							>
								/24 (255.255.255.0)
							</Button>
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9 px-2.5 font-medium border-primary/30"
								onclick={() => (v4SubnetMask = "255.255.252.0")}
							>
								/22 (255.255.252.0)
							</Button>
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9 px-2.5"
								onclick={() => (v4SubnetMask = "255.255.254.0")}
							>
								/23 (255.255.254.0)
							</Button>
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9 px-2.5"
								onclick={() => (v4SubnetMask = "255.255.0.0")}
							>
								/16 (255.255.0.0)
							</Button>
						</div>
					</div>
					<p class="text-xs text-muted-foreground">
						Broadcasted network mask. For a /22 subnet, use
						<code class="font-mono text-primary font-semibold"
							>255.255.252.0</code
						>
						(1,022 usable host addresses).
					</p>
				</div>

				<Separator />

				<!-- DNS & Domains -->
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div class="flex flex-col gap-1.5">
						<Label for="v4-dns" class="text-xs font-semibold"
							>DNS Resolvers (Option 6)</Label
						>
						<Input
							id="v4-dns"
							bind:value={v4DnsStr}
							placeholder="192.168.0.1, 1.1.1.1"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Comma-separated list of IPv4 DNS servers.
						</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v4-domain" class="text-xs font-semibold"
							>Local Domain Name (Option 15)</Label
						>
						<Input
							id="v4-domain"
							bind:value={v4DomainName}
							placeholder="lan, home.arpa"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Appended to unqualified hostnames on the link.
						</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v4-search" class="text-xs font-semibold"
							>Domain Search List (Option 119)</Label
						>
						<Input
							id="v4-search"
							bind:value={v4SearchDomainsStr}
							placeholder="lan, internal.corp"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Comma-separated list of search domain suffixes.
						</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v4-ntp" class="text-xs font-semibold"
							>NTP Time Servers (Option 42)</Label
						>
						<Input
							id="v4-ntp"
							bind:value={v4NtpStr}
							placeholder="162.159.200.1, 216.239.35.0"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							NTP time synchronization IPs for network clients.
						</p>
					</div>
				</div>

				<Separator />

				<!-- Default Lease Lifetime -->
				<div class="flex flex-col gap-2.5">
					<div class="flex items-center justify-between">
						<Label for="v4-lease-time" class="text-xs font-semibold"
							>Default Lease Duration (Seconds)</Label
						>
						<span
							class="text-xs font-medium text-emerald-500 font-mono"
						>
							≈ {humanLeaseDuration}
						</span>
					</div>

					<div class="flex flex-col sm:flex-row gap-3">
						<Input
							id="v4-lease-time"
							type="number"
							bind:value={v4LeaseTime}
							placeholder="86400"
							class="font-mono text-xs sm:w-48"
						/>

						<div class="flex flex-wrap items-center gap-1.5">
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9"
								onclick={() => (v4LeaseTime = 43200)}
								>12h (43200s)</Button
							>
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9"
								onclick={() => (v4LeaseTime = 86400)}
								>24h (86400s)</Button
							>
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9"
								onclick={() => (v4LeaseTime = 604800)}
								>7d (604800s)</Button
							>
							<Button
								variant="outline"
								size="sm"
								class="text-xs h-9"
								onclick={() => (v4LeaseTime = 2592000)}
								>30d (2592000s)</Button
							>
						</div>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- 2. PRIMARY IPv6 SERVER OPTIONS -->
		<Card.Root class="border-border/80 shadow-sm overflow-hidden">
			<Card.Header class="bg-muted/20 border-b pb-4">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2.5">
						<GlobeIcon class="size-5 text-purple-500" />
						<div>
							<Card.Title class="text-base font-bold"
								>IPv6 Network Parameters</Card.Title
							>
							<Card.Description class="text-xs">
								Global DHCPv6 options advertised to stateful
								clients (RFC 8415)
							</Card.Description>
						</div>
					</div>

					<div class="flex items-center gap-2">
						<Label for="v6-enable-toggle" class="text-xs font-medium"
							>DHCPv6 Service</Label
						>
						<Switch
							id="v6-enable-toggle"
							bind:checked={v6Enabled}
						/>
					</div>
				</div>
			</Card.Header>

			<Card.Content class="p-6 flex flex-col gap-6">
				<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
					<div class="flex flex-col gap-1.5">
						<Label for="v6-dns" class="text-xs font-semibold"
							>DNS Recursive Servers (Option 23)</Label
						>
						<Input
							id="v6-dns"
							bind:value={v6DnsStr}
							placeholder="fd00::1, 2606:4700:4700::1111"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Comma-separated list of IPv6 recursive DNS servers.
						</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v6-lease" class="text-xs font-semibold"
							>Lease Duration (Seconds)</Label
						>
						<Input
							id="v6-lease"
							type="number"
							bind:value={v6LeaseTime}
							placeholder="86400"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Valid lifetime for stateful IPv6 leases.
						</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v6-search" class="text-xs font-semibold"
							>Domain Search List (Option 24)</Label
						>
						<Input
							id="v6-search"
							bind:value={v6SearchDomainsStr}
							placeholder="lan, internal.corp"
							class="font-mono text-xs"
						/>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v6-ntp" class="text-xs font-semibold"
							>NTP Servers (Option 56)</Label
						>
						<Input
							id="v6-ntp"
							bind:value={v6NtpStr}
							placeholder="time.cloudflare.com, time.google.com"
							class="font-mono text-xs"
						/>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- 3. PXE & NETWORK BOOT OPTIONS -->
		<Card.Root class="border-border/80 shadow-sm overflow-hidden">
			<Card.Header class="bg-muted/20 border-b pb-4">
				<div class="flex items-center gap-2.5">
					<HardDriveIcon class="size-5 text-amber-500" />
					<div>
						<Card.Title class="text-base font-bold"
							>Network Boot & TFTP Parameters</Card.Title
						>
						<Card.Description class="text-xs">
							Default PXE and UEFI HTTP netboot options (Option
							66, 67, 59)
						</Card.Description>
					</div>
				</div>
			</Card.Header>

			<Card.Content class="p-6">
				<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
					<div class="flex flex-col gap-1.5">
						<Label
							for="v4-tftp-server"
							class="text-xs font-semibold"
						>
							Next-Server / siaddr (Option 66)
						</Label>
						<Input
							id="v4-tftp-server"
							bind:value={v4TftpServer}
							placeholder="e.g. 10.0.0.1"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							TFTP server IP advertised to PXE netboot clients.
						</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v4-boot-file" class="text-xs font-semibold">
							Default IPv4 Boot File (Option 67)
						</Label>
						<Input
							id="v4-boot-file"
							bind:value={v4BootFile}
							placeholder="ipxe.efi, pxelinux.0"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							Initial Network Bootstrap Program (NBP) file.
						</p>
					</div>

					<div class="flex flex-col gap-1.5">
						<Label for="v6-boot-file" class="text-xs font-semibold">
							Default IPv6 Boot URL (Option 59)
						</Label>
						<Input
							id="v6-boot-file"
							bind:value={v6BootFile}
							placeholder="tftp://[fd00::1]/ipxe.efi"
							class="font-mono text-xs"
						/>
						<p class="text-[11px] text-muted-foreground">
							DHCPv6 network bootloader URL.
						</p>
					</div>
				</div>
			</Card.Content>
		</Card.Root>

		<!-- 4. CUSTOM RAW OPTIONS -->
		<Card.Root class="border-border/80 shadow-sm overflow-hidden">
			<Card.Header class="bg-muted/20 border-b pb-4">
				<div class="flex items-center gap-2.5">
					<SlidersIcon class="size-5 text-emerald-500" />
					<div>
						<Card.Title class="text-base font-bold"
							>Custom Raw DHCP Options</Card.Title
						>
						<Card.Description class="text-xs">
							Inject arbitrary RFC or vendor-specific option code
							payloads into DHCP packets
						</Card.Description>
					</div>
				</div>
			</Card.Header>

			<Card.Content class="p-6">
				<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
					<!-- IPv4 Raw Options -->
					<div class="flex flex-col gap-3">
						<div class="flex items-center gap-2">
							<Badge
								variant="outline"
								class="font-mono text-[10px] text-blue-500 border-blue-500/30"
								>IPv4</Badge
							>
							<span class="text-xs font-bold text-foreground"
								>Raw Option Codes</span
							>
						</div>

						{#if v4RawOptions.length > 0}
							<div
								class="border rounded-lg overflow-hidden font-mono text-xs"
							>
								<Table.Root>
									<Table.Header class="bg-muted/40">
										<Table.Row>
											<Table.Head class="w-28"
												>Option Code</Table.Head
											>
											<Table.Head>Payload</Table.Head>
											<Table.Head
												class="w-12 text-right"
											></Table.Head>
										</Table.Row>
									</Table.Header>
									<Table.Body>
										{#each v4RawOptions as opt, idx}
											<Table.Row>
												<Table.Cell class="font-bold">
													Option {opt.code}
												</Table.Cell>
												<Table.Cell
													>{opt.value}</Table.Cell
												>
												<Table.Cell class="text-right">
													<Button
														variant="ghost"
														size="icon"
														class="size-6 text-destructive hover:text-destructive"
														onclick={() =>
															removeV4Raw(idx)}
													>
														<Trash2Icon
															class="size-3.5"
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
								<PlusIcon class="size-3.5 mr-1" />
								Add
							</Button>
						</div>
					</div>

					<!-- IPv6 Raw Options -->
					<div class="flex flex-col gap-3">
						<div class="flex items-center gap-2">
							<Badge
								variant="outline"
								class="font-mono text-[10px] text-purple-500 border-purple-500/30"
								>IPv6</Badge
							>
							<span class="text-xs font-bold text-foreground"
								>Raw Option Codes</span
							>
						</div>

						{#if v6RawOptions.length > 0}
							<div
								class="border rounded-lg overflow-hidden font-mono text-xs"
							>
								<Table.Root>
									<Table.Header class="bg-muted/40">
										<Table.Row>
											<Table.Head class="w-28"
												>Option Code</Table.Head
											>
											<Table.Head>Payload</Table.Head>
											<Table.Head
												class="w-12 text-right"
											></Table.Head>
										</Table.Row>
									</Table.Header>
									<Table.Body>
										{#each v6RawOptions as opt, idx}
											<Table.Row>
												<Table.Cell class="font-bold">
													Option {opt.code}
												</Table.Cell>
												<Table.Cell
													>{opt.value}</Table.Cell
												>
												<Table.Cell class="text-right">
													<Button
														variant="ghost"
														size="icon"
														class="size-6 text-destructive hover:text-destructive"
														onclick={() =>
															removeV6Raw(idx)}
													>
														<Trash2Icon
															class="size-3.5"
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
								<PlusIcon class="size-3.5 mr-1" />
								Add
							</Button>
						</div>
					</div>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}
</div>
