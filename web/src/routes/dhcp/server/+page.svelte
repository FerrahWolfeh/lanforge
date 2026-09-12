<script lang="ts">
	import { onMount } from "svelte";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";
	import { dhcpOptionsGet, dhcpOptionsUpdate, dhcpReconcile } from "$lib/api/client";
	import type { DhcpOptionsConfig, TftpOptions } from "$lib/api/types";

	import DhcpServerHeader from "./components/DhcpServerHeader.svelte";
	import DhcpV4OptionsCard from "./components/DhcpV4OptionsCard.svelte";
	import DhcpV6OptionsCard from "./components/DhcpV6OptionsCard.svelte";
	import DhcpNetbootCard from "./components/DhcpNetbootCard.svelte";
	import DhcpRawOptionsCard from "./components/DhcpRawOptionsCard.svelte";

	let loading = $state(true);
	let saving = $state(false);
	let reconciling = $state(false);
	let pristineJson = $state("");
	let currentTftpConfig = $state<TftpOptions>({
		enabled: false,
		listen_addr: "0.0.0.0:69",
		root_dir: "/var/lib/lanforge/tftp",
		block_size: 512,
		timeout: 5,
		max_retries: 3,
	});

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
			tftp: currentTftpConfig,
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
		if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
			const u32 =
				((parts[0] << 24) |
					(parts[1] << 16) |
					(parts[2] << 8) |
					parts[3]) >>>
				0;
			let ones = 0;
			let bit = 31;
			while (bit >= 0 && (u32 & (1 << bit)) !== 0) {
				ones++;
				bit--;
			}
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

			if (opts.tftp) {
				currentTftpConfig = { ...opts.tftp };
			}

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
			toast.success("DHCP server options saved and propagated successfully");
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

	onMount(() => {
		loadOptions();
	});
</script>

<div class="flex flex-col gap-6 w-full">
	<!-- Action Header -->
	<DhcpServerHeader
		{isDirty}
		{loading}
		{saving}
		{reconciling}
		onReconcile={reconcileLeases}
		onRefresh={loadOptions}
		onDiscard={discardChanges}
		onSave={saveOptions}
	/>

	{#if loading}
		<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
			<Skeleton class="h-96 rounded-xl" />
			<Skeleton class="h-96 rounded-xl" />
		</div>
	{:else}
		<!-- 1. PRIMARY IPv4 SERVER OPTIONS -->
		<DhcpV4OptionsCard
			bind:v4Enabled
			bind:v4Router
			bind:v4SubnetMask
			bind:v4DnsStr
			bind:v4DomainName
			bind:v4SearchDomainsStr
			bind:v4NtpStr
			bind:v4LeaseTime
			{subnetInfo}
			{humanLeaseDuration}
		/>

		<!-- 2. PRIMARY IPv6 SERVER OPTIONS -->
		<DhcpV6OptionsCard
			bind:v6Enabled
			bind:v6LeaseTime
			bind:v6DnsStr
			bind:v6SearchDomainsStr
			bind:v6NtpStr
		/>

		<!-- 3. PXE & NETWORK BOOT OPTIONS -->
		<DhcpNetbootCard
			bind:v4TftpServer
			bind:v4BootFile
			bind:v6BootFile
		/>

		<!-- 4. CUSTOM RAW OPTIONS -->
		<DhcpRawOptionsCard
			bind:v4RawOptions
			bind:v6RawOptions
		/>
	{/if}
</div>
