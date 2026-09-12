<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import { toast } from "svelte-sonner";
	import HelpPopover from "$lib/components/HelpPopover.svelte";

	// Icons
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SaveIcon from "@lucide/svelte/icons/save";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import PlayIcon from "@lucide/svelte/icons/play";
	import SquareIcon from "@lucide/svelte/icons/square";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import FolderIcon from "@lucide/svelte/icons/folder";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import HelpCircleIcon from "@lucide/svelte/icons/help-circle";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";

	import {
		dhcpOptionsGet,
		dhcpOptionsUpdate,
		status as getSystemStatus,
		serviceBanners,
		controlService,
	} from "$lib/api/client";
	import type {
		DhcpOptionsConfig,
		TftpOptions,
		StatusResponse,
		ServiceBanner,
	} from "$lib/api/types";

	let loading = $state(true);
	let saving = $state(false);
	let serviceActionLoading = $state<string | null>(null);
	let copiedTarget = $state<string | null>(null);

	let fullOptions = $state<DhcpOptionsConfig | null>(null);
	let systemStatus = $state<StatusResponse | null>(null);
	let tftpBanner = $state<ServiceBanner | null>(null);

	// TFTP Server form fields
	let enabled = $state(false);
	let listenAddr = $state("0.0.0.0:69");
	let rootDir = $state("/var/lib/lanforge/tftp");
	let blockSize = $state(512);
	let timeoutSecs = $state(5);
	let maxRetries = $state(3);

	// DHCP PXE Integration fields
	let dhcpV4TftpServer = $state("");
	let dhcpV4BootFile = $state("");
	let dhcpV6BootFile = $state("");

	let pristineTftpJson = $state("");
	let pristineDhcpPxeJson = $state("");

	const BLOCK_SIZE_PRESETS = [
		{ label: "512 B (RFC Standard)", value: 512 },
		{ label: "1024 B", value: 1024 },
		{ label: "1456 B (Ethernet Optimal)", value: 1456 },
		{ label: "4096 B", value: 4096 },
		{ label: "8192 B (Fast Netboot)", value: 8192 },
	];

	const BOOTLOADER_PRESETS = [
		{
			name: "iPXE UEFI",
			file: "ipxe.efi",
			desc: "Modern UEFI network bootloader with HTTP/SAN support",
		},
		{
			name: "Syslinux BIOS",
			file: "pxelinux.0",
			desc: "Classic BIOS PXELINUX bootloader",
		},
		{
			name: "SNP Universal",
			file: "snponly.efi",
			desc: "UEFI Simple Network Protocol driver",
		},
		{
			name: "UNDI Legacy",
			file: "undionly.kpxe",
			desc: "Legacy BIOS chainloader",
		},
	];

	function currentTftpPayload(): TftpOptions {
		return {
			enabled,
			listen_addr: listenAddr.trim() || "0.0.0.0:69",
			root_dir: rootDir.trim() || "/var/lib/lanforge/tftp",
			block_size: Number(blockSize) || 512,
			timeout: Number(timeoutSecs) || 5,
			max_retries: Number(maxRetries) || 3,
		};
	}

	function currentDhcpPxePayload() {
		return {
			tftp_server: dhcpV4TftpServer.trim() || null,
			v4_boot_file: dhcpV4BootFile.trim() || null,
			v6_boot_file: dhcpV6BootFile.trim() || null,
		};
	}

	const isDirty = $derived.by(() => {
		if (loading) return false;
		const tftpChanged = JSON.stringify(currentTftpPayload()) !== pristineTftpJson;
		const dhcpChanged = JSON.stringify(currentDhcpPxePayload()) !== pristineDhcpPxeJson;
		return tftpChanged || dhcpChanged;
	});

	async function loadAllData() {
		loading = true;
		try {
			const [optsRes, sysRes, bannersRes] = await Promise.allSettled([
				dhcpOptionsGet(),
				getSystemStatus(),
				serviceBanners(),
			]);

			if (optsRes.status === "fulfilled") {
				fullOptions = optsRes.value;
				const tftp = optsRes.value.tftp ?? {
					enabled: false,
					listen_addr: "0.0.0.0:69",
					root_dir: "/var/lib/lanforge/tftp",
					block_size: 512,
					timeout: 5,
					max_retries: 3,
				};

				enabled = tftp.enabled ?? false;
				listenAddr = tftp.listen_addr || "0.0.0.0:69";
				rootDir = tftp.root_dir || "/var/lib/lanforge/tftp";
				blockSize = tftp.block_size || 512;
				timeoutSecs = tftp.timeout || 5;
				maxRetries = tftp.max_retries || 3;

				dhcpV4TftpServer = optsRes.value.v4?.tftp_server || "";
				dhcpV4BootFile = optsRes.value.v4?.boot_file || "";
				dhcpV6BootFile = optsRes.value.v6?.boot_file || "";

				pristineTftpJson = JSON.stringify(currentTftpPayload());
				pristineDhcpPxeJson = JSON.stringify(currentDhcpPxePayload());
			}

			if (sysRes.status === "fulfilled") {
				systemStatus = sysRes.value;
			}

			if (bannersRes.status === "fulfilled") {
				const list = bannersRes.value;
				tftpBanner = list.find(
					(b) => b.id?.toLowerCase() === "tftp" || b.name.toLowerCase().includes("tftp"),
				) ?? null;
			}
		} catch (err: any) {
			toast.error(`Failed to load TFTP server configuration: ${err.message}`);
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		if (!pristineTftpJson) return;
		const origTftp: TftpOptions = JSON.parse(pristineTftpJson);
		enabled = origTftp.enabled;
		listenAddr = origTftp.listen_addr;
		rootDir = origTftp.root_dir;
		blockSize = origTftp.block_size;
		timeoutSecs = origTftp.timeout;
		maxRetries = origTftp.max_retries;

		if (pristineDhcpPxeJson) {
			const origDhcp = JSON.parse(pristineDhcpPxeJson);
			dhcpV4TftpServer = origDhcp.tftp_server || "";
			dhcpV4BootFile = origDhcp.v4_boot_file || "";
			dhcpV6BootFile = origDhcp.v6_boot_file || "";
		}
		toast.info("Form reset to saved configuration");
	}

	async function saveAll() {
		if (!fullOptions) return;
		saving = true;
		try {
			const tftp = currentTftpPayload();
			const dhcp = currentDhcpPxePayload();

			const mergedPayload: DhcpOptionsConfig = {
				...fullOptions,
				tftp,
				v4: {
					...fullOptions.v4,
					tftp_server: dhcp.tftp_server,
					boot_file: dhcp.v4_boot_file,
				},
				v6: {
					...fullOptions.v6,
					boot_file: dhcp.v6_boot_file,
				},
			};

			await dhcpOptionsUpdate(mergedPayload);
			fullOptions = mergedPayload;
			pristineTftpJson = JSON.stringify(tftp);
			pristineDhcpPxeJson = JSON.stringify(dhcp);

			toast.success("TFTP server and DHCP bootstrapping options saved successfully");

			// Refresh banners to sync state
			setTimeout(async () => {
				try {
					const banners = await serviceBanners();
					tftpBanner = banners.find(
						(b) => b.id?.toLowerCase() === "tftp" || b.name.toLowerCase().includes("tftp"),
					) ?? null;
				} catch {
					// non-critical
				}
			}, 750);
		} catch (err: any) {
			toast.error(`Failed to save TFTP configuration: ${err.message}`);
		} finally {
			saving = false;
		}
	}

	async function handleServiceControl(action: "Start" | "Stop" | "Restart") {
		serviceActionLoading = action;
		try {
			await controlService("tftp", action);
			toast.success(`TFTP service received ${action.toLowerCase()} command`);
			setTimeout(async () => {
				const banners = await serviceBanners();
				tftpBanner = banners.find(
					(b) => b.id?.toLowerCase() === "tftp" || b.name.toLowerCase().includes("tftp"),
				) ?? null;
				serviceActionLoading = null;
			}, 750);
		} catch (err: any) {
			serviceActionLoading = null;
			toast.error(`Failed to ${action.toLowerCase()} TFTP service: ${err.message}`);
		}
	}

	function useLanforgeIp() {
		const ip = systemStatus?.network?.lan_ipv4;
		if (ip) {
			dhcpV4TftpServer = ip;
			toast.success(`Option 66 set to Lanforge IP: ${ip}`);
		} else {
			toast.error("Lanforge LAN IPv4 address not available from status");
		}
	}

	function applyPreset(file: string) {
		dhcpV4BootFile = file;
		dhcpV6BootFile = file;
		toast.success(`Boot filename set to ${file}`);
	}

	function copyToClipboard(text: string, label: string) {
		navigator.clipboard.writeText(text);
		copiedTarget = label;
		setTimeout(() => {
			copiedTarget = null;
		}, 2000);
		toast.success(`Copied ${label} to clipboard`);
	}

	onMount(loadAllData);

	const serviceState = $derived(tftpBanner?.state?.toLowerCase() ?? (enabled ? "active" : "inactive"));
	const isServiceActive = $derived(serviceState === "active" || serviceState === "online");
</script>

<svelte:head>
	<title>TFTP Server & Netboot — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<div class="flex items-center gap-2.5">
				<h1 class="text-foreground text-2xl font-bold tracking-tight">
					TFTP Server & Netboot
				</h1>
				<Badge
					variant={isServiceActive ? "default" : "secondary"}
					class="font-mono text-[10px] uppercase tracking-wider"
				>
					{serviceState}
				</Badge>
				<HelpPopover
					title="TFTP Netboot Setup"
					description="Trivial File Transfer Protocol server for PXE/UEFI network booting and OS installation."
				>
					{#snippet children()}
						<div class="flex flex-col gap-2.5 text-xs text-muted-foreground">
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">1. Filesystem Root</span>
								<span>Copy kernels or bootloaders (e.g. <code class="text-foreground">ipxe.efi</code>) into <code class="text-foreground">{rootDir}</code>.</span>
							</div>
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">2. Active Daemon</span>
								<span>Enable the TFTP server. Ensure UDP port 69 is reachable.</span>
							</div>
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">3. DHCP Option 66 & 67</span>
								<span>Option 66 points to Lanforge's IP, Option 67 specifies the NBP filename.</span>
							</div>
							<div class="flex flex-col gap-0.5 border-l-2 border-primary/50 pl-2">
								<span class="font-semibold text-foreground">4. PXE Client Boot</span>
								<span>Client BIOS/UEFI configured for PXE will bootstrap automatically.</span>
							</div>
						</div>
					{/snippet}
				</HelpPopover>
			</div>
			<p class="text-muted-foreground text-sm mt-0.5">
				TFTP server for PXE network booting and OS installation
			</p>
		</div>

		<!-- Action Bar -->
		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={loadAllData}
				disabled={loading}
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={loading ? "animate-spin" : ""}
				/>
				Refresh
			</Button>

			{#if isDirty}
				<Button
					variant="ghost"
					size="sm"
					onclick={resetForm}
					disabled={saving}
				>
					<RotateCcwIcon data-icon="inline-start" />
					Discard
				</Button>
				<Button
					size="sm"
					onclick={saveAll}
					disabled={saving}
				>
					<SaveIcon
						data-icon="inline-start"
						class={saving ? "animate-spin" : ""}
					/>
					Save Changes
				</Button>
			{/if}
		</div>
	</div>

	<!-- Vitals / Stat Cards (4 Cards) -->
	<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Card 1: Service State & Quick Actions -->
		<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
			<Card.Content class="flex flex-col gap-3 p-5">
				<div class="flex items-center justify-between">
					<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
						Service Lifecycle
					</span>
					<div
						class={[
							"flex size-8 items-center justify-center rounded-lg border",
							isServiceActive
								? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
								: "bg-zinc-500/10 border-zinc-500/20 text-zinc-400",
						].join(" ")}
					>
						<HardDriveDownloadIcon class="size-4" />
					</div>
				</div>

				{#if loading}
					<Skeleton class="h-8 w-24" />
					<Skeleton class="h-4 w-32" />
				{:else}
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2">
							<span
								class={[
									"size-2.5 rounded-full",
									isServiceActive
										? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
										: "bg-zinc-600",
								].join(" ")}
							></span>
							<span class="text-foreground text-lg font-bold capitalize">
								{serviceState}
							</span>
						</div>

						<div class="flex items-center gap-1">
							{#if isServiceActive}
								<Button
									variant="outline"
									size="icon-sm"
									onclick={() => handleServiceControl("Restart")}
									disabled={serviceActionLoading !== null}
									title="Restart TFTP Server"
								>
									<RotateCwIcon class={serviceActionLoading === "Restart" ? "animate-spin size-3.5" : "size-3.5"} />
								</Button>
								<Button
									variant="outline"
									size="icon-sm"
									class="text-rose-400 hover:text-rose-300"
									onclick={() => handleServiceControl("Stop")}
									disabled={serviceActionLoading !== null}
									title="Stop TFTP Server"
								>
									<SquareIcon class="size-3.5 fill-current" />
								</Button>
							{:else}
								<Button
									variant="outline"
									size="icon-sm"
									class="text-emerald-400 hover:text-emerald-300"
									onclick={() => handleServiceControl("Start")}
									disabled={serviceActionLoading !== null}
									title="Start TFTP Server"
								>
									<PlayIcon class="size-3.5 fill-current" />
								</Button>
							{/if}
						</div>
					</div>
					<span class="text-muted-foreground text-xs font-medium">
						{enabled ? "Enabled in system configuration" : "Disabled in configuration"}
					</span>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Card 2: Listen Socket -->
		<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
			<Card.Content class="flex flex-col gap-3 p-5">
				<div class="flex items-center justify-between">
					<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
						Listen Socket
					</span>
					<div class="bg-sky-500/10 border-sky-500/20 text-sky-400 flex size-8 items-center justify-center rounded-lg border">
						<RadioIcon class="size-4" />
					</div>
				</div>

				{#if loading}
					<Skeleton class="h-8 w-28" />
					<Skeleton class="h-4 w-20" />
				{:else}
					<div class="flex flex-col gap-0.5">
						<span class="text-foreground text-xl font-bold font-mono tracking-tight">
							{listenAddr || "0.0.0.0:69"}
						</span>
						<span class="text-muted-foreground text-xs font-medium">
							UDP Port 69 (Dual-Stack)
						</span>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Card 3: Root Directory -->
		<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
			<Card.Content class="flex flex-col gap-3 p-5">
				<div class="flex items-center justify-between">
					<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
						Root Directory
					</span>
					<div class="bg-amber-500/10 border-amber-500/20 text-amber-400 flex size-8 items-center justify-center rounded-lg border">
						<FolderIcon class="size-4" />
					</div>
				</div>

				{#if loading}
					<Skeleton class="h-8 w-36" />
					<Skeleton class="h-4 w-24" />
				{:else}
					<div class="flex flex-col gap-0.5">
						<span
							class="text-foreground text-sm font-bold font-mono truncate max-w-full"
							title={rootDir}
						>
							{rootDir || "/var/lib/lanforge/tftp"}
						</span>
						<span class="text-muted-foreground text-xs font-medium">
							Base filesystem path
						</span>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Card 4: Transfer Parameters -->
		<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
			<Card.Content class="flex flex-col gap-3 p-5">
				<div class="flex items-center justify-between">
					<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
						Transfer Tuning
					</span>
					<div class="bg-purple-500/10 border-purple-500/20 text-purple-400 flex size-8 items-center justify-center rounded-lg border">
						<NetworkIcon class="size-4" />
					</div>
				</div>

				{#if loading}
					<Skeleton class="h-8 w-24" />
					<Skeleton class="h-4 w-28" />
				{:else}
					<div class="flex flex-col gap-0.5">
						<span class="text-foreground text-xl font-bold font-mono tracking-tight">
							{blockSize} B / {timeoutSecs}s
						</span>
						<span class="text-muted-foreground text-xs font-medium">
							Max {maxRetries} block retries
						</span>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>

	<!-- Main Workspace Grid: TFTP Server Config (Col 1) + DHCP PXE Integration (Col 2) -->
	<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
		<!-- Panel 1: Server Configuration -->
		<Card.Root class="flex flex-col">
			<Card.Header class="pb-4 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<HardDriveDownloadIcon class="size-4 text-emerald-400" />
						<Card.Title class="text-base">Server Parameters</Card.Title>
					</div>
					<Badge variant="outline" class="font-mono text-[10px]">RFC 1350 / 2348</Badge>
				</div>
				<Card.Description>
					Configure daemon listening socket, filesystem root, and transmission block sizes
				</Card.Description>
			</Card.Header>

			<Card.Content class="flex flex-col gap-5 p-5">
				{#if loading}
					<div class="flex flex-col gap-4">
						<Skeleton class="h-12 w-full" />
						<Skeleton class="h-10 w-full" />
						<Skeleton class="h-10 w-full" />
					</div>
				{:else}
					<!-- Service Enable Switch -->
					<div class="flex items-center justify-between rounded-lg border border-border/70 bg-muted/20 p-3.5">
						<div class="flex flex-col gap-0.5">
							<span class="text-sm font-semibold text-foreground">
								Enable TFTP Daemon
							</span>
							<span class="text-xs text-muted-foreground">
								Binds UDP socket on startup and serves files to requesting clients
							</span>
						</div>
						<Switch bind:checked={enabled} />
					</div>

					<!-- Root Directory & Listen Address Grid -->
					<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
						<!-- Root Directory -->
						<div class="flex flex-col gap-2">
							<div class="flex items-center justify-between">
								<Label class="text-xs font-medium">Root Directory Path</Label>
								<Tooltip.Provider>
									<Tooltip.Root>
										<Tooltip.Trigger>
											<HelpCircleIcon class="size-3.5 text-muted-foreground" />
										</Tooltip.Trigger>
										<Tooltip.Content>
											<p class="text-xs max-w-xs">
												Directory where PXE files, kernels, and bootloaders reside. Path traversal outside this root is strictly forbidden by the daemon.
											</p>
										</Tooltip.Content>
									</Tooltip.Root>
								</Tooltip.Provider>
							</div>
							<Input
								bind:value={rootDir}
								placeholder="/var/lib/lanforge/tftp"
								class="font-mono text-xs"
							/>
						</div>

						<!-- Listen Address -->
						<div class="flex flex-col gap-2">
							<div class="flex items-center justify-between">
								<Label class="text-xs font-medium">Listen Address & Port</Label>
								<Tooltip.Provider>
									<Tooltip.Root>
										<Tooltip.Trigger>
											<HelpCircleIcon class="size-3.5 text-muted-foreground" />
										</Tooltip.Trigger>
										<Tooltip.Content>
											<p class="text-xs max-w-xs">
												Bind address for UDP requests. Default is 0.0.0.0:69 (IPv4) or [::]:69 for dual-stack.
											</p>
										</Tooltip.Content>
									</Tooltip.Root>
								</Tooltip.Provider>
							</div>
							<Input
								bind:value={listenAddr}
								placeholder="0.0.0.0:69"
								class="font-mono text-xs"
							/>
						</div>
					</div>

					<Separator class="my-1" />

					<!-- Transmission Tuning Grid -->
					<div class="flex flex-col gap-3">
						<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
							Protocol Transmission Tuning
						</span>

						<div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
							<!-- Block Size -->
							<div class="flex flex-col gap-1.5">
								<Label class="text-xs">Block Size (blksize)</Label>
								<Input
									type="number"
									min="512"
									max="65464"
									bind:value={blockSize}
									class="font-mono text-xs"
								/>
								<span class="text-[11px] text-muted-foreground">
									Default: 512 bytes
								</span>
							</div>

							<!-- Timeout -->
							<div class="flex flex-col gap-1.5">
								<Label class="text-xs">Timeout (seconds)</Label>
								<Input
									type="number"
									min="1"
									max="60"
									bind:value={timeoutSecs}
									class="font-mono text-xs"
								/>
								<span class="text-[11px] text-muted-foreground">
									Retransmission window
								</span>
							</div>

							<!-- Retries -->
							<div class="flex flex-col gap-1.5">
								<Label class="text-xs">Max Retries</Label>
								<Input
									type="number"
									min="1"
									max="10"
									bind:value={maxRetries}
									class="font-mono text-xs"
								/>
								<span class="text-[11px] text-muted-foreground">
									Fail after N drops
								</span>
							</div>
						</div>

						<!-- Block Size Quick Presets -->
						<div class="flex flex-wrap items-center gap-1.5 pt-1">
							<span class="text-[11px] text-muted-foreground mr-1">Presets:</span>
							{#each BLOCK_SIZE_PRESETS as preset (preset.value)}
								<Button
									variant={blockSize === preset.value ? "secondary" : "outline"}
									size="sm"
									class="h-6 text-[11px] px-2 py-0"
									onclick={() => { blockSize = preset.value; }}
								>
									{preset.label}
								</Button>
							{/each}
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>

		<!-- Panel 2: DHCP & Netboot PXE Integration -->
		<Card.Root class="flex flex-col">
			<Card.Header class="pb-4 border-b border-border/50">
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<NetworkIcon class="size-4 text-sky-400" />
						<Card.Title class="text-base">DHCP PXE Boot Integration</Card.Title>
					</div>
					<Badge variant="outline" class="font-mono text-[10px]">Option 66 / 67</Badge>
				</div>
				<Card.Description>
					Synchronize DHCP announcements so PXE/UEFI clients automatically bootstrap from this TFTP server
				</Card.Description>
			</Card.Header>

			<Card.Content class="flex flex-col gap-5 p-5">
				{#if loading}
					<div class="flex flex-col gap-4">
						<Skeleton class="h-10 w-full" />
						<Skeleton class="h-10 w-full" />
						<Skeleton class="h-10 w-full" />
					</div>
				{:else}
					<!-- Option 66: TFTP Server Address -->
					<div class="flex flex-col gap-2">
						<div class="flex items-center justify-between">
							<Label class="text-xs font-medium">
								DHCPv4 Next Server / TFTP Server (Option 66)
							</Label>
							{#if systemStatus?.network?.lan_ipv4}
								<Button
									variant="ghost"
									size="sm"
									class="h-6 text-[11px] text-primary px-2 py-0"
									onclick={useLanforgeIp}
								>
									<ZapIcon class="size-3 mr-1" />
									Use Lanforge IP ({systemStatus.network.lan_ipv4})
								</Button>
							{/if}
						</div>
						<Input
							bind:value={dhcpV4TftpServer}
							placeholder="192.168.1.1 (leave blank to omit)"
							class="font-mono text-xs"
						/>
						<span class="text-[11px] text-muted-foreground">
							Announced in DHCP OFFER and ACK packets as Option 66 (sname / siaddr target).
						</span>
					</div>

					<!-- Option 67: Boot Filename -->
					<div class="flex flex-col gap-2">
						<div class="flex items-center justify-between">
							<Label class="text-xs font-medium">
								DHCPv4 Boot Filename (Option 67)
							</Label>
							<span class="text-[11px] text-muted-foreground font-mono">file parameter</span>
						</div>
						<Input
							bind:value={dhcpV4BootFile}
							placeholder="ipxe.efi, pxelinux.0, bootx64.efi..."
							class="font-mono text-xs"
						/>
					</div>

					<!-- DHCPv6 Boot File -->
					<div class="flex flex-col gap-2">
						<div class="flex items-center justify-between">
							<Label class="text-xs font-medium">
								DHCPv6 Boot URL / Filename (Option 59)
							</Label>
							<Badge variant="outline" class="text-[9px] font-mono">IPv6 RFC 5970</Badge>
						</div>
						<Input
							bind:value={dhcpV6BootFile}
							placeholder="tftp://[2001:db8::1]/ipxe.efi or ipxe.efi"
							class="font-mono text-xs"
						/>
					</div>

					<Separator class="my-1" />

					<!-- Bootloader Presets -->
					<div class="flex flex-col gap-2.5">
						<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
							Popular Netboot Bootloaders
						</span>

						<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
							{#each BOOTLOADER_PRESETS as preset (preset.file)}
								<button
									type="button"
									class={[
										"flex flex-col items-start gap-1 rounded-lg border p-2.5 text-left transition-all",
										dhcpV4BootFile === preset.file
											? "border-primary bg-primary/10 text-foreground"
											: "border-border/60 bg-muted/20 hover:bg-muted/40 hover:border-zinc-700 text-muted-foreground",
									].join(" ")}
									onclick={() => applyPreset(preset.file)}
								>
									<div class="flex w-full items-center justify-between">
										<span class="text-xs font-semibold text-foreground">
											{preset.name}
										</span>
										{#if dhcpV4BootFile === preset.file}
											<CheckIcon class="size-3.5 text-primary" />
										{/if}
									</div>
									<span class="font-mono text-[11px] text-emerald-400">
										{preset.file}
									</span>
									<span class="text-[10px] leading-tight text-muted-foreground">
										{preset.desc}
									</span>
								</button>
							{/each}
						</div>
					</div>
				{/if}
			</Card.Content>
		</Card.Root>
	</div>
</div>
