<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { Separator } from "$lib/components/ui/separator";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { status, scan, reload } from "$lib/api/client";
	import { normalizeServices, type StatusResponse } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import HardDriveIcon from "@lucide/svelte/icons/hard-drive";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import LoaderIcon from "@lucide/svelte/icons/loader";

	let data = $state<StatusResponse | null>(null);
	let loading = $state(true);
	let reloading = $state(false);
	let scanning = $state(false);

	async function loadStatus() {
		loading = true;
		try {
			data = await status();
		} catch {
			toast.error("Could not fetch system status");
		} finally {
			loading = false;
		}
	}

	async function triggerScan() {
		scanning = true;
		try {
			await scan();
			toast.success("Network scan triggered");
		} catch {
			toast.error("Failed to trigger scan");
		} finally {
			scanning = false;
		}
	}

	async function triggerReload() {
		reloading = true;
		try {
			await reload();
			toast.success("Configuration reloaded");
		} catch {
			toast.error("Failed to reload configuration");
		} finally {
			reloading = false;
		}
	}

	onMount(loadStatus);

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
	}

	function formatUptime(secs: number): string {
		const d = Math.floor(secs / 86400);
		const h = Math.floor((secs % 86400) / 3600);
		const m = Math.floor((secs % 3600) / 60);
		if (d > 0) return `${d}d ${h}h ${m}m`;
		if (h > 0) return `${h}h ${m}m`;
		return `${m}m ${secs % 60}s`;
	}

	const serviceList = $derived(normalizeServices(data));

	function stateIcon(state: string) {
		if (state === "active") return CheckCircleIcon;
		if (state === "starting") return LoaderIcon;
		return XCircleIcon;
	}

	function stateColor(state: string) {
		if (state === "active") return "text-green-400";
		if (state === "starting") return "text-yellow-400";
		return "text-red-400";
	}
</script>

<svelte:head>
	<title>System — Lanforge</title>
</svelte:head>

<div class="flex items-center justify-between">
	<div>
		<h1 class="text-foreground text-2xl font-bold tracking-tight">
			System
		</h1>
		<p class="text-muted-foreground text-sm">
			Daemon status and operations
		</p>
	</div>
	<div class="flex gap-2">
		<Button
			variant="outline"
			size="sm"
			onclick={loadStatus}
			disabled={loading}
		>
			<RefreshCwIcon
				data-icon="inline-start"
				class={loading ? "animate-spin" : ""}
			/>
			Refresh
		</Button>
		<Button
			variant="outline"
			size="sm"
			onclick={triggerScan}
			disabled={scanning}
		>
			<ZapIcon data-icon="inline-start" />
			{scanning ? "Scanning…" : "Scan"}
		</Button>

		<AlertDialog.Root>
			<AlertDialog.Trigger>
				{#snippet child({ props })}
					<Button
						variant="outline"
						size="sm"
						{...props}
						disabled={reloading}
					>
						<RefreshCwIcon
							data-icon="inline-start"
							class={reloading ? "animate-spin" : ""}
						/>
						{reloading ? "Reloading…" : "Reload Config"}
					</Button>
				{/snippet}
			</AlertDialog.Trigger>
			<AlertDialog.Content>
				<AlertDialog.Header>
					<AlertDialog.Title>Reload configuration?</AlertDialog.Title>
					<AlertDialog.Description>
						This will re-read <code class="font-mono"
							>lanforge.toml</code
						> from disk. Active sessions and leases are not affected,
						but DNS/DHCP services may briefly restart.
					</AlertDialog.Description>
				</AlertDialog.Header>
				<AlertDialog.Footer>
					<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
					<AlertDialog.Action onclick={triggerReload}
						>Reload</AlertDialog.Action
					>
				</AlertDialog.Footer>
			</AlertDialog.Content>
		</AlertDialog.Root>
	</div>
</div>

<div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
	<!-- Uptime -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<ZapIcon class="text-green-400 size-4" />
				Daemon
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1">
			{#if loading}
				<Skeleton class="h-8 w-32" />
				<Skeleton class="h-4 w-20" />
			{:else if data}
				<span class="text-foreground text-2xl font-bold"
					>{formatUptime(data.uptime_secs)}</span
				>
				{#if data.version}
					<span class="text-muted-foreground text-xs"
						>v{data.version}</span
					>
				{/if}
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Network -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<NetworkIcon class="text-blue-400 size-4" />
				Network
			</Card.Title>
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-4 w-full" />
				<Skeleton class="mt-2 h-4 w-3/4" />
			{:else if data}
				<dl class="text-sm">
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Interface</dt>
						<dd class="font-mono font-medium">
							{data.network.lan_iface}
						</dd>
					</div>
					{#if data.network.lan_ipv4}
						<div class="flex justify-between py-0.5">
							<dt class="text-muted-foreground">IPv4</dt>
							<dd class="font-mono text-xs">
								{data.network.lan_ipv4}
							</dd>
						</div>
					{/if}
					{#if data.network.gua}
						<div class="flex justify-between py-0.5">
							<dt class="text-muted-foreground">GUA</dt>
							<dd
								class="max-w-[160px] truncate font-mono text-xs"
							>
								{data.network.gua}
							</dd>
						</div>
					{/if}
					{#if data.network.ula}
						<div class="flex justify-between py-0.5">
							<dt class="text-muted-foreground">ULA</dt>
							<dd
								class="max-w-[160px] truncate font-mono text-xs"
							>
								{data.network.ula}
							</dd>
						</div>
					{/if}
				</dl>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Database -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<HardDriveIcon class="text-indigo-400 size-4" />
				Database
			</Card.Title>
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-4 w-full" />
				<Skeleton class="mt-2 h-4 w-1/2" />
			{:else if data}
				<dl class="text-sm">
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Size</dt>
						<dd class="font-medium">
							{formatBytes(data.db.size_bytes)}
						</dd>
					</div>
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">Last flush</dt>
						<dd class="text-xs">
							{data.db.last_flush_secs_ago}s ago
						</dd>
					</div>
					<div class="flex flex-col py-0.5 gap-0.5">
						<dt class="text-muted-foreground">Path</dt>
						<dd
							class="text-muted-foreground truncate font-mono text-xs"
						>
							{data.db.path}
						</dd>
					</div>
				</dl>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Resources -->
	<Card.Root>
		<Card.Header class="pb-2">
			<Card.Title class="flex items-center gap-2 text-sm font-medium">
				<CpuIcon class="text-orange-400 size-4" />
				Resources
			</Card.Title>
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-4 w-full" />
				<Skeleton class="mt-2 h-4 w-1/2" />
			{:else if data}
				<dl class="text-sm">
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">RSS</dt>
						<dd class="font-medium">
							{formatBytes(
								data.resources.memory_rss_bytes ??
									data.resources.rss_bytes ??
									0,
							)}
						</dd>
					</div>
					<div class="flex justify-between py-0.5">
						<dt class="text-muted-foreground">VMS</dt>
						<dd class="font-medium">
							{formatBytes(
								data.resources.memory_vms_bytes ??
									data.resources.vms_bytes ??
									0,
							)}
						</dd>
					</div>
				</dl>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Services -->
	<Card.Root class="md:col-span-2">
		<Card.Header class="pb-2">
			<Card.Title class="text-sm font-medium">Services</Card.Title>
		</Card.Header>
		<Card.Content class="p-0">
			{#if loading}
				<div class="flex flex-col divide-y divide-border">
					{#each { length: 4 } as _, i (i)}
						<div class="flex items-center gap-3 px-5 py-3">
							<Skeleton class="size-4 rounded-full" />
							<Skeleton class="h-4 w-24" />
							<Skeleton class="ml-auto h-4 w-16" />
						</div>
					{/each}
				</div>
			{:else if serviceList.length === 0}
				<p class="text-muted-foreground px-5 py-6 text-sm">
					No service data available
				</p>
			{:else}
				<div class="divide-border divide-y">
					{#each serviceList as svc (svc.name)}
						{@const Icon = stateIcon(svc.state)}
						<div class="flex items-center gap-3 px-5 py-3">
							<Icon
								class={[
									"size-4 flex-shrink-0",
									stateColor(svc.state),
									svc.state === "starting"
										? "animate-spin"
										: "",
								].join(" ")}
							/>
							<div class="flex flex-1 flex-col">
								<span
									class="text-foreground text-sm font-medium capitalize"
								>
									{svc.name.replace(/_/g, " ")}
								</span>
								<span class="text-muted-foreground text-xs">
									{#if svc.uptime_secs > 0}
										up {formatUptime(svc.uptime_secs)}
									{:else}
										—
									{/if}
								</span>
							</div>
							<div class="flex flex-wrap justify-end gap-2">
								{#each Object.entries(svc.stats) as [k, v] (k)}
									<span class="text-muted-foreground text-xs">
										{k.replace(/_/g, " ")}:
										<span
											class="text-foreground font-medium"
											>{v}</span
										>
									</span>
								{/each}
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>

<!-- Capabilities -->
{#if data}
	<Card.Root>
		<Card.Header>
			<Card.Title class="text-sm font-medium"
				>Server Capabilities</Card.Title
			>
			<Card.Description
				>Compiled feature flags vs. runtime enabled capabilities</Card.Description
			>
		</Card.Header>
		<Card.Content class="flex flex-col gap-4">
			<div>
				<p
					class="text-muted-foreground mb-2 text-xs font-medium uppercase tracking-wide"
				>
					Enabled
				</p>
				<div class="flex flex-wrap gap-1.5">
					{#each data.capabilities.enabled as cap (cap)}
						<Badge variant="default" class="font-mono text-xs"
							>{cap}</Badge
						>
					{/each}
				</div>
			</div>
			<Separator />
			<div>
				<p
					class="text-muted-foreground mb-2 text-xs font-medium uppercase tracking-wide"
				>
					Compiled (not enabled)
				</p>
				<div class="flex flex-wrap gap-1.5">
					{#each data.capabilities.compiled.filter((c) => !data!.capabilities.enabled.includes(c)) as cap (cap)}
						<Badge
							variant="outline"
							class="text-muted-foreground font-mono text-xs"
							>{cap}</Badge
						>
					{/each}
				</div>
			</div>
		</Card.Content>
	</Card.Root>
{/if}
