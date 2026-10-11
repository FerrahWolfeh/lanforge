<script lang="ts">
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import LayoutDashboardIcon from "@lucide/svelte/icons/layout-dashboard";
	import ListIcon from "@lucide/svelte/icons/list";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import BanIcon from "@lucide/svelte/icons/ban";
	import SettingsIcon from "@lucide/svelte/icons/settings";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PauseIcon from "@lucide/svelte/icons/pause";
	import PlayIcon from "@lucide/svelte/icons/play";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Switch } from "$lib/components/ui/switch";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import { createPolling } from "$lib/utils/polling";
	import NavTabs, { type NavTabItem } from "$lib/components/NavTabs.svelte";
	import PageHeader from "$lib/components/PageHeader.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";
	import HelpPopover from "$lib/components/HelpPopover.svelte";
	import DnsAdblockSettingsModal from "./components/DnsAdblockSettingsModal.svelte";
	import {
		dnsAdblockStatus,
		dnsAdblockSet,
		dnsAdblockReload,
	} from "$lib/api/client";
	import type { DnsAdblockStatusResponse } from "$lib/api/types";

	let { children } = $props();

	let status = $state<DnsAdblockStatusResponse | null>(null);
	let loadingStatus = $state(true);
	let reloadingLists = $state(false);
	let settingsOpen = $state(false);

	const tabs: NavTabItem[] = [
		{ label: "Overview", href: "/dns/adblock", icon: LayoutDashboardIcon },
		{ label: "Blocklists", href: "/dns/adblock/lists", icon: ListIcon },
		{ label: "Filtering Rules", href: "/dns/adblock/rules", icon: SlidersIcon },
	];

	async function fetchStatus() {
		try {
			const res = await dnsAdblockStatus();
			if (res) status = res;
		} catch {
			// Silent fallback when daemon isn't ready
		} finally {
			loadingStatus = false;
		}
	}

	async function toggleEnabled(newVal: boolean) {
		try {
			await dnsAdblockSet(newVal);
			toast.success(
				newVal
					? "Adblock domain filtering enabled"
					: "Adblock domain filtering disabled",
			);
			await fetchStatus();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to toggle adblock status");
		}
	}

	async function pauseFor(seconds: number) {
		try {
			await dnsAdblockSet(false, seconds);
			const mins = Math.round(seconds / 60);
			const label = seconds < 60 ? `${seconds}s` : `${mins}m`;
			toast.info(`Adblock filtering paused for ${label}`);
			await fetchStatus();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to pause adblock");
		}
	}

	async function handleReloadLists() {
		reloadingLists = true;
		try {
			await dnsAdblockReload();
			toast.success("Triggered background blocklist compilation & reload");
			setTimeout(fetchStatus, 1500);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to reload blocklists");
		} finally {
			setTimeout(() => {
				reloadingLists = false;
			}, 1000);
		}
	}

	function formatRemaining(secs?: number | null): string {
		if (!secs || secs <= 0) return "";
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		if (m > 0) return `${m}m ${s}s`;
		return `${s}s`;
	}

	onMount(() => {
		fetchStatus();
		const stopPolling = createPolling(fetchStatus, 5000);
		return () => {
			stopPolling();
		};
	});
</script>

<svelte:head>
	<title>Adblock & Domain Filtering — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Adblock Header Banner -->
	<PageHeader
		title="Adblock & Domain Filtering"
		description="Zero-copy FST sinkhole blocking ads, trackers, and telemetry at sub-microsecond wire latency."
		icon={ShieldIcon}
		class="border-b pb-5"
	>
		{#snippet badge()}
			{#if status}
				{#if status.enabled}
					<StatusBadge
						variant="online"
						showDot={true}
						pulse={true}
						text="Active"
					/>
				{:else if status.remaining_secs && status.remaining_secs > 0}
					<StatusBadge
						variant="warning"
						text={`Paused (${formatRemaining(status.remaining_secs)})`}
					/>
				{:else}
					<StatusBadge
						variant="error"
						text="Disabled"
					/>
				{/if}
			{/if}
			<HelpPopover
				title="Zero-Copy Reversed-FST Filtering Architecture"
				description="High-performance domain sinkhole evaluation (~0.2µs wire latency) across three operational tiers."
				contentClass="w-80 sm:w-[460px]"
			>
				{#snippet children()}
					<div class="flex flex-col gap-2.5 text-xs text-muted-foreground">
						<div class="flex flex-col gap-0.5 border-l-2 border-emerald-500/80 pl-2.5">
							<span class="font-semibold text-foreground flex items-center gap-1.5">
								<span class="size-1.5 rounded-full bg-emerald-500"></span>
								Tier 1: In-Memory Overrides & Exceptions
							</span>
							<span>User custom rules and <code class="text-primary font-mono font-medium">@@</code> exceptions evaluated in-memory with priority override and <code class="text-amber-500 font-mono font-medium">$important</code> handling.</span>
						</div>
						<div class="flex flex-col gap-0.5 border-l-2 border-sky-500/80 pl-2.5">
							<span class="font-semibold text-foreground flex items-center gap-1.5">
								<span class="size-1.5 rounded-full bg-sky-500"></span>
								Tier 2: Zero-Copy Mmap Reversed FST
							</span>
							<span>Finite State Transducer on disk (<code class="text-foreground font-mono">blocklist.fst</code>). Traverses reversed labels (<code class="text-foreground font-mono">com.doubleclick</code>) for deterministic suffix & exact matching in ~0.2µs with zero heap bloat.</span>
						</div>
						<div class="flex flex-col gap-0.5 border-l-2 border-purple-500/80 pl-2.5">
							<span class="font-semibold text-foreground flex items-center gap-1.5">
								<span class="size-1.5 rounded-full bg-purple-500"></span>
								Tier 3: Incremental HTTP Manifest Cache
							</span>
							<span>Per-source ETag & Last-Modified conditional downloads. Merges sorted lists via streaming multi-way k-merge, skipping unchanged sources entirely.</span>
						</div>
					</div>
				{/snippet}
			</HelpPopover>
		{/snippet}

		{#snippet actions()}
			{#if status}
				<!-- Pause Dropdown Menu -->
				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Button
								variant="outline"
								size="sm"
								{...props}
								class="gap-2 text-xs h-8"
							>
								{#if status?.enabled}
									<PauseIcon class="size-3.5 text-amber-500" />
									Pause
								{:else}
									<PlayIcon class="size-3.5 text-emerald-500" />
									Resume
								{/if}
								<ChevronDownIcon class="size-3 opacity-60" />
							</Button>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="end" class="w-48 text-xs">
						<DropdownMenu.Group>
							<DropdownMenu.GroupHeading
								>Temporary Pause</DropdownMenu.GroupHeading
							>
							<DropdownMenu.Item onclick={() => pauseFor(30)}>
								For 30 seconds
							</DropdownMenu.Item>
							<DropdownMenu.Item onclick={() => pauseFor(300)}>
								For 5 minutes
							</DropdownMenu.Item>
							<DropdownMenu.Item onclick={() => pauseFor(900)}>
								For 15 minutes
							</DropdownMenu.Item>
							<DropdownMenu.Item onclick={() => pauseFor(3600)}>
								For 1 hour
							</DropdownMenu.Item>
						</DropdownMenu.Group>
						<DropdownMenu.Separator />
						<DropdownMenu.Item
							onclick={() => toggleEnabled(!status?.enabled)}
							class={status?.enabled
								? "text-rose-500 font-medium"
								: "text-emerald-500 font-medium"}
						>
							{#if status?.enabled}
								Disable Indefinitely
							{:else}
								Re-enable Filtering Now
							{/if}
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>

				<!-- List Update Button -->
				<Button
					variant="outline"
					size="sm"
					onclick={handleReloadLists}
					disabled={reloadingLists}
					class="gap-1.5 text-xs h-8"
					title="Trigger background download & compilation of all blocklists"
				>
					<RefreshCwIcon
						class="size-3.5 {reloadingLists ? 'animate-spin text-primary' : ''}"
					/>
					Update Lists
				</Button>

				<!-- Settings Dialog Trigger -->
				<Button
					variant="outline"
					size="sm"
					onclick={() => (settingsOpen = true)}
					class="gap-1.5 text-xs h-8"
					title="Configure sinkhole policy, custom IPs, and automated refresh schedule"
				>
					<SettingsIcon class="size-3.5" />
					Settings
				</Button>

				<!-- Master Toggle Switch -->
				<div
					class="flex items-center gap-2 pl-2 border-l border-border/60"
				>
					<Switch
						checked={status.enabled}
						onCheckedChange={toggleEnabled}
						aria-label="Toggle Adblock Filtering"
					/>
				</div>
			{/if}
		{/snippet}
	</PageHeader>

	<!-- Navigation Tabs -->
	<NavTabs {tabs} ariaLabel="Adblock section navigation" />

	<!-- Page Content -->
	{@render children()}
</div>

<DnsAdblockSettingsModal
	bind:open={settingsOpen}
	onUpdated={fetchStatus}
/>
