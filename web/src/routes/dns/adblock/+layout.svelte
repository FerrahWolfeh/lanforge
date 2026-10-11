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
	<div
		class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between border-b pb-5"
	>
		<div>
			<div class="flex flex-wrap items-center gap-3">
				<div
					class="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20 shrink-0"
				>
					<ShieldIcon class="h-6 w-6" />
				</div>
				<div>
					<div class="flex items-center gap-2.5">
						<h1 class="text-2xl font-bold tracking-tight">
							Adblock & Domain Filtering
						</h1>
						{#if status}
							{#if status.enabled}
								<Badge
									variant="outline"
									class="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 gap-1.5 font-mono text-xs px-2.5 py-0.5"
								>
									<span
										class="size-1.5 rounded-full bg-emerald-500 animate-pulse"
									></span>
									Active
								</Badge>
							{:else if status.remaining_secs && status.remaining_secs > 0}
								<Badge
									variant="outline"
									class="bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20 gap-1.5 font-mono text-xs px-2.5 py-0.5"
								>
									<ClockIcon class="size-3" />
									Paused ({formatRemaining(status.remaining_secs)})
								</Badge>
							{:else}
								<Badge
									variant="outline"
									class="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20 gap-1.5 font-mono text-xs px-2.5 py-0.5"
								>
									<BanIcon class="size-3" />
									Disabled
								</Badge>
							{/if}
						{/if}
					</div>
					<p class="text-sm text-muted-foreground mt-0.5">
						Zero-copy FST sinkhole blocking ads, trackers, and telemetry
						at sub-microsecond wire latency.
					</p>
				</div>
			</div>
		</div>

		<!-- Global Control Action Bar -->
		<div class="flex flex-wrap items-center gap-3">
			{#if status}
				<!-- Pause Dropdown Menu -->
				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Button
								variant="outline"
								size="sm"
								{...props}
								class="gap-2 text-xs"
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
					class="gap-2 text-xs"
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
					class="gap-1.5 text-xs"
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
		</div>
	</div>

	<!-- Navigation Tabs -->
	<NavTabs {tabs} ariaLabel="Adblock section navigation" />

	<!-- Page Content -->
	{@render children()}
</div>

<DnsAdblockSettingsModal
	bind:open={settingsOpen}
	onUpdated={fetchStatus}
/>
