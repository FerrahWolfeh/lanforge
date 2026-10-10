<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Badge } from "$lib/components/ui/badge";
	import SettingsIcon from "@lucide/svelte/icons/settings";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import SaveIcon from "@lucide/svelte/icons/save";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ServerIcon from "@lucide/svelte/icons/server";
	import { toast } from "svelte-sonner";
	import {
		dnsAdblockStatus,
		dnsAdblockConfigSet,
		dnsCacheFlush,
		exportSystemConfig,
		importSystemConfig,
	} from "$lib/api/client";
	import type { BlockingMode, TimeOfDay } from "$lib/api/types";

	let loading = $state(true);
	let saving = $state(false);
	let flushing = $state(false);

	let blockingMode = $state<BlockingMode>("nxdomain");
	let customIpV4 = $state("");
	let customIpV6 = $state("");
	let refreshTime = $state("03:00");
	let nextUpdate = $state<number | null>(null);

	const MODES: Array<{
		id: BlockingMode;
		title: string;
		description: string;
		badge: string;
	}> = [
		{
			id: "nxdomain",
			title: "NXDOMAIN",
			description: "Responds that the domain does not exist. Prevents client connection retries.",
			badge: "Default",
		},
		{
			id: "null_ip",
			title: "Null IP (0.0.0.0 / ::)",
			description: "Returns 0.0.0.0 for A queries and :: for AAAA queries.",
			badge: "Sinkhole",
		},
		{
			id: "custom_ip",
			title: "Custom IP",
			description: "Returns configured IP addresses hosting a local block page.",
			badge: "Custom",
		},
		{
			id: "refused",
			title: "REFUSED (RCODE 5)",
			description: "Refuses the DNS query with RCODE 5.",
			badge: "RCODE 5",
		},
	];

	async function loadConfig() {
		loading = true;
		try {
			const [status, sysCfg] = await Promise.all([
				dnsAdblockStatus().catch(() => null),
				exportSystemConfig().catch(() => null),
			]);
			if (status) {
				const mode = (status.blocking_mode as string) === "nx_domain" ? "nxdomain" : status.blocking_mode;
				blockingMode = mode ?? "nxdomain";
				customIpV4 = status.blocking_ip_v4 ?? "";
				customIpV6 = status.blocking_ip_v6 ?? "";
				nextUpdate = status.next_update ?? null;
			}
			if (sysCfg?.dns_adblock_config?.refresh_time) {
				const rt = sysCfg.dns_adblock_config.refresh_time;
				if (typeof rt.hour === "number" && typeof rt.minute === "number") {
					refreshTime = `${String(rt.hour).padStart(2, "0")}:${String(rt.minute).padStart(2, "0")}`;
				}
			}
		} catch {
			toast.error("Failed to load adblock configuration");
		} finally {
			loading = false;
		}
	}

	async function handleSave(e: Event) {
		e.preventDefault();
		if (blockingMode === "custom_ip" && !customIpV4.trim()) {
			toast.error("Custom IP mode requires at least an IPv4 address");
			return;
		}

		saving = true;
		try {
			const [hourStr, minuteStr] = refreshTime.split(":");
			const hour = Math.min(23, Math.max(0, parseInt(hourStr || "3", 10)));
			const minute = Math.min(59, Math.max(0, parseInt(minuteStr || "0", 10)));
			const timeOfDay: TimeOfDay = { hour, minute };

			await dnsAdblockConfigSet({
				blocking_mode: blockingMode,
				blocking_ip_v4: customIpV4.trim() || null,
				blocking_ip_v6: customIpV6.trim() || null,
				refresh_time: timeOfDay,
			});
			const sysCfg = await exportSystemConfig().catch(() => null);
			if (sysCfg?.dns_adblock_config) {
				sysCfg.dns_adblock_config.refresh_time = timeOfDay;
				sysCfg.dns_adblock_config.blocking_mode = blockingMode;
				sysCfg.dns_adblock_config.blocking_ip_v4 = customIpV4.trim() || null;
				sysCfg.dns_adblock_config.blocking_ip_v6 = customIpV6.trim() || null;
				await importSystemConfig(sysCfg);
			}
			toast.success("Adblock configuration saved successfully");
			await loadConfig();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save configuration");
		} finally {
			saving = false;
		}
	}

	async function handleFlushCache() {
		flushing = true;
		try {
			await dnsCacheFlush();
			toast.success("Flushed DNS cache and adblock lookup entries");
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to flush DNS cache");
		} finally {
			flushing = false;
		}
	}

	onMount(() => {
		loadConfig();
	});
</script>

<form onsubmit={handleSave} class="space-y-6">
	<!-- Blocking Mode Selection -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<ShieldAlertIcon class="size-4 text-primary" />
					<Card.Title class="text-base font-semibold">
						Blocking & Sinkhole Policy
					</Card.Title>
				</div>
				<Badge variant="outline" class="font-mono text-xs capitalize">
					Active: {blockingMode}
				</Badge>
			</div>
			<Card.Description class="text-xs">
				Determines how Lanforge answers DNS requests when a query matches a blocklist rule.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
			{#each MODES as mode (mode.id)}
				{@const selected = blockingMode === mode.id}
				<button
					type="button"
					onclick={() => (blockingMode = mode.id)}
					class={[
						"flex flex-col text-left p-3.5 rounded-lg border transition-all cursor-pointer",
						selected
							? "border-primary bg-primary/5 ring-1 ring-primary/40 shadow-xs"
							: "border-border/60 bg-card hover:bg-muted/40",
					].join(" ")}
				>
					<div class="flex items-center justify-between gap-2">
						<span class="font-semibold text-xs text-foreground">
							{mode.title}
						</span>
						<Badge
							variant={selected ? "default" : "secondary"}
							class="text-[10px] px-1.5 py-0 font-mono"
						>
							{mode.badge}
						</Badge>
					</div>
					<p class="text-[11px] text-muted-foreground mt-1.5 leading-relaxed">
						{mode.description}
					</p>
				</button>
			{/each}
		</Card.Content>
	</Card.Root>

	<!-- Custom Sinkhole IP Addresses (Conditional) -->
	{#if blockingMode === "custom_ip"}
		<Card.Root>
			<Card.Header class="pb-3 border-b border-border/50">
				<div class="flex items-center gap-2">
					<ServerIcon class="size-4 text-primary" />
					<Card.Title class="text-base font-semibold">
						Custom Sinkhole Server Addresses
					</Card.Title>
				</div>
				<Card.Description class="text-xs">
					Specify the internal LAN addresses serving your custom HTTP block page.
				</Card.Description>
			</Card.Header>

			<Card.Content class="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
				<div class="flex flex-col gap-1.5">
					<Label for="ipv4-sinkhole" class="text-xs font-semibold">IPv4 Sinkhole IP</Label>
					<Input
						id="ipv4-sinkhole"
						placeholder="192.168.1.100"
						bind:value={customIpV4}
						required
						class="font-mono text-xs"
					/>
				</div>

				<div class="flex flex-col gap-1.5">
					<Label for="ipv6-sinkhole" class="text-xs font-semibold">IPv6 Sinkhole IP (Optional)</Label>
					<Input
						id="ipv6-sinkhole"
						placeholder="fd00::100"
						bind:value={customIpV6}
						class="font-mono text-xs"
					/>
				</div>
			</Card.Content>
		</Card.Root>
	{/if}

	<!-- Refresh Scheduling & Maintenance -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center gap-2">
				<ClockIcon class="size-4 text-primary" />
				<Card.Title class="text-base font-semibold">
					Automated Daily Refresh Schedule
				</Card.Title>
			</div>
			<Card.Description class="text-xs">
				Controls the daily wall-clock time when background worker threads check remote blocklists for updates and rebuild the FST database if changed.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
			<div class="flex flex-col gap-1.5">
				<Label for="refresh-time" class="text-xs font-semibold">Daily Update Time (24h)</Label>
				<Input
					id="refresh-time"
					type="time"
					bind:value={refreshTime}
					class="font-mono text-xs w-full max-w-[160px]"
				/>
				<p class="text-[11px] text-muted-foreground">
					Triggered once per day at the specified local time. Unchanged lists skip compilation to preserve flash memory.
				</p>
			</div>

			<div class="flex items-center justify-between p-3 rounded-lg border bg-card/60">
				<div class="flex flex-col gap-0.5">
					<span class="text-xs font-semibold text-foreground">Next Scheduled Run</span>
					<span class="text-[11px] text-muted-foreground font-mono">
						{#if nextUpdate}
							{new Date(nextUpdate * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
						{:else}
							Pending schedule calculation
						{/if}
					</span>
				</div>
				<Badge variant="outline" class="font-mono text-[10px]">
					Daily
				</Badge>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Flush Cache & Maintenance -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<Trash2Icon class="size-4 text-rose-500" />
					<Card.Title class="text-base font-semibold">
						Resolver Cache Maintenance
					</Card.Title>
				</div>
			</div>
			<Card.Description class="text-xs">
				Clear recently cached query answers and negative entries to immediately reflect allowlist or rule changes.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<p class="text-xs text-muted-foreground">
				Flushing will clear the in-memory response cache. The disk-backed FST blocklist will remain intact.
			</p>

			<Button
				type="button"
				variant="outline"
				size="sm"
				onclick={handleFlushCache}
				disabled={flushing}
				class="text-xs h-8 gap-1.5 shrink-0"
			>
				<Trash2Icon class="size-3.5 {flushing ? 'animate-spin' : ''}" />
				Flush DNS Cache
			</Button>
		</Card.Content>
	</Card.Root>

	<!-- Save Action Footer -->
	<div class="flex items-center justify-end gap-3 pt-2">
		<Button
			type="submit"
			size="sm"
			disabled={saving || loading}
			class="gap-1.5 px-5"
		>
			<SaveIcon class="size-3.5" />
			{saving ? "Saving Changes..." : "Save Settings"}
		</Button>
	</div>
</form>
