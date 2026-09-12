<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import * as Select from "$lib/components/ui/select";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
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
	import type { BlockingMode } from "$lib/api/types";

	let loading = $state(true);
	let saving = $state(false);
	let flushing = $state(false);

	let blockingMode = $state<BlockingMode>("nxdomain");
	let customIpV4 = $state("");
	let customIpV6 = $state("");
	let refreshHours = $state("12");
	let refreshAtNight = $state(true);

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
			}
			if (sysCfg?.dns_adblock_config) {
				refreshHours = String(sysCfg.dns_adblock_config.refresh_hours ?? 12);
				refreshAtNight = sysCfg.dns_adblock_config.refresh_at_night ?? true;
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
			await dnsAdblockConfigSet({
				blocking_mode: blockingMode,
				blocking_ip_v4: customIpV4.trim() || null,
				blocking_ip_v6: customIpV6.trim() || null,
			});
			const sysCfg = await exportSystemConfig().catch(() => null);
			if (sysCfg?.dns_adblock_config) {
				sysCfg.dns_adblock_config.refresh_hours = Number(refreshHours) || 12;
				sysCfg.dns_adblock_config.refresh_at_night = refreshAtNight;
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
					Automated Refresh Schedule
				</Card.Title>
			</div>
			<Card.Description class="text-xs">
				Controls how often background worker threads download remote blocklist updates and rebuild the FST database.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
			<div class="flex flex-col gap-1.5">
				<Label for="refresh-interval" class="text-xs font-semibold">Update Interval</Label>
				<Select.Root
					type="single"
					value={refreshHours}
					onValueChange={(val) => {
						if (val) refreshHours = val;
					}}
				>
					<Select.Trigger class="w-full text-xs">
						Every {refreshHours} hours
					</Select.Trigger>
					<Select.Content>
						<Select.Item value="6" class="text-xs">Every 6 hours</Select.Item>
						<Select.Item value="12" class="text-xs">Every 12 hours (Default)</Select.Item>
						<Select.Item value="24" class="text-xs">Every 24 hours (Daily)</Select.Item>
						<Select.Item value="48" class="text-xs">Every 48 hours</Select.Item>
						<Select.Item value="168" class="text-xs">Once a week</Select.Item>
					</Select.Content>
				</Select.Root>
				<p class="text-[11px] text-muted-foreground">
					Hashes are compared before rebuilding to avoid unnecessary disk I/O.
				</p>
			</div>

			<div class="flex items-center justify-between p-3 rounded-lg border bg-card/60">
				<div class="flex flex-col gap-0.5">
					<span class="text-xs font-semibold text-foreground">Prefer Nighttime Updates</span>
					<span class="text-[11px] text-muted-foreground">
						Schedules compilation at 03:00 local time to avoid latency spikes during peak use.
					</span>
				</div>
				<Switch bind:checked={refreshAtNight} />
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
