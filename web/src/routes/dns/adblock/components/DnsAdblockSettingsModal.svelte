<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Badge } from "$lib/components/ui/badge";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import SaveIcon from "@lucide/svelte/icons/save";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ServerIcon from "@lucide/svelte/icons/server";
	import SettingsIcon from "@lucide/svelte/icons/settings";
	import { toast } from "svelte-sonner";
	import {
		dnsAdblockStatus,
		dnsAdblockConfigSet,
		dnsCacheFlush,
		exportSystemConfig,
		importSystemConfig,
	} from "$lib/api/client";
	import type { BlockingMode, TimeOfDay } from "$lib/api/types";

	interface Props {
		open?: boolean;
		onUpdated?: () => void;
	}

	let { open = $bindable(false), onUpdated }: Props = $props();

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
			open = false;
			onUpdated?.();
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

	$effect(() => {
		if (open) {
			loadConfig();
		}
	});
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-w-2xl max-h-[90vh] overflow-y-auto">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<SettingsIcon class="size-5 text-primary" />
				Adblock & Sinkhole Settings
			</Dialog.Title>
			<Dialog.Description class="text-xs">
				Configure response modes for blocked domains, custom sinkhole servers, and background refresh schedules.
			</Dialog.Description>
		</Dialog.Header>

		<form onsubmit={handleSave} class="space-y-4 pt-2">
			<!-- Blocking Mode Selection -->
			<div class="space-y-2">
				<div class="flex items-center justify-between">
					<Label class="text-xs font-semibold">Blocking & Sinkhole Policy</Label>
					<Badge variant="outline" class="font-mono text-[10px] capitalize">
						Active: {blockingMode}
					</Badge>
				</div>

				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
					{#each MODES as mode (mode.id)}
						{@const selected = blockingMode === mode.id}
						<button
							type="button"
							onclick={() => (blockingMode = mode.id)}
							class={[
								"flex flex-col text-left p-3 rounded-lg border transition-all cursor-pointer",
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
							<p class="text-[11px] text-muted-foreground mt-1 leading-relaxed">
								{mode.description}
							</p>
						</button>
					{/each}
				</div>
			</div>

			<!-- Custom Sinkhole IP Addresses (Conditional) -->
			{#if blockingMode === "custom_ip"}
				<div class="p-3 rounded-lg border bg-card/60 space-y-3">
					<Label class="text-xs font-semibold flex items-center gap-1.5">
						<ServerIcon class="size-3.5 text-primary" />
						Custom Sinkhole Server Addresses
					</Label>
					<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
						<div class="flex flex-col gap-1">
							<Label for="ipv4-sinkhole-modal" class="text-[11px] text-muted-foreground">IPv4 Address</Label>
							<Input
								id="ipv4-sinkhole-modal"
								placeholder="192.168.1.100"
								bind:value={customIpV4}
								required
								class="font-mono text-xs h-8"
							/>
						</div>
						<div class="flex flex-col gap-1">
							<Label for="ipv6-sinkhole-modal" class="text-[11px] text-muted-foreground">IPv6 Address (Optional)</Label>
							<Input
								id="ipv6-sinkhole-modal"
								placeholder="fd00::100"
								bind:value={customIpV6}
								class="font-mono text-xs h-8"
							/>
						</div>
					</div>
				</div>
			{/if}

			<!-- Refresh Scheduling & Maintenance -->
			<div class="p-3 rounded-lg border bg-card/60 space-y-3">
				<div class="flex items-center justify-between">
					<Label class="text-xs font-semibold flex items-center gap-1.5">
						<ClockIcon class="size-3.5 text-primary" />
						Automated Daily Refresh Schedule
					</Label>
					{#if nextUpdate}
						<span class="text-[10px] text-muted-foreground font-mono">
							Next: {new Date(nextUpdate * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
						</span>
					{/if}
				</div>

				<div class="flex items-center gap-3">
					<Input
						type="time"
						bind:value={refreshTime}
						class="font-mono text-xs w-32 h-8"
					/>
					<span class="text-[11px] text-muted-foreground">
						Daily check for remote blocklist updates and compilation.
					</span>
				</div>
			</div>

			<!-- Cache Flush -->
			<div class="flex items-center justify-between pt-1 text-xs">
				<span class="text-muted-foreground">Clear cached sinkhole answers:</span>
				<Button
					type="button"
					variant="outline"
					size="sm"
					onclick={handleFlushCache}
					disabled={flushing}
					class="text-xs h-7 gap-1.5"
				>
					<Trash2Icon class="size-3 {flushing ? 'animate-spin' : ''}" />
					Flush Cache
				</Button>
			</div>

			<Dialog.Footer class="pt-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					onclick={() => (open = false)}
				>
					Cancel
				</Button>
				<Button
					type="submit"
					size="sm"
					disabled={saving || loading}
					class="gap-1.5"
				>
					<SaveIcon class="size-3.5" />
					{saving ? "Saving..." : "Save Settings"}
				</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
