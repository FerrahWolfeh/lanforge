<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import PlayIcon from "@lucide/svelte/icons/play";
	import SquareIcon from "@lucide/svelte/icons/square";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import { toast } from "svelte-sonner";
	import { controlService } from "$lib/api/client";
	import type { ServiceBanner } from "$lib/api/types";

	let {
		banners = [],
		onReload = async () => {},
	}: {
		banners?: ServiceBanner[];
		onReload?: () => Promise<void>;
	} = $props();

	let busyService = $state<string | null>(null);

	const monitorService = $derived(
		banners.find((b) => b.id?.toLowerCase() === "monitor" || b.name?.toLowerCase().includes("discovery")),
	);

	const mdnsService = $derived(
		banners.find((b) => b.id?.toLowerCase() === "mdns" || b.name?.toLowerCase().includes("mdns")),
	);

	async function handleControl(serviceId: string, action: "start" | "stop" | "restart") {
		busyService = `${serviceId}-${action}`;
		try {
			await controlService(serviceId, action);
			toast.success(`Sent ${action} signal to ${serviceId}`);
			await onReload();
		} catch (err: any) {
			toast.error(err?.message || `Failed to ${action} service ${serviceId}`);
		} finally {
			busyService = null;
		}
	}
</script>

<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
	<!-- Neighbor Monitor Service -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<RadioIcon class="size-4 text-emerald-400" />
					<Card.Title class="text-sm font-semibold">
						Neighbor Monitor (ARP & NDP)
					</Card.Title>
				</div>
				<Badge
					variant={monitorService?.state === "active" ? "default" : "secondary"}
					class={[
						"text-[10px] uppercase font-mono px-2 py-0.5",
						monitorService?.state === "active"
							? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
							: "text-muted-foreground",
					].join(" ")}
				>
					{monitorService?.state || "Offline"}
				</Badge>
			</div>
			<Card.Description class="text-xs">
				Listens to Netlink kernel neighbor tables for active IPv4 ARP and IPv6 NDP solicitations.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-3 sm:p-4 flex flex-col gap-3">
			<div class="flex justify-between items-center text-xs">
				<span class="text-muted-foreground">Socket / Interface:</span>
				<span class="font-mono text-foreground">Linux Netlink RTM_GETNEIGH</span>
			</div>
			<div class="flex justify-between items-center text-xs">
				<span class="text-muted-foreground">Service ID:</span>
				<span class="font-mono text-muted-foreground">{monitorService?.id || "monitor"}</span>
			</div>

			<!-- Service Controls -->
			<div class="flex items-center justify-end gap-1.5 pt-2 border-t border-border/40">
				<Button
					variant="outline"
					size="sm"
					class="h-7 text-[11px] gap-1 px-2.5"
					onclick={() => handleControl(monitorService?.id || "monitor", "start")}
					disabled={busyService !== null || monitorService?.state === "active"}
				>
					<PlayIcon class="size-3 text-emerald-400" />
					Start
				</Button>
				<Button
					variant="outline"
					size="sm"
					class="h-7 text-[11px] gap-1 px-2.5 text-rose-400 hover:text-rose-300"
					onclick={() => handleControl(monitorService?.id || "monitor", "stop")}
					disabled={busyService !== null || monitorService?.state !== "active"}
				>
					<SquareIcon class="size-3" />
					Stop
				</Button>
				<Button
					variant="outline"
					size="sm"
					class="h-7 text-[11px] gap-1 px-2.5"
					onclick={() => handleControl(monitorService?.id || "monitor", "restart")}
					disabled={busyService !== null}
				>
					<RotateCcwIcon class="size-3 {busyService === (monitorService?.id || 'monitor') + '-restart' ? 'animate-spin' : ''}" />
					Restart
				</Button>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- mDNS Prober Service -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<WifiIcon class="size-4 text-sky-400" />
					<Card.Title class="text-sm font-semibold">
						mDNS Hostname Prober
					</Card.Title>
				</div>
				<Badge
					variant={mdnsService?.state === "active" ? "default" : "secondary"}
					class={[
						"text-[10px] uppercase font-mono px-2 py-0.5",
						mdnsService?.state === "active"
							? "bg-sky-500/20 text-sky-400 border-sky-500/30"
							: "text-muted-foreground",
					].join(" ")}
				>
					{mdnsService?.state || "Offline"}
				</Badge>
			</div>
			<Card.Description class="text-xs">
				Probes multicast 224.0.0.251 / ff02::fb on UDP 5353 to resolve hostnames for discovered IP endpoints.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-3 sm:p-4 flex flex-col gap-3">
			<div class="flex justify-between items-center text-xs">
				<span class="text-muted-foreground">Multicast Group:</span>
				<span class="font-mono text-foreground">224.0.0.251:5353 / [ff02::fb]:5353</span>
			</div>
			<div class="flex justify-between items-center text-xs">
				<span class="text-muted-foreground">Service ID:</span>
				<span class="font-mono text-muted-foreground">{mdnsService?.id || "mdns"}</span>
			</div>

			<!-- Service Controls -->
			<div class="flex items-center justify-end gap-1.5 pt-2 border-t border-border/40">
				<Button
					variant="outline"
					size="sm"
					class="h-7 text-[11px] gap-1 px-2.5"
					onclick={() => handleControl(mdnsService?.id || "mdns", "start")}
					disabled={busyService !== null || mdnsService?.state === "active"}
				>
					<PlayIcon class="size-3 text-emerald-400" />
					Start
				</Button>
				<Button
					variant="outline"
					size="sm"
					class="h-7 text-[11px] gap-1 px-2.5 text-rose-400 hover:text-rose-300"
					onclick={() => handleControl(mdnsService?.id || "mdns", "stop")}
					disabled={busyService !== null || mdnsService?.state !== "active"}
				>
					<SquareIcon class="size-3" />
					Stop
				</Button>
				<Button
					variant="outline"
					size="sm"
					class="h-7 text-[11px] gap-1 px-2.5"
					onclick={() => handleControl(mdnsService?.id || "mdns", "restart")}
					disabled={busyService !== null}
				>
					<RotateCcwIcon class="size-3 {busyService === (mdnsService?.id || 'mdns') + '-restart' ? 'animate-spin' : ''}" />
					Restart
				</Button>
			</div>
		</Card.Content>
	</Card.Root>
</div>
