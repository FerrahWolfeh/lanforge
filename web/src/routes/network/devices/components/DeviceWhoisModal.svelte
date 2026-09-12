<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import MonitorIcon from "@lucide/svelte/icons/monitor";
	import type { DeviceEntry } from "$lib/api/types";

	let {
		open = $bindable(false),
		device = null,
		history = [],
		loading = false,
	}: {
		open?: boolean;
		device?: DeviceEntry | null;
		history?: any[];
		loading?: boolean;
	} = $props();

	function formatLastSeen(ts: string | number | undefined): string {
		if (!ts) return "—";
		let ms = typeof ts === "string" ? Date.parse(ts) : ts;
		if (isNaN(ms) || ms === 0) return "Never";
		if (ms < 10000000000) ms *= 1000;
		const secsAgo = Math.floor((Date.now() - ms) / 1000);
		if (secsAgo < 0 || secsAgo < 10) return "Just now";
		if (secsAgo < 60) return `${secsAgo}s ago`;
		const minsAgo = Math.floor(secsAgo / 60);
		if (minsAgo < 60) return `${minsAgo}m ago`;
		const hoursAgo = Math.floor(minsAgo / 60);
		if (hoursAgo < 24) return `${hoursAgo}h ago`;
		return `${Math.floor(hoursAgo / 24)}d ago`;
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="w-[95vw] sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<MonitorIcon class="size-5 text-emerald-400" />
				<span>Device Details</span>
			</Dialog.Title>
		</Dialog.Header>

		{#if loading}
			<div class="flex flex-col gap-3 py-4">
				<Skeleton class="h-4 w-full" />
				<Skeleton class="h-4 w-3/4" />
				<Skeleton class="h-4 w-5/6" />
			</div>
		{:else if device}
			<div class="flex flex-col gap-3 text-xs py-2">
				<div class="flex justify-between items-center border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">Hostname</span>
					<span class="font-semibold text-foreground">{device.hostname || "Unassigned"}</span>
				</div>
				<div class="flex justify-between items-center border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">MAC Address</span>
					<span class="font-mono text-foreground">{device.mac}</span>
				</div>
				<div class="flex justify-between items-center border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">IPv4 Address</span>
					<span class="font-mono text-emerald-400">
						{device.display_v4 || device.v4?.ip || "—"}
					</span>
				</div>
				<div class="flex justify-between items-center border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">IPv6 Address</span>
					<span class="font-mono text-sky-400 truncate max-w-[200px]">
						{device.display_v6 || device.v6?.ip || "—"}
					</span>
				</div>
				{#if device.duid}
					<div class="flex justify-between items-center border-b border-border/50 pb-2">
						<span class="text-muted-foreground font-medium">DHCPv6 DUID</span>
						<span class="font-mono text-foreground truncate max-w-[200px]">
							{device.duid}
						</span>
					</div>
				{/if}
				<div class="flex justify-between items-center border-b border-border/50 pb-2">
					<span class="text-muted-foreground font-medium">Discovery Origin</span>
					<Badge variant="outline">{device.origin || "Dynamic"}</Badge>
				</div>
				<div class="flex justify-between items-center">
					<span class="text-muted-foreground font-medium">Last Reachable</span>
					<span>{formatLastSeen(device.last_seen)}</span>
				</div>

				{#if history.length > 0}
					<div class="flex flex-col gap-2 mt-2 pt-2 border-t border-border/60">
						<span class="text-muted-foreground font-medium uppercase text-[10px] tracking-wider">
							Lease History
						</span>
						<div class="flex flex-col gap-1 max-h-32 overflow-auto font-mono text-[11px]">
							{#each history as h (h.ts || h.ip)}
								<div class="flex justify-between text-muted-foreground">
									<span>{h.ip}</span>
									<span>{formatLastSeen(h.ts || h.expires)}</span>
								</div>
							{/each}
						</div>
					</div>
				{/if}
			</div>
		{/if}
	</Dialog.Content>
</Dialog.Root>
