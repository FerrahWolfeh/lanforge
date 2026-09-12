<script lang="ts">
	import { Badge } from "$lib/components/ui/badge";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import ClockIcon from "@lucide/svelte/icons/clock";
</script>

<div class="flex flex-col gap-2 pt-1">
	<!-- Kernel Netlink -->
	<div class="p-2.5 rounded-lg border border-border/60 bg-muted/20 flex flex-col gap-1">
		<div class="flex items-center justify-between">
			<span class="text-xs font-semibold text-foreground flex items-center gap-1.5">
				<CpuIcon class="size-3.5 text-emerald-400" />
				Netlink RTM_GETNEIGH
			</span>
			<Badge variant="outline" class="text-[9px] font-mono text-emerald-400">Zero-Polling</Badge>
		</div>
		<p class="text-[11px] text-muted-foreground leading-relaxed">
			Subscribes directly to kernel ARP/NDP event streams. Updates state immediately upon L2/L3 packet arrival without scanning loops.
		</p>
	</div>

	<!-- Active Probing -->
	<div class="p-2.5 rounded-lg border border-border/60 bg-muted/20 flex flex-col gap-1">
		<div class="flex items-center justify-between">
			<span class="text-xs font-semibold text-foreground flex items-center gap-1.5">
				<ZapIcon class="size-3.5 text-amber-400" />
				Ping Sweeps
			</span>
			<Badge variant="outline" class="text-[9px] font-mono text-amber-400">Paced 10ms</Badge>
		</div>
		<p class="text-[11px] text-muted-foreground leading-relaxed">
			Batched ICMP sweeps periodically verify endpoint reachability while respecting hardware sleep states and low-power SBCs.
		</p>
	</div>

	<!-- Stale Expiry -->
	<div class="p-2.5 rounded-lg border border-border/60 bg-muted/20 flex flex-col gap-1">
		<div class="flex items-center justify-between">
			<span class="text-xs font-semibold text-foreground flex items-center gap-1.5">
				<ClockIcon class="size-3.5 text-sky-400" />
				Stale Expiration
			</span>
			<Badge variant="outline" class="text-[9px] font-mono text-sky-400">1 Hour</Badge>
		</div>
		<p class="text-[11px] text-muted-foreground leading-relaxed">
			Neighbors inactive for longer than 3600 seconds transition to offline, preventing zombie entries in DNS reverse lookups.
		</p>
	</div>
</div>
