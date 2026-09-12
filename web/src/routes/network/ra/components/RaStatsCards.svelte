<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import type { RaStatusResponse } from "$lib/api/types";

	let {
		status = null,
	}: {
		status?: RaStatusResponse | null;
	} = $props();

	function formatSeconds(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "Never";
		if (sec < 60) return `${sec}s ago`;
		if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s ago`;
		const h = Math.floor(sec / 3600);
		const m = Math.floor((sec % 3600) / 60);
		return `${h}h ${m}m ago`;
	}

	function formatCountdown(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "—";
		if (sec === 0) return "Imminent";
		if (sec < 60) return `in ${sec}s`;
		const m = Math.floor(sec / 60);
		const s = sec % 60;
		return `in ${m}m ${s}s`;
	}

	function formatUptime(sec: number | null | undefined): string {
		if (sec === null || sec === undefined) return "—";
		const days = Math.floor(sec / 86400);
		const hours = Math.floor((sec % 86400) / 3600);
		const minutes = Math.floor((sec % 3600) / 60);
		const seconds = sec % 60;
		if (days > 0) return `${days}d ${hours}h ${minutes}m`;
		if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
		if (minutes > 0) return `${minutes}m ${seconds}s`;
		return `${seconds}s`;
	}
</script>

<div class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-3 sm:gap-4">
	<!-- Card 1: Operational Interface -->
	<Card.Root>
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Interface</span>
				<NetworkIcon class="size-4 text-muted-foreground" />
			</Card.Description>
			<Card.Title class="text-base font-bold font-mono">
				{status?.interface ?? "Not bound"}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1.5 text-xs text-muted-foreground pt-0 p-3 sm:p-4">
			<div class="flex justify-between items-center">
				<span class="text-[11px]">Service State:</span>
				<div class="flex items-center gap-1.5">
					{#if status?.enabled}
						<span class="size-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
						<span class="font-medium text-emerald-600 dark:text-emerald-400">Announcing</span>
					{:else}
						<span class="size-1.5 rounded-full bg-muted-foreground/40"></span>
						<span class="font-medium text-muted-foreground">Idle</span>
					{/if}
				</div>
			</div>
			<div class="flex flex-col gap-0.5 border-t pt-1.5">
				<span class="text-[10px] text-muted-foreground">Link-Local:</span>
				<span class="font-mono text-[11px] text-foreground font-medium select-all truncate" title={status?.link_local ?? "—"}>
					{status?.link_local ?? "—"}
				</span>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Card 2: Prefixes State -->
	<Card.Root>
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Prefix Subnets</span>
				<GlobeIcon class="size-4 text-muted-foreground" />
			</Card.Description>
			<Card.Title class="text-base font-bold font-mono">
				{(status?.prefixes ?? []).length} Announced
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1.5 text-xs text-muted-foreground pt-0 p-3 sm:p-4">
			<div class="flex justify-between items-center">
				<span class="text-[11px]">GUA Delegated:</span>
				<span class="font-mono text-[11px] text-foreground font-medium select-all truncate max-w-[160px]" title={status?.active_gua_prefix ?? "—"}>
					{status?.active_gua_prefix ?? "None"}
				</span>
			</div>
			<div class="flex justify-between items-center border-t pt-1.5">
				<span class="text-[11px]">Active ULA:</span>
				<span class="font-mono text-[11px] text-foreground font-medium select-all truncate max-w-[160px]" title={status?.active_ula_prefix ?? "—"}>
					{status?.active_ula_prefix ?? "None"}
				</span>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Card 3: Packet Telemetry -->
	<Card.Root>
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Packet Telemetry</span>
				<ActivityIcon class="size-4 text-muted-foreground" />
			</Card.Description>
			<Card.Title class="text-base font-bold font-mono flex items-center gap-2">
				<span>{(status?.sent_multicast_ras ?? 0) + (status?.sent_unicast_ras ?? 0)}</span>
				<span class="text-xs font-normal text-muted-foreground">Total RAs</span>
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1 text-xs text-muted-foreground pt-0 p-3 sm:p-4">
			<div class="flex justify-between items-center">
				<span>Multicast / Unicast:</span>
				<span class="font-mono font-medium text-foreground">
					{status?.sent_multicast_ras ?? 0} / {status?.sent_unicast_ras ?? 0}
				</span>
			</div>
			<div class="flex justify-between items-center">
				<span>RS Solicitations:</span>
				<span class="font-mono font-medium text-foreground">
					{status?.received_solicitations ?? 0}
					{#if (status?.ignored_solicitations ?? 0) > 0}
						<span class="text-amber-500 font-normal">({status?.ignored_solicitations} drop)</span>
					{/if}
				</span>
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Card 4: Timing & Schedule -->
	<Card.Root>
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Convergence</span>
				<ClockIcon class="size-4 text-muted-foreground" />
			</Card.Description>
			<Card.Title class="text-base font-bold flex items-center gap-2">
				<span class="text-primary font-mono">{formatCountdown(status?.next_ra_in_secs)}</span>
				<span class="text-xs font-normal text-muted-foreground">Next RA</span>
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-1 text-xs text-muted-foreground pt-0 p-3 sm:p-4">
			<div class="flex justify-between items-center">
				<span>Last Sent / Recv:</span>
				<span class="text-foreground text-[11px] truncate">
					{formatSeconds(status?.last_ra_sent_secs_ago)} / {formatSeconds(status?.last_rs_received_secs_ago)}
				</span>
			</div>
			<div class="flex justify-between items-center">
				<span>Service Uptime:</span>
				<span class="text-foreground">{formatUptime(status?.uptime_secs)}</span>
			</div>
		</Card.Content>
	</Card.Root>
</div>
