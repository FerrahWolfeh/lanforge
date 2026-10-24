<script lang="ts">
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ServerIcon from "@lucide/svelte/icons/server";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import StatusBadge from "$lib/components/StatusBadge.svelte";
	import type { PppoeStatusResponse, PppoeDataplane, PppoeAuthMethod, PppoeConfig } from "$lib/api/types";

	let {
		status = null,
		config = null,
		formDataplane = "kernel",
		formWanIface = "eth1",
		formAuth = "chap_md5",
		formServiceName = "",
	}: {
		status?: PppoeStatusResponse | null;
		config?: PppoeConfig | null;
		formDataplane?: PppoeDataplane;
		formWanIface?: string;
		formAuth?: PppoeAuthMethod;
		formServiceName?: string;
	} = $props();

	function formatUptime(seconds?: number | null): string {
		if (status?.state === "connected" && (!seconds || seconds <= 0)) {
			return "< 1m";
		}
		if (!seconds || seconds <= 0) return "Disconnected";
		const d = Math.floor(seconds / 86400);
		const h = Math.floor((seconds % 86400) / 3600);
		const m = Math.floor((seconds % 3600) / 60);
		const s = seconds % 60;
		if (d > 0) return `${d}d ${h}h ${m}m`;
		if (h > 0) return `${h}h ${m}m ${s}s`;
		if (m > 0) return `${m}m ${s}s`;
		return `${s}s`;
	}

	function formatAuthMethod(auth?: string): string {
		switch (auth) {
			case "chap_md5": return "CHAP (MD5)";
			case "pap": return "PAP (Plaintext)";
			case "mschap_v2": return "MS-CHAPv2";
			case "none": return "None";
			default: return auth || "CHAP (MD5)";
		}
	}
</script>

<StatCardGrid cols={3}>
	<!-- Card 1: Session State -->
	<StatCard
		label="Session State"
		popover={{
			title: "PPPoE Session Lifecycle",
			description: "Point-to-Point Protocol over Ethernet session state negotiated with carrier access concentrator.",
		}}
		badge={{
			text: status?.state ? status.state.replace(/_/g, " ") : "Offline",
			variant: status?.state === "connected" ? "online" : status?.state === "reconnecting" || status?.state === "authenticating" || status?.state === "discovering" || status?.state === "waiting_for_carrier" || status?.state === "waiting_for_terminal" ? "starting" : "dormant",
			showDot: true,
			pulse: true,
		}}
	>
		{#snippet valueExtra()}
			<div class="flex items-center gap-2 pt-0.5">
				{#if status?.state === "connected"}
					<CheckCircleIcon class="size-5 text-emerald-500 shrink-0" />
					<span class="text-base font-bold text-emerald-400">Connected</span>
				{:else if status?.state === "reconnecting"}
					<RefreshCwIcon class="size-5 text-amber-500 shrink-0 animate-spin" />
					<span class="text-base text-amber-400 font-bold">Reconnecting...</span>
				{:else if status?.state === "authenticating"}
					<RefreshCwIcon class="size-5 text-amber-500 shrink-0 animate-spin" />
					<span class="text-base text-amber-400 font-bold">Authenticating...</span>
				{:else if status?.state === "discovering"}
					<RadioIcon class="size-5 text-cyan-500 shrink-0 animate-pulse" />
					<span class="text-base text-cyan-400 font-bold">Discovering BNG...</span>
				{:else if status?.state === "waiting_for_carrier"}
					<AlertCircleIcon class="size-5 text-amber-500 shrink-0" />
					<span class="text-base text-amber-400 font-bold">Waiting for Carrier</span>
				{:else if status?.state === "waiting_for_terminal"}
					<RefreshCwIcon class="size-5 text-amber-500 shrink-0 animate-spin" />
					<span class="text-base text-amber-400 font-bold">Waiting for ONT...</span>
				{:else}
					<XCircleIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Offline / Idle</span>
				{/if}
			</div>
		{/snippet}

		{#snippet footer()}
			<StatCardFooterItem label="Uptime" value={formatUptime(status?.uptime_secs)} color={status?.state === "connected" ? "text-emerald-400" : "text-muted-foreground"} />
			<StatCardFooterItem label="Dataplane" value={(status?.dataplane ?? formDataplane) === "ebpf" ? "eBPF Fast-Path" : "Linux Kernel"} color={(status?.dataplane ?? formDataplane) === "ebpf" ? "text-amber-400" : "text-foreground"} />
		{/snippet}
	</StatCard>

	<!-- Card 2: Assigned WAN IP Lease -->
	<StatCard
		label="Assigned IP Lease"
		icon={GlobeIcon}
		color="emerald"
		popover={{
			title: "IPCP Network Layer",
			description: "Public IPv4 address and peer gateway allocated by broadband ISP.",
		}}
		badge={{
			text: status?.local_ip ? "IPCP Active" : "Waiting",
			variant: status?.local_ip ? "online" : "dormant",
		}}
	>
		{#snippet valueExtra()}
			<div class="pt-0.5">
				{#if status?.local_ip}
					<span class="text-lg sm:text-xl font-bold font-mono text-emerald-400 truncate block">
						{status.local_ip}
					</span>
				{:else}
					<span class="text-sm text-muted-foreground font-normal">Waiting for IPCP…</span>
				{/if}
			</div>
		{/snippet}

		{#snippet footer()}
			<StatCardFooterItem label="Gateway Peer" value={status?.peer_ip ?? "—"} />
			<StatCardFooterItem label="Negotiated MRU" value={status?.mru ? `${status.mru} B` : "1492 B"} />
		{/snippet}
	</StatCard>

	<!-- Card 3: Access Concentrator -->
	<StatCard
		label="Access Concentrator"
		icon={ServerIcon}
		color="indigo"
		popover={{
			title: "Carrier Access Concentrator",
			description: "Remote ISP broadband terminal responding to PPPoE discovery (PADI/PADO) packets.",
		}}
		badge={{
			text: formatAuthMethod(status?.auth ?? config?.auth ?? formAuth),
			variant: "indigo",
		}}
	>
		{#snippet valueExtra()}
			<div class="pt-0.5">
				<span class="text-base sm:text-lg font-bold text-foreground truncate block" title={status?.ac_name ?? "None"}>
					{status?.ac_name || (status?.state === "connected" ? "ISP Concentrator" : "Searching…")}
				</span>
			</div>
		{/snippet}

		{#snippet footer()}
			<StatCardFooterItem label="AC MAC" value={status?.ac_mac ?? "—"} />
			<StatCardFooterItem label="Session ID" value={status?.session_id ? `0x${status.session_id.toString(16).padStart(4, "0")}` : "—"} />
		{/snippet}
	</StatCard>
</StatCardGrid>
