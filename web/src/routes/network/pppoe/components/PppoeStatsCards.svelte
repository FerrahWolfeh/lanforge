<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import XCircleIcon from "@lucide/svelte/icons/x-circle";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import ServerIcon from "@lucide/svelte/icons/server";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ZapIcon from "@lucide/svelte/icons/zap";

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

<div class="grid gap-3.5 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Session State Card -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Session State</span>
				<Badge
					variant="outline"
					class={[
						"text-[10px] uppercase font-mono px-1.5 py-0",
						status?.state === "connected"
							? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
							: status?.state === "reconnecting" || status?.state === "authenticating"
								? "border-amber-500/30 bg-amber-500/10 text-amber-400"
								: "border-border text-muted-foreground",
					].join(" ")}
				>
					{status?.state ?? "Offline"}
				</Badge>
			</Card.Description>
			<Card.Title class="flex items-center gap-2 pt-0.5">
				{#if status?.state === "connected"}
					<CheckCircleIcon class="size-5 text-emerald-500 shrink-0" />
					<span class="text-base font-bold text-emerald-400">Connected</span>
				{:else if status?.state === "reconnecting"}
					<RefreshCwIcon class="size-5 text-amber-500 shrink-0 animate-spin" />
					<span class="text-base text-amber-400">Reconnecting...</span>
				{:else if status?.state === "authenticating"}
					<RefreshCwIcon class="size-5 text-amber-500 shrink-0 animate-spin" />
					<span class="text-base text-amber-400">Authenticating...</span>
				{:else}
					<XCircleIcon class="size-5 text-muted-foreground shrink-0" />
					<span class="text-base text-muted-foreground font-normal">Offline / Idle</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Uptime</span>
					<span class="font-medium text-foreground">{formatUptime(status?.uptime_secs)}</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Dataplane</span>
					<div>
						{#if (status?.dataplane ?? formDataplane) === "ebpf"}
							<Badge variant="outline" class="border-amber-500/30 bg-amber-500/10 text-amber-400 font-mono text-[10px] px-1 py-0">
								<ZapIcon class="size-2.5 mr-1 text-amber-500" />
								eBPF
							</Badge>
						{:else}
							<Badge variant="secondary" class="font-mono text-[10px] px-1 py-0">
								<CpuIcon class="size-2.5 mr-1 text-blue-400" />
								Kernel
							</Badge>
						{/if}
					</div>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Session ID</span>
					<span class="font-mono text-foreground">
						{status?.session_id ? `0x${status.session_id.toString(16).padStart(4, "0")}` : "—"}
					</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">WAN Port</span>
					<span class="font-mono text-foreground font-medium truncate">{status?.wan_iface ?? formWanIface}</span>
				</div>
			</div>

			{#if status?.last_error}
				<div class="flex items-center gap-1.5 rounded-md bg-destructive/10 px-2 py-1 text-[11px] text-destructive">
					<AlertCircleIcon class="size-3 shrink-0" />
					<span class="truncate">{status.last_error}</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Network IP Configuration Card -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Assigned IP Lease</span>
				<GlobeIcon class="size-4 text-muted-foreground" />
			</Card.Description>
			<Card.Title class="text-base sm:text-lg font-bold font-mono tracking-tight text-foreground truncate">
				{#if status?.local_ip}
					<span class="text-emerald-400">{status.local_ip}</span>
				{:else}
					<span class="text-muted-foreground text-sm font-normal">Waiting for IPCP...</span>
				{/if}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Gateway (Peer IP)</span>
					<span class="font-mono font-medium text-foreground truncate">{status?.peer_ip ?? "—"}</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Negotiated MRU</span>
					<span class="font-mono font-medium text-foreground">{status?.mru ? `${status.mru} bytes` : "—"}</span>
				</div>
			</div>
			<div class="flex flex-col gap-1 border-t pt-1.5">
				<span class="text-[11px] text-muted-foreground">ISP DNS Fallback</span>
				{#if status?.dns_servers && status.dns_servers.length > 0}
					<div class="flex flex-wrap gap-1">
						{#each status.dns_servers as dns}
							<Badge variant="secondary" class="font-mono text-[10px] font-normal px-1 py-0">
								{dns}
							</Badge>
						{/each}
					</div>
				{:else}
					<span class="font-mono text-[11px] text-muted-foreground/80">None provided by ISP</span>
				{/if}
			</div>
		</Card.Content>
	</Card.Root>

	<!-- AC & Remote Details Card -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header class="pb-2 p-3 sm:p-4">
			<Card.Description class="flex items-center justify-between text-xs font-semibold uppercase tracking-wider">
				<span>Access Concentrator</span>
				<ServerIcon class="size-4 text-muted-foreground" />
			</Card.Description>
			<Card.Title class="truncate text-base sm:text-lg font-bold text-foreground" title={status?.ac_name ?? "None"}>
				{status?.ac_name || (status?.state === "connected" ? "ISP Concentrator" : "Searching...")}
			</Card.Title>
		</Card.Header>
		<Card.Content class="flex flex-col gap-2 p-3 sm:p-4 pt-0 text-xs">
			<div class="grid grid-cols-2 gap-x-3 gap-y-1.5 border-t pt-2">
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">AC MAC</span>
					<span class="font-mono font-medium text-foreground truncate">{status?.ac_mac ?? "—"}</span>
				</div>
				<div class="flex flex-col gap-0.5">
					<span class="text-[11px] text-muted-foreground">Auth Method</span>
					<div>
						<Badge variant="outline" class="font-medium text-[10px] px-1.5 py-0">
							{formatAuthMethod(status?.auth ?? config?.auth ?? formAuth)}
						</Badge>
					</div>
				</div>
			</div>
			<div class="flex flex-col gap-0.5 border-t pt-1.5">
				<span class="text-[11px] text-muted-foreground">Service Name</span>
				<span class="font-mono text-[11px] text-foreground truncate">
					{config?.service_name || formServiceName || "Any / Automatic"}
				</span>
			</div>
		</Card.Content>
	</Card.Root>
</div>
