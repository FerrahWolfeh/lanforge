<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import PlayIcon from "@lucide/svelte/icons/play";
	import SquareIcon from "@lucide/svelte/icons/square";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import FolderIcon from "@lucide/svelte/icons/folder";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";

	let {
		loading = false,
		isServiceActive = false,
		serviceState = "inactive",
		enabled = false,
		listenAddr = "0.0.0.0:69",
		rootDir = "/var/lib/lanforge/tftp",
		serviceActionLoading = null,
		onServiceControl
	}: {
		loading: boolean;
		isServiceActive: boolean;
		serviceState: string;
		enabled: boolean;
		listenAddr: string;
		rootDir: string;
		serviceActionLoading: string | null;
		onServiceControl: (action: "Start" | "Stop" | "Restart") => void;
	} = $props();
</script>

<StatCardGrid cols={3}>
	<!-- Card 1: Service Lifecycle -->
	<StatCard
		label="Service Lifecycle"
		value={serviceState ? serviceState.charAt(0).toUpperCase() + serviceState.slice(1) : "Inactive"}
		icon={HardDriveDownloadIcon}
		color={isServiceActive ? "emerald" : "zinc"}
		badge={{
			text: enabled ? "Enabled" : "Disabled",
			variant: enabled ? "online" : "dormant",
			showDot: true
		}}
		subtext={enabled ? "Enabled in system configuration" : "Disabled in configuration"}
		{loading}
	>
		{#snippet actions()}
			<div class="flex items-center gap-1.5 pt-1">
				{#if isServiceActive}
					<Button
						variant="outline"
						size="sm"
						class="h-7 px-2.5 text-xs"
						onclick={() => onServiceControl("Restart")}
						disabled={serviceActionLoading !== null}
						title="Restart TFTP Server"
					>
						<RotateCwIcon class={serviceActionLoading === "Restart" ? "animate-spin size-3 mr-1.5" : "size-3 mr-1.5"} />
						Restart
					</Button>
					<Button
						variant="outline"
						size="sm"
						class="h-7 px-2.5 text-xs text-rose-500 hover:text-rose-400 border-rose-500/20 hover:bg-rose-500/10"
						onclick={() => onServiceControl("Stop")}
						disabled={serviceActionLoading !== null}
						title="Stop TFTP Server"
					>
						<SquareIcon class="size-3 fill-current mr-1.5" />
						Stop
					</Button>
				{:else}
					<Button
						variant="outline"
						size="sm"
						class="h-7 px-2.5 text-xs text-emerald-500 hover:text-emerald-400 border-emerald-500/20 hover:bg-emerald-500/10"
						onclick={() => onServiceControl("Start")}
						disabled={serviceActionLoading !== null}
						title="Start TFTP Server"
					>
						<PlayIcon class="size-3 fill-current mr-1.5" />
						Start
					</Button>
				{/if}
			</div>
		{/snippet}

		{#snippet footer()}
			<StatCardFooterItem
				label="Daemon"
				value={isServiceActive ? "Running" : "Stopped"}
				color={isServiceActive ? "text-emerald-500" : "text-muted-foreground"}
			/>
			<StatCardFooterItem label="Supervisor" value="Managed" />
		{/snippet}
	</StatCard>

	<!-- Card 2: Listen Socket -->
	<StatCard
		label="Listen Socket"
		value={listenAddr || "0.0.0.0:69"}
		icon={RadioIcon}
		color="sky"
		subtext="UDP Port 69 (Dual-Stack)"
		{loading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Transport" value="UDP / IPv4+IPv6" />
			<StatCardFooterItem label="Service Port" value="69 / tftp" />
		{/snippet}
	</StatCard>

	<!-- Card 3: Root Directory -->
	<StatCard
		label="Root Directory"
		icon={FolderIcon}
		color="amber"
		subtext="Base filesystem storage"
		{loading}
	>
		{#snippet valueExtra()}
			<div class="flex flex-col gap-0.5 my-0.5 min-w-0">
				<span
					class="text-foreground text-sm font-bold font-mono truncate max-w-full"
					title={rootDir}
				>
					{rootDir || "/var/lib/lanforge/tftp"}
				</span>
				<span class="text-muted-foreground text-xs font-medium">
					Bootloader & kernel root
				</span>
			</div>
		{/snippet}

		{#snippet footer()}
			<StatCardFooterItem label="Permissions" value="0755 Read" />
			<StatCardFooterItem label="Path" value={rootDir.split("/").pop() || "tftp"} />
		{/snippet}
	</StatCard>
</StatCardGrid>
