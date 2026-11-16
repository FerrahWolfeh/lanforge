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
		/** Absent when the session may not control services (admin-only). */
		onServiceControl?: (action: "Start" | "Stop" | "Restart") => void;
	} = $props();
</script>

<StatCardGrid cols={2}>
	<!-- Card 1: Service Lifecycle -->
	<StatCard
		label="Service"
		value={serviceState ? serviceState.charAt(0).toUpperCase() + serviceState.slice(1) : "Inactive"}
		icon={HardDriveDownloadIcon}
		subtext={enabled ? "Enabled in lanforge.toml" : "Disabled in lanforge.toml ([tftp] enabled = false)"}
		{loading}
	>
		{#snippet actions()}
			{#if onServiceControl}
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
						class="h-7 px-2.5 text-xs text-danger hover:text-danger border-danger/20 hover:bg-danger/10"
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
						class="h-7 px-2.5 text-xs text-success hover:text-success border-success/20 hover:bg-success/10"
						onclick={() => onServiceControl("Start")}
						disabled={serviceActionLoading !== null}
						title="Start TFTP Server"
					>
						<PlayIcon class="size-3 fill-current mr-1.5" />
						Start
					</Button>
				{/if}
			</div>
			{/if}
		{/snippet}

	</StatCard>

	<!-- Card 2: Service Binding -->
	<StatCard
		label="Listening On"
		value={listenAddr || "—"}
		icon={RadioIcon}
		subtext={rootDir ? `Serving files from ${rootDir}` : ""}
		{loading}
	>
	</StatCard>
</StatCardGrid>
