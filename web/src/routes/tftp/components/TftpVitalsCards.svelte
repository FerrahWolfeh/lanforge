<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import PlayIcon from "@lucide/svelte/icons/play";
	import SquareIcon from "@lucide/svelte/icons/square";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import FolderIcon from "@lucide/svelte/icons/folder";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import NetworkIcon from "@lucide/svelte/icons/network";

	let {
		loading = false,
		isServiceActive = false,
		serviceState = "inactive",
		enabled = false,
		listenAddr = "0.0.0.0:69",
		rootDir = "/var/lib/lanforge/tftp",
		blockSize = 512,
		timeoutSecs = 5,
		maxRetries = 3,
		serviceActionLoading = null,
		onServiceControl
	}: {
		loading: boolean;
		isServiceActive: boolean;
		serviceState: string;
		enabled: boolean;
		listenAddr: string;
		rootDir: string;
		blockSize: number;
		timeoutSecs: number;
		maxRetries: number;
		serviceActionLoading: string | null;
		onServiceControl: (action: "Start" | "Stop" | "Restart") => void;
	} = $props();
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Card 1: Service State & Quick Actions -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Service Lifecycle
				</span>
				<div
					class={[
						"flex size-8 items-center justify-center rounded-lg border",
						isServiceActive
							? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
							: "bg-zinc-500/10 border-zinc-500/20 text-zinc-400",
					].join(" ")}
				>
					<HardDriveDownloadIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-24" />
				<Skeleton class="h-4 w-32" />
			{:else}
				<div class="flex items-center justify-between">
					<div class="flex items-center gap-2">
						<span
							class={[
								"size-2.5 rounded-full",
								isServiceActive
									? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
									: "bg-zinc-600",
							].join(" ")}
						></span>
						<span class="text-foreground text-lg font-bold capitalize">
							{serviceState}
						</span>
					</div>

					<div class="flex items-center gap-1">
						{#if isServiceActive}
							<Button
								variant="outline"
								size="icon-sm"
								onclick={() => onServiceControl("Restart")}
								disabled={serviceActionLoading !== null}
								title="Restart TFTP Server"
							>
								<RotateCwIcon class={serviceActionLoading === "Restart" ? "animate-spin size-3.5" : "size-3.5"} />
							</Button>
							<Button
								variant="outline"
								size="icon-sm"
								class="text-rose-400 hover:text-rose-300"
								onclick={() => onServiceControl("Stop")}
								disabled={serviceActionLoading !== null}
								title="Stop TFTP Server"
							>
								<SquareIcon class="size-3.5 fill-current" />
							</Button>
						{:else}
							<Button
								variant="outline"
								size="icon-sm"
								class="text-emerald-400 hover:text-emerald-300"
								onclick={() => onServiceControl("Start")}
								disabled={serviceActionLoading !== null}
								title="Start TFTP Server"
							>
								<PlayIcon class="size-3.5 fill-current" />
							</Button>
						{/if}
					</div>
				</div>
				<span class="text-muted-foreground text-xs font-medium">
					{enabled ? "Enabled in system configuration" : "Disabled in configuration"}
				</span>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 2: Listen Socket -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Listen Socket
				</span>
				<div class="bg-sky-500/10 border-sky-500/20 text-sky-400 flex size-8 items-center justify-center rounded-lg border">
					<RadioIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-28" />
				<Skeleton class="h-4 w-20" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span class="text-foreground text-xl font-bold font-mono tracking-tight">
						{listenAddr || "0.0.0.0:69"}
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						UDP Port 69 (Dual-Stack)
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 3: Root Directory -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Root Directory
				</span>
				<div class="bg-amber-500/10 border-amber-500/20 text-amber-400 flex size-8 items-center justify-center rounded-lg border">
					<FolderIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-36" />
				<Skeleton class="h-4 w-24" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span
						class="text-foreground text-sm font-bold font-mono truncate max-w-full"
						title={rootDir}
					>
						{rootDir || "/var/lib/lanforge/tftp"}
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						Base filesystem path
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Card 4: Transfer Parameters -->
	<Card.Root class="relative overflow-hidden transition-all hover:border-zinc-700">
		<Card.Content class="flex flex-col gap-3 p-5">
			<div class="flex items-center justify-between">
				<span class="text-muted-foreground text-xs font-semibold uppercase tracking-wider">
					Transfer Tuning
				</span>
				<div class="bg-purple-500/10 border-purple-500/20 text-purple-400 flex size-8 items-center justify-center rounded-lg border">
					<NetworkIcon class="size-4" />
				</div>
			</div>

			{#if loading}
				<Skeleton class="h-8 w-24" />
				<Skeleton class="h-4 w-28" />
			{:else}
				<div class="flex flex-col gap-0.5">
					<span class="text-foreground text-xl font-bold font-mono tracking-tight">
						{blockSize} B / {timeoutSecs}s
					</span>
					<span class="text-muted-foreground text-xs font-medium">
						Max {maxRetries} block retries
					</span>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
