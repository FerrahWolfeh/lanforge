<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Switch } from "$lib/components/ui/switch";
	import { Separator } from "$lib/components/ui/separator";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import HardDriveDownloadIcon from "@lucide/svelte/icons/hard-drive-download";
	import HelpCircleIcon from "@lucide/svelte/icons/help-circle";

	let {
		loading = false,
		enabled = $bindable(false),
		rootDir = $bindable("/var/lib/lanforge/tftp"),
		listenAddr = $bindable("0.0.0.0:69"),
		blockSize = $bindable(512),
		timeoutSecs = $bindable(5),
		maxRetries = $bindable(3)
	}: {
		loading: boolean;
		enabled: boolean;
		rootDir: string;
		listenAddr: string;
		blockSize: number;
		timeoutSecs: number;
		maxRetries: number;
	} = $props();

	const BLOCK_SIZE_PRESETS = [
		{ label: "512 B (RFC Standard)", value: 512 },
		{ label: "1024 B", value: 1024 },
		{ label: "1456 B (Ethernet Optimal)", value: 1456 },
		{ label: "4096 B", value: 4096 },
		{ label: "8192 B (Fast Netboot)", value: 8192 },
	];
</script>

<Card.Root class="flex flex-col">
	<Card.Header class="pb-4 border-b border-border/50">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<HardDriveDownloadIcon class="size-4 text-emerald-400" />
				<Card.Title class="text-base">Server Parameters</Card.Title>
			</div>
			<Badge variant="outline" class="font-mono text-[10px]">RFC 1350 / 2348</Badge>
		</div>
		<Card.Description>
			Configure daemon listening socket, filesystem root, and transmission block sizes
		</Card.Description>
	</Card.Header>

	<Card.Content class="flex flex-col gap-5 p-5">
		{#if loading}
			<div class="flex flex-col gap-4">
				<Skeleton class="h-12 w-full" />
				<Skeleton class="h-10 w-full" />
				<Skeleton class="h-10 w-full" />
			</div>
		{:else}
			<!-- Service Enable Switch -->
			<div class="flex items-center justify-between rounded-lg border border-border/70 bg-muted/20 p-3.5">
				<div class="flex flex-col gap-0.5">
					<span class="text-sm font-semibold text-foreground">
						Enable TFTP Daemon
					</span>
					<span class="text-xs text-muted-foreground">
						Binds UDP socket on startup and serves files to requesting clients
					</span>
				</div>
				<Switch bind:checked={enabled} />
			</div>

			<!-- Root Directory & Listen Address Grid -->
			<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
				<!-- Root Directory -->
				<div class="flex flex-col gap-2">
					<div class="flex items-center justify-between">
						<Label class="text-xs font-medium">Root Directory Path</Label>
						<Tooltip.Provider>
							<Tooltip.Root>
								<Tooltip.Trigger>
									<HelpCircleIcon class="size-3.5 text-muted-foreground" />
								</Tooltip.Trigger>
								<Tooltip.Content>
									<p class="text-xs max-w-xs">
										Directory where PXE files, kernels, and bootloaders reside. Path traversal outside this root is strictly forbidden by the daemon.
									</p>
								</Tooltip.Content>
							</Tooltip.Root>
						</Tooltip.Provider>
					</div>
					<Input
						bind:value={rootDir}
						placeholder="/var/lib/lanforge/tftp"
						class="font-mono text-xs"
					/>
				</div>

				<!-- Listen Address -->
				<div class="flex flex-col gap-2">
					<div class="flex items-center justify-between">
						<Label class="text-xs font-medium">Listen Address & Port</Label>
						<Tooltip.Provider>
							<Tooltip.Root>
								<Tooltip.Trigger>
									<HelpCircleIcon class="size-3.5 text-muted-foreground" />
								</Tooltip.Trigger>
								<Tooltip.Content>
									<p class="text-xs max-w-xs">
										Bind address for UDP requests. Default is 0.0.0.0:69 (IPv4) or [::]:69 for dual-stack.
									</p>
								</Tooltip.Content>
							</Tooltip.Root>
						</Tooltip.Provider>
					</div>
					<Input
						bind:value={listenAddr}
						placeholder="0.0.0.0:69"
						class="font-mono text-xs"
					/>
				</div>
			</div>

			<Separator class="my-1" />

			<!-- Transmission Tuning Grid -->
			<div class="flex flex-col gap-3">
				<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
					Protocol Transmission Tuning
				</span>

				<div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
					<!-- Block Size -->
					<div class="flex flex-col gap-1.5">
						<Label class="text-xs">Block Size (blksize)</Label>
						<Input
							type="number"
							min="512"
							max="65464"
							bind:value={blockSize}
							class="font-mono text-xs"
						/>
						<span class="text-[11px] text-muted-foreground">
							Default: 512 bytes
						</span>
					</div>

					<!-- Timeout -->
					<div class="flex flex-col gap-1.5">
						<Label class="text-xs">Timeout (seconds)</Label>
						<Input
							type="number"
							min="1"
							max="60"
							bind:value={timeoutSecs}
							class="font-mono text-xs"
						/>
						<span class="text-[11px] text-muted-foreground">
							Retransmission window
						</span>
					</div>

					<!-- Retries -->
					<div class="flex flex-col gap-1.5">
						<Label class="text-xs">Max Retries</Label>
						<Input
							type="number"
							min="1"
							max="10"
							bind:value={maxRetries}
							class="font-mono text-xs"
						/>
						<span class="text-[11px] text-muted-foreground">
							Fail after N drops
						</span>
					</div>
				</div>

				<!-- Block Size Quick Presets -->
				<div class="flex flex-wrap items-center gap-1.5 pt-1">
					<span class="text-[11px] text-muted-foreground mr-1">Presets:</span>
					{#each BLOCK_SIZE_PRESETS as preset (preset.value)}
						<Button
							variant={blockSize === preset.value ? "secondary" : "outline"}
							size="sm"
							class="h-6 text-[11px] px-2 py-0 cursor-pointer"
							onclick={() => { blockSize = preset.value; }}
						>
							{preset.label}
						</Button>
					{/each}
				</div>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
