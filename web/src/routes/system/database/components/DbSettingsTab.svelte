<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Separator } from "$lib/components/ui/separator";
	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import CheckIcon from "@lucide/svelte/icons/check";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import RotateCcwIcon from "@lucide/svelte/icons/rotate-ccw";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";

	let {
		formStorageType = $bindable("persistent" as "persistent" | "volatile"),
		formUrl = $bindable("/var/lib/lanforge/lanforge.redb"),
		formFlushInterval = $bindable(60),
		formLogUrl = $bindable("/run/lanforge/runtime.redb"),
		computedToml = "",
		isDirty = false,
		applyingEngineSwitch = false,
		onDiscard = () => {},
		onApply = () => {},
		onCopyToml = () => {},
	}: {
		formStorageType?: "persistent" | "volatile";
		formUrl?: string;
		formFlushInterval?: number;
		formLogUrl?: string;
		computedToml?: string;
		isDirty?: boolean;
		applyingEngineSwitch?: boolean;
		onDiscard?: () => void;
		onApply?: () => void;
		onCopyToml?: () => void;
	} = $props();
</script>

<div class="flex flex-col gap-6">
	<Card.Root>
		<Card.Header>
			<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
				<div class="space-y-1">
					<Card.Title class="text-base flex items-center gap-2 font-semibold">
						<SlidersIcon class="size-5 text-primary" />
						Storage Engine Configuration
					</Card.Title>
					<Card.Description class="text-xs">
						Configure how the Lanforge persistence layer connects to its storage backend.
					</Card.Description>
				</div>
				{#if isDirty}
					<Badge variant="outline" class="border-amber-500/30 bg-amber-500/10 text-amber-500 text-xs gap-1">
						<span class="size-1.5 rounded-full bg-amber-500 animate-pulse"></span>
						Unsaved Changes
					</Badge>
				{/if}
			</div>
		</Card.Header>
		<Card.Content class="space-y-6">
			<!-- Storage Mode Selector -->
			<div class="space-y-2">
				<Label class="text-xs font-semibold">Storage Persistence Mode</Label>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
					<button
						type="button"
						class={[
							"flex flex-col gap-1 p-3.5 rounded-xl border text-left transition-all cursor-pointer",
							formStorageType === "persistent"
								? "border-primary bg-primary/5 ring-1 ring-primary"
								: "border-border hover:bg-muted/40",
						].join(" ")}
						onclick={() => {
							formStorageType = "persistent";
							if (formUrl.startsWith("/run") || formUrl.startsWith("/tmp") || formUrl === "memory") {
								formUrl = "/var/lib/lanforge/lanforge.redb";
							}
						}}
					>
						<div class="flex items-center justify-between w-full">
							<span class="text-sm font-bold text-foreground">Persistent Storage (Disk / Flash)</span>
							{#if formStorageType === "persistent"}
								<CheckIcon class="size-4 text-primary" />
							{/if}
						</div>
						<p class="text-xs text-muted-foreground leading-relaxed">
							Default for standard Linux servers, homelabs, and VMs. Preserves all configuration and state across reboots.
						</p>
					</button>

					<button
						type="button"
						class={[
							"flex flex-col gap-1 p-3.5 rounded-xl border text-left transition-all cursor-pointer",
							formStorageType === "volatile"
								? "border-amber-500 bg-amber-500/5 ring-1 ring-amber-500"
								: "border-border hover:bg-muted/40",
						].join(" ")}
						onclick={() => {
							formStorageType = "volatile";
							if (formUrl.startsWith("/var/lib")) {
								formUrl = "in_memory";
							}
						}}
					>
						<div class="flex items-center justify-between w-full">
							<span class="text-sm font-bold text-foreground">Volatile / In-Memory</span>
							{#if formStorageType === "volatile"}
								<CheckIcon class="size-4 text-amber-500" />
							{/if}
						</div>
						<p class="text-xs text-muted-foreground leading-relaxed">
							Keeps the entire Lanforge state in application RAM without using redb. State resets completely when the process restarts.
						</p>
					</button>
				</div>
			</div>

			<Separator />

			{#if formStorageType === "volatile"}
				<div class="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs flex flex-col gap-1.5">
					<div class="flex items-center gap-1.5 font-semibold text-amber-600 dark:text-amber-400">
						<AlertTriangleIcon class="size-4 shrink-0" />
						<span>In-Memory Volatile Mode</span>
					</div>
					<p class="text-muted-foreground leading-relaxed text-[11px]">
						No database files will be created or read from disk. The complete Lanforge state resides purely in application process RAM and resets when the daemon restarts.
					</p>
				</div>
			{:else}
				<!-- Database Paths and Cadence -->
				<div class="space-y-4">
					<div class="space-y-1.5">
						<Label for="cfg-path" class="text-xs font-semibold">redb Database Path</Label>
						<Input
							id="cfg-path"
							bind:value={formUrl}
							placeholder="/var/lib/lanforge/config.redb"
							class="text-xs font-mono"
						/>
						<p class="text-[11px] text-muted-foreground">
							Path to the persistent configuration <code class="text-foreground">redb</code> database file.
						</p>
					</div>

					<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-1">
						<div class="space-y-1.5">
							<Label for="cfg-flush" class="text-xs font-semibold">Flush Interval (seconds)</Label>
							<Input
								id="cfg-flush"
								type="number"
								min="5"
								max="600"
								bind:value={formFlushInterval}
								class="text-xs font-mono"
							/>
							<p class="text-[10px] text-muted-foreground">
								Frequency at which in-memory state is flushed to disk.
							</p>
						</div>
						<div class="space-y-1.5">
							<Label for="cfg-logpath" class="text-xs font-semibold">Runtime Database Path</Label>
							<Input
								id="cfg-logpath"
								bind:value={formLogUrl}
								placeholder="/run/lanforge/runtime.redb"
								class="text-xs font-mono"
							/>
							<p class="text-[10px] text-muted-foreground">
								Optional path for runtime query logs and audit records.
							</p>
						</div>
					</div>
				</div>
			{/if}

			<Separator />

			<!-- Live Generated TOML Preview -->
			<div class="space-y-3">
				<div class="flex items-center justify-between">
					<div class="space-y-0.5">
						<h4 class="text-sm font-semibold text-foreground">
							Generated Configuration (lanforge.toml)
						</h4>
						<p class="text-xs text-muted-foreground">
							Add or replace this section in your <span class="font-mono text-foreground font-medium">/etc/lanforge/lanforge.toml</span> configuration file.
						</p>
					</div>
					<Button variant="outline" size="sm" class="gap-1.5 text-xs" onclick={onCopyToml}>
						<CopyIcon class="size-3.5" />
						Copy TOML
					</Button>
				</div>

				<pre class="rounded-lg bg-muted/60 border p-4 font-mono text-xs text-foreground overflow-x-auto select-all leading-relaxed"><code>{computedToml}</code></pre>
			</div>

			<!-- Action bar when dirty -->
			{#if isDirty}
				<div class="flex flex-col sm:flex-row items-center justify-between gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
					<div class="flex items-center gap-2 text-amber-600 dark:text-amber-400 font-medium">
						<AlertTriangleIcon class="size-4 shrink-0" />
						<span>Unsaved changes in form. Copy configuration or apply switch to activate.</span>
					</div>
					<div class="flex items-center gap-2">
						<Button variant="ghost" size="sm" class="h-8 gap-1 text-xs" onclick={onDiscard}>
							<RotateCcwIcon class="size-3.5" />
							Revert
						</Button>
						<Button
							variant="default"
							size="sm"
							class="h-8 gap-1.5 text-xs shadow-sm"
							onclick={onApply}
							disabled={applyingEngineSwitch}
						>
							{#if applyingEngineSwitch}
								<RefreshCwIcon class="size-3.5 animate-spin" />
								Migrating &amp; Rebooting...
							{:else}
								<CheckCircleIcon class="size-3.5" />
								Save &amp; Switch Engine
							{/if}
						</Button>
					</div>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
