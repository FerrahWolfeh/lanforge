<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Label } from "$lib/components/ui/label";
	import { Separator } from "$lib/components/ui/separator";
	import { toast } from "svelte-sonner";

	import SlidersIcon from "@lucide/svelte/icons/sliders";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import DatabaseIcon from "@lucide/svelte/icons/database";

	import { dnsCacheFlush } from "$lib/api/client";
	import type { DnsStatsResponse } from "$lib/api/types";

	let {
		open = $bindable(false),
		statsData = null,
		onReload = async () => {},
	}: {
		open?: boolean;
		statsData?: DnsStatsResponse | null;
		onReload?: () => Promise<void>;
	} = $props();

	let flushing = $state(false);
	let selectedMode = $state<"sequential" | "parallel" | "fastest" | "roundrobin">("sequential");

	const MODES = [
		{
			id: "sequential" as const,
			name: "Sequential (Default)",
			desc: "Queries upstreams in configured priority order with fallback",
			badge: "Predictable",
		},
		{
			id: "fastest" as const,
			name: "Fastest Response (EWMA)",
			desc: "Dynamically routes queries to the resolver with the lowest EWMA latency",
			badge: "Lowest Latency",
		},
		{
			id: "parallel" as const,
			name: "Parallel Blast",
			desc: "Sends query to all upstreams simultaneously, first valid answer wins",
			badge: "Most Resilient",
		},
		{
			id: "roundrobin" as const,
			name: "Round-Robin",
			desc: "Evenly distributes outbound lookups across all configured upstreams",
			badge: "Load Balanced",
		},
	];

	async function handleFlushCache() {
		flushing = true;
		try {
			await dnsCacheFlush();
			toast.success("Flushed DNS resolver in-memory cache");
			await onReload();
		} catch (err: any) {
			toast.error(`Failed to flush DNS cache: ${err.message || String(err)}`);
		} finally {
			flushing = false;
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<SlidersIcon class="size-4 text-sky-500 dark:text-sky-400" />
				<span>DNS Resolver Tuning & Maintenance</span>
			</Dialog.Title>
			<Dialog.Description>
				Configure recursive query forwarding strategies and cache memory lifecycle
			</Dialog.Description>
		</Dialog.Header>

		<div class="flex flex-col gap-4 py-2">
			<!-- Strategy Selection -->
			<div class="flex flex-col gap-2">
				<Label class="text-xs font-semibold text-foreground uppercase tracking-wider">
					Upstream Resolution Strategy
				</Label>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
					{#each MODES as m (m.id)}
						{@const selected = selectedMode === m.id}
						<button
							type="button"
							class={[
								"flex flex-col text-left p-2.5 rounded-lg border transition-all cursor-pointer",
								selected
									? "border-primary bg-primary/5 ring-1 ring-primary/40"
									: "border-border/60 bg-muted/20 hover:bg-muted/40",
							].join(" ")}
							onclick={() => {
								selectedMode = m.id;
								toast.info(`Selected ${m.name} upstream mode`);
							}}
						>
							<div class="flex w-full items-center justify-between gap-1">
								<span class="text-xs font-semibold text-foreground">{m.name}</span>
								<Badge variant={selected ? "default" : "secondary"} class="text-[9px] px-1.5 py-0 font-mono">
									{m.badge}
								</Badge>
							</div>
							<span class="text-[10px] text-muted-foreground mt-1 leading-tight">
								{m.desc}
							</span>
						</button>
					{/each}
				</div>
			</div>

			<Separator />

			<!-- Cache Maintenance & Telemetry -->
			<div class="flex flex-col gap-2">
				<Label class="text-xs font-semibold text-foreground uppercase tracking-wider">
					In-Memory Cache Lifecycle
				</Label>

				<div class="grid grid-cols-3 gap-2 text-center">
					<div class="rounded-lg border border-border/60 bg-muted/20 p-2">
						<span class="text-xs text-muted-foreground">Cached Records</span>
						<p class="text-base font-bold font-mono text-foreground mt-0.5">
							{statsData?.cache_entries?.toLocaleString() ?? "—"}
						</p>
					</div>
					<div class="rounded-lg border border-border/60 bg-muted/20 p-2">
						<span class="text-xs text-muted-foreground">Capacity</span>
						<p class="text-base font-bold font-mono text-foreground mt-0.5">
							{statsData?.cache_capacity?.toLocaleString() ?? "5,000"}
						</p>
					</div>
					<div class="rounded-lg border border-border/60 bg-muted/20 p-2">
						<span class="text-xs text-muted-foreground">Evictions</span>
						<p class="text-base font-bold font-mono text-foreground mt-0.5">
							{statsData?.cache_evictions?.toLocaleString() ?? "0"}
						</p>
					</div>
				</div>

				<div class="flex items-center justify-between p-3 rounded-lg border bg-card/60 mt-1">
					<div class="flex flex-col gap-0.5">
						<span class="text-xs font-semibold text-foreground">Flush In-Memory Cache</span>
						<span class="text-[11px] text-muted-foreground">
							Purges all cached query responses, forcing next queries to resolve upstream.
						</span>
					</div>
					<Button
						variant="outline"
						size="sm"
						onclick={handleFlushCache}
						disabled={flushing}
						class="text-xs gap-1.5 text-rose-400 hover:text-rose-300"
					>
						<Trash2Icon class="size-3.5 {flushing ? 'animate-spin' : ''}" />
						Flush Cache
					</Button>
				</div>
			</div>
		</div>

		<Dialog.Footer>
			<Button variant="outline" onclick={() => { open = false; }}>
				Close
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
