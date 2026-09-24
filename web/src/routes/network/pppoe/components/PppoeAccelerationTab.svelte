<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import CpuIcon from "@lucide/svelte/icons/cpu";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import CheckCircleIcon from "@lucide/svelte/icons/check-circle";
	import AlertTriangleIcon from "@lucide/svelte/icons/triangle-alert";
	import ArrowRightIcon from "@lucide/svelte/icons/arrow-right";

	import type { PppoeDataplane } from "$lib/api/types";
	import { capabilitiesState } from "$lib/stores/capabilities.svelte";

	let {
		formDataplane = $bindable("kernel" as PppoeDataplane),
		onSelectEbpf = () => {},
	}: {
		formDataplane?: PppoeDataplane;
		onSelectEbpf?: () => void;
	} = $props();
</script>

<div class="flex flex-col gap-6">
	<!-- Data Plane Architecture Card -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<Card.Title class="text-base font-semibold flex items-center gap-2">
				<ZapIcon class="size-4 text-primary" />
				PPPoE Dataplane Architecture
			</Card.Title>
			<Card.Description class="text-xs">
				Choose how PPPoE session packets are encapsulated, processed, and routed through the network subsystem.
			</Card.Description>
		</Card.Header>
		<Card.Content class="p-4">
			<div class="grid gap-4 md:grid-cols-2">
				<!-- Linux Kernel Mode Option -->
				<button
					type="button"
					class={[
						"relative text-left rounded-xl border p-4 transition-all duration-200 cursor-pointer flex flex-col gap-2",
						formDataplane === "kernel"
							? "border-primary bg-primary/5 shadow-xs"
							: "border-border/60 hover:bg-muted/10",
					].join(" ")}
					onclick={() => (formDataplane = "kernel")}
				>
					<div class="flex items-center justify-between">
						<div class="flex items-center gap-2 font-semibold text-sm">
							<CpuIcon class="size-4 text-primary" />
							<span>Standard Linux Kernel</span>
						</div>
						{#if formDataplane === "kernel"}
							<Badge variant="default" class="text-xs">Active</Badge>
						{:else}
							<Badge variant="outline" class="text-xs">Recommended</Badge>
						{/if}
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed">
						Uses the kernel <code class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono">/dev/ppp</code> device and native <code class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono">ppp_generic</code> driver. Maximum stability and full compatibility with Netfilter hardware offloading.
					</p>
					<div class="flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400 font-medium mt-1">
						<CheckCircleIcon class="size-3.5" />
						Compatible with Flowtable Fast-Path and bidirectional TCP MSS Clamping
					</div>
				</button>

				<!-- eBPF Fast-Path Option -->
				{#if capabilitiesState.isCompiled("ebpf")}
					<button
						type="button"
						class={[
							"relative text-left rounded-xl border p-4 transition-all duration-200 cursor-pointer flex flex-col gap-2",
							formDataplane === "ebpf"
								? "border-amber-500 bg-amber-500/5 shadow-xs"
								: "border-border/60 hover:bg-muted/10",
						].join(" ")}
						onclick={onSelectEbpf}
					>
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2 font-semibold text-sm text-amber-500">
								<ZapIcon class="size-4 text-amber-500" />
								<span>eBPF Fast-Path (Generic XDP + TC)</span>
							</div>
							<div class="flex items-center gap-1.5">
								{#if capabilitiesState.debugMode && !capabilitiesState.isActualCompiled("ebpf")}
									<Badge variant="outline" class="border-amber-500/40 text-amber-500 text-[10px]">Debug View</Badge>
								{/if}
								{#if formDataplane === "ebpf"}
									<Badge variant="outline" class="border-amber-500 text-amber-500 text-xs">Active (Experimental)</Badge>
								{:else}
									<Badge variant="secondary" class="text-xs">Experimental</Badge>
								{/if}
							</div>
						</div>
						<p class="text-xs text-muted-foreground leading-relaxed">
							Processes PPPoE framing directly inside eBPF TC filters on the WAN interface, bypassing generic ppp driver layers.
						</p>
						<div class="flex items-center gap-1.5 text-[11px] text-amber-500 font-medium mt-1">
							<AlertTriangleIcon class="size-3.5" />
							Requires Generic XDP SKB kernel support
						</div>
					</button>
				{:else}
					<div class="relative text-left rounded-xl border border-dashed border-border/60 p-4 flex flex-col gap-2 opacity-60">
						<div class="flex items-center justify-between">
							<div class="flex items-center gap-2 font-semibold text-sm text-muted-foreground">
								<ZapIcon class="size-4" />
								<span>eBPF Fast-Path</span>
							</div>
							<Badge variant="outline" class="text-xs">Not Compiled</Badge>
						</div>
						<p class="text-xs text-muted-foreground leading-relaxed">
							eBPF dataplane support is not compiled into this binary. Recompile with <code class="rounded bg-muted px-1 py-0.5 text-[11px] font-mono">--features ebpf</code> to enable Generic XDP and TC fast-path acceleration.
						</p>
					</div>
				{/if}
			</div>
		</Card.Content>
	</Card.Root>

	<!-- Firewall & Routing Delegation Card -->
	<Card.Root class="border-primary/20 bg-muted/10">
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
				<div>
					<Card.Title class="text-base font-semibold flex items-center gap-2">
						<ShieldCheckIcon class="size-4 text-primary" />
						Firewall & Routing Orchestration
					</Card.Title>
					<Card.Description class="text-xs">
						Packet filtering, bidirectional TCP MSS Clamping, Flowtable Fast-Path, and PPPoE Masquerade are centrally orchestrated by the Lanforge Firewall service.
					</Card.Description>
				</div>
				<Button variant="outline" size="sm" href="/firewall" class="shrink-0 h-8 text-xs gap-1.5">
					<span>Configure in Firewall</span>
					<ArrowRightIcon class="size-3.5" />
				</Button>
			</div>
		</Card.Header>
		<Card.Content class="p-4">
			<div class="grid gap-3 sm:grid-cols-3">
				<div class="flex items-center gap-2.5 p-3 rounded-lg border bg-card">
					<div class="size-2 rounded-full bg-emerald-500"></div>
					<div class="flex flex-col">
						<span class="text-xs font-semibold">Flowtable Fast-Path</span>
						<span class="text-[11px] text-muted-foreground">Kernel bypass for established streams</span>
					</div>
				</div>
				<div class="flex items-center gap-2.5 p-3 rounded-lg border bg-card">
					<div class="size-2 rounded-full bg-emerald-500"></div>
					<div class="flex flex-col">
						<span class="text-xs font-semibold">MSS Clamping (1452/1432)</span>
						<span class="text-[11px] text-muted-foreground">Bidirectional protection against MTU drops</span>
					</div>
				</div>
				<div class="flex items-center gap-2.5 p-3 rounded-lg border bg-card">
					<div class="size-2 rounded-full bg-emerald-500"></div>
					<div class="flex flex-col">
						<span class="text-xs font-semibold">NAT Masquerade</span>
						<span class="text-[11px] text-muted-foreground">Automatic translation on ppp0 uplink</span>
					</div>
				</div>
			</div>
		</Card.Content>
	</Card.Root>
</div>
