<script lang="ts">
	import * as Dialog from "$lib/components/ui/dialog";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import CodeIcon from "@lucide/svelte/icons/code";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import NetworkIcon from "@lucide/svelte/icons/network";
	import ServerIcon from "@lucide/svelte/icons/server";
	import { toast } from "svelte-sonner";
	import { formatEventPayload, type SseEvent } from "$lib/api/types";

	let {
		open = $bindable(false),
		event = null,
	}: {
		open: boolean;
		event: SseEvent | null;
	} = $props();

	let copied = $state(false);

	function formatTimestamp(ts: number): string {
		if (!ts) return "—";
		const date = new Date(ts);
		return date.toLocaleString(undefined, {
			year: "numeric",
			month: "2-digit",
			day: "2-digit",
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
			fractionalSecondDigits: 3,
			hour12: false,
		});
	}

	const rawJson = $derived(
		event ? JSON.stringify(event.raw ?? event, null, 2) : "{}"
	);

	const formattedDescription = $derived(
		event
			? formatEventPayload(
					event.data,
					event.kind,
					event.device_info,
					event.interface_info,
					event.service_info,
				)
			: "—"
	);

	async function copyRaw() {
		if (!event) return;
		try {
			await navigator.clipboard.writeText(rawJson);
			copied = true;
			toast.success("Event JSON copied to clipboard");
			setTimeout(() => {
				copied = false;
			}, 2000);
		} catch {
			toast.error("Failed to copy JSON");
		}
	}
</script>

<Dialog.Root bind:open>
	<Dialog.Content class="max-w-2xl max-h-[85vh] flex flex-col gap-4 overflow-hidden">
		<Dialog.Header>
			<div class="flex items-center justify-between pr-6">
				<div class="flex items-center gap-2">
					<ActivityIcon class="size-5 text-primary" />
					<Dialog.Title class="text-lg font-semibold">Event Inspector</Dialog.Title>
				</div>
				{#if event?.topic}
					<Badge variant="outline" class="uppercase text-xs font-mono tracking-wider">
						{event.topic}
					</Badge>
				{/if}
			</div>
			<Dialog.Description class="text-xs text-muted-foreground">
				Detailed payload information, system context, and structured JSON representation.
			</Dialog.Description>
		</Dialog.Header>

		{#if event}
			<div class="flex flex-col gap-4 overflow-y-auto pr-1">
				<!-- Event Overview -->
				<div class="rounded-lg border bg-muted/30 p-3.5 space-y-2 text-sm">
					<div class="flex items-center justify-between">
						<span class="font-medium text-foreground text-base">{event.kind}</span>
						<span class="text-xs text-muted-foreground flex items-center gap-1.5 font-mono">
							<ClockIcon class="size-3.5" />
							{formatTimestamp(event.ts)}
						</span>
					</div>
					<p class="text-xs text-muted-foreground leading-relaxed">
						{formattedDescription}
					</p>
				</div>

				<!-- Device Context from lanforge-core -->
				{#if event.device_info}
					<div class="space-y-1.5">
						<div class="flex items-center gap-1.5">
							<LaptopIcon class="size-3.5 text-primary" />
							<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
								Device Identity & Context
							</span>
						</div>
						<div class="rounded-lg border bg-card/60 p-3 space-y-2 text-xs">
							<div class="grid grid-cols-2 sm:grid-cols-3 gap-2">
								<div>
									<span class="text-[11px] text-muted-foreground block">Hostname</span>
									<span class="font-medium text-foreground">{event.device_info.hostname || "—"}</span>
								</div>
								<div>
									<span class="text-[11px] text-muted-foreground block">IPv4 Address</span>
									<span class="font-mono text-foreground">{event.device_info.ip || "—"}</span>
								</div>
								<div>
									<span class="text-[11px] text-muted-foreground block">MAC Address</span>
									<span class="font-mono text-foreground">{event.device_info.mac}</span>
								</div>
								<div>
									<span class="text-[11px] text-muted-foreground block">Device Class</span>
									<Badge variant="outline" class="text-[11px] px-1.5 py-0 mt-0.5">
										{event.device_info.class || "None"}
									</Badge>
								</div>
								<div>
									<span class="text-[11px] text-muted-foreground block">Lease Mode</span>
									<Badge variant={event.device_info.is_static ? "default" : "secondary"} class="text-[11px] px-1.5 py-0 mt-0.5">
										{event.device_info.is_static ? "Static (Reserved)" : "Dynamic (DHCP)"}
									</Badge>
								</div>
								{#if event.device_info.iface}
									<div>
										<span class="text-[11px] text-muted-foreground block">Interface</span>
										<span class="font-mono text-foreground">{event.device_info.iface}</span>
									</div>
								{/if}
							</div>
						</div>
					</div>
				{/if}

				<!-- Interface Context -->
				{#if event.interface_info}
					<div class="space-y-1.5">
						<div class="flex items-center gap-1.5">
							<NetworkIcon class="size-3.5 text-primary" />
							<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
								Interface Context
							</span>
						</div>
						<div class="rounded-lg border bg-card/60 p-3 space-y-2 text-xs">
							<div class="grid grid-cols-2 sm:grid-cols-3 gap-2">
								<div>
									<span class="text-[11px] text-muted-foreground block">Interface Name</span>
									<span class="font-mono font-medium text-foreground">{event.interface_info.name || `Index #${event.interface_info.ifindex}`}</span>
								</div>
								{#if event.interface_info.ipv4}
									<div>
										<span class="text-[11px] text-muted-foreground block">IPv4</span>
										<span class="font-mono text-foreground">{event.interface_info.ipv4}</span>
									</div>
								{/if}
								{#if event.interface_info.gua}
									<div>
										<span class="text-[11px] text-muted-foreground block">IPv6 GUA</span>
										<span class="font-mono text-[11px] text-foreground break-all">{event.interface_info.gua}</span>
									</div>
								{/if}
								{#if event.interface_info.ula}
									<div>
										<span class="text-[11px] text-muted-foreground block">IPv6 ULA</span>
										<span class="font-mono text-[11px] text-foreground break-all">{event.interface_info.ula}</span>
									</div>
								{/if}
							</div>
						</div>
					</div>
				{/if}

				<!-- Service Context -->
				{#if event.service_info}
					<div class="space-y-1.5">
						<div class="flex items-center gap-1.5">
							<ServerIcon class="size-3.5 text-primary" />
							<span class="text-xs font-semibold text-foreground uppercase tracking-wider">
								Service Lifecycle Context
							</span>
						</div>
						<div class="rounded-lg border bg-card/60 p-3 space-y-2 text-xs">
							<div class="grid grid-cols-3 gap-2">
								<div>
									<span class="text-[11px] text-muted-foreground block">Service ID</span>
									<span class="font-mono font-medium text-foreground">{event.service_info.id}</span>
								</div>
								<div>
									<span class="text-[11px] text-muted-foreground block">State</span>
									<Badge variant="outline" class="text-[11px] px-1.5 py-0 mt-0.5">
										{event.service_info.state}
									</Badge>
								</div>
								<div>
									<span class="text-[11px] text-muted-foreground block">Uptime</span>
									<span class="text-foreground">{event.service_info.uptime_secs > 0 ? `${Math.floor(event.service_info.uptime_secs / 60)}m ${event.service_info.uptime_secs % 60}s` : "0s"}</span>
								</div>
							</div>
						</div>
					</div>
				{/if}

				<!-- Structured Data -->
				{#if event.data && Object.keys(event.data).length > 0}
					<div class="space-y-1.5">
						<span class="text-xs font-medium text-muted-foreground uppercase tracking-wider">
							Attributes
						</span>
						<div class="rounded-md border bg-card/60 p-2.5 space-y-1 text-xs font-mono">
							{#each Object.entries(event.data) as [key, val]}
								<div class="flex items-start justify-between py-0.5 border-b border-muted/40 last:border-0">
									<span class="text-muted-foreground font-semibold">{key}:</span>
									<span class="text-foreground max-w-[70%] text-right break-all">
										{typeof val === "object" ? JSON.stringify(val) : String(val)}
									</span>
								</div>
							{/each}
						</div>
					</div>
				{/if}

				<!-- Raw JSON Viewer -->
				<div class="space-y-1.5">
					<div class="flex items-center justify-between">
						<span class="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
							<CodeIcon class="size-3.5" />
							Raw Event JSON
						</span>
						<Button
							variant="ghost"
							size="sm"
							class="h-7 text-xs gap-1.5 px-2"
							onclick={copyRaw}
						>
							{#if copied}
								<CheckIcon class="size-3.5 text-emerald-500" />
								<span>Copied</span>
							{:else}
								<CopyIcon class="size-3.5" />
								<span>Copy JSON</span>
							{/if}
						</Button>
					</div>
					<pre class="rounded-lg border bg-muted/50 p-3 text-xs font-mono overflow-x-auto max-h-60 leading-tight text-foreground select-all">{rawJson}</pre>
				</div>
			</div>
		{/if}

		<Dialog.Footer class="mt-2">
			<Button variant="outline" size="sm" onclick={() => (open = false)}>
				Close
			</Button>
		</Dialog.Footer>
	</Dialog.Content>
</Dialog.Root>
