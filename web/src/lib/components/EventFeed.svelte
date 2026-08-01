<script lang="ts">
	import * as ScrollArea from "$lib/components/ui/scroll-area";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Separator } from "$lib/components/ui/separator";
	import { eventFeed } from "$lib/stores/events.svelte";
	import { formatEventPayload, type EventKind } from "$lib/api/types";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";
	import XIcon from "@lucide/svelte/icons/x";
	import CircleIcon from "@lucide/svelte/icons/circle";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import WifiIcon from "@lucide/svelte/icons/wifi";
	import ShieldIcon from "@lucide/svelte/icons/shield";

	let open = $state(false);
	let filterKind = $state<EventKind | null>(null);

	const kindColors: Record<string, string> = {
		DeviceOnline: "text-green-400",
		DeviceOffline: "text-red-400",
		DeviceUpdated: "text-blue-400",
		DevicePurged: "text-orange-400",
		DhcpLeaseGranted: "text-teal-400",
		DhcpLeaseReleased: "text-yellow-400",
		DnsQuery: "text-sky-400",
		DnsBlocked: "text-rose-400",
		AdblockToggled: "text-purple-400",
		ScanCompleted: "text-cyan-400",
		ConfigReloaded: "text-indigo-400",
	};

	const kindIcons: Record<string, unknown> = {
		DeviceOnline: WifiIcon,
		DeviceOffline: WifiIcon,
		DnsBlocked: ShieldIcon,
		AdblockToggled: ShieldIcon,
		ScanCompleted: ZapIcon,
	};

	function kindColor(kind: string) {
		return kindColors[kind] ?? "text-muted-foreground";
	}

	function formatTs(ts: number): string {
		return new Date(ts).toLocaleTimeString(undefined, {
			hour12: false,
			timeStyle: "medium",
		});
	}

	function formatPayload(
		data: Record<string, unknown>,
		kind?: string,
	): string {
		return formatEventPayload(data, kind);
	}

	const visibleEvents = $derived(
		filterKind
			? eventFeed.events.filter((e) => e.kind === filterKind)
			: eventFeed.events,
	);

	const recentKinds = $derived(
		[...new Set(eventFeed.events.slice(0, 30).map((e) => e.kind))].slice(
			0,
			6,
		),
	);
</script>

<!-- Floating panel anchored bottom-right -->
<div
	class="fixed right-4 bottom-4 z-50 flex flex-col items-end gap-1"
	style="pointer-events: none;"
>
	<!-- Toggle button -->
	<div style="pointer-events: auto;">
		<Button
			variant={open ? "default" : "outline"}
			size="sm"
			onclick={() => (open = !open)}
			class="gap-1.5 shadow-lg"
		>
			<RadioIcon
				class={eventFeed.connected
					? "text-green-400"
					: "text-muted-foreground"}
			/>
			Event Feed
			{#if eventFeed.events.length > 0}
				<Badge
					variant="secondary"
					class="ml-1 h-4 px-1.5 py-0 text-[10px]"
				>
					{eventFeed.events.length}
				</Badge>
			{/if}
			<ChevronDownIcon
				class={["transition-transform", open ? "rotate-180" : ""].join(
					" ",
				)}
			/>
		</Button>
	</div>

	<!-- Panel -->
	{#if open}
		<div
			class="bg-popover border-border flex w-80 flex-col overflow-hidden rounded-lg border shadow-2xl"
			style="pointer-events: auto; max-height: 420px;"
		>
			<!-- Header -->
			<div class="flex items-center gap-2 px-3 py-2">
				<span class="text-foreground text-sm font-semibold">Events</span
				>
				<span
					class={[
						"size-1.5 rounded-full",
						eventFeed.connected
							? "bg-green-500"
							: "bg-muted-foreground",
					].join(" ")}
				></span>
				<div class="flex-1"></div>
				{#if filterKind}
					<Button
						variant="ghost"
						size="icon"
						class="size-6"
						onclick={() => (filterKind = null)}
					>
						<XIcon />
					</Button>
				{/if}
			</div>

			<!-- Kind filter chips -->
			{#if recentKinds.length > 0}
				<div class="flex flex-wrap gap-1 px-3 pb-2">
					{#each recentKinds as kind (kind)}
						<button
							class={[
								"rounded px-1.5 py-0.5 text-[10px] font-medium transition-colors",
								filterKind === kind
									? "bg-primary text-primary-foreground"
									: "bg-muted text-muted-foreground hover:bg-muted/80",
							].join(" ")}
							onclick={() =>
								(filterKind =
									filterKind === kind ? null : kind)}
						>
							{kind}
						</button>
					{/each}
				</div>
				<Separator />
			{/if}

			<!-- Event list -->
			<ScrollArea.Root class="flex-1" style="height: 300px;">
				<div style="height:300px;overflow-y:auto;">
					{#if visibleEvents.length === 0}
						<div
							class="text-muted-foreground flex flex-col items-center gap-2 py-8 text-xs"
						>
							<CircleIcon class="size-6 opacity-30" />
							<span>No events yet</span>
						</div>
					{:else}
						<div class="divide-border divide-y">
							{#each visibleEvents as event (event.id + event.ts)}
								<div class="flex flex-col gap-0.5 px-3 py-2">
									<div class="flex items-center gap-1.5">
										<span
											class={[
												"text-[10px] font-semibold",
												kindColor(event.kind),
											].join(" ")}
										>
											{event.kind}
										</span>
										<span
											class="text-muted-foreground ml-auto text-[10px] tabular-nums"
										>
											{formatTs(event.ts)}
										</span>
									</div>
									<span
										class="text-muted-foreground truncate text-[10px]"
									>
										{formatPayload(event.data)}
									</span>
								</div>
							{/each}
						</div>
					{/if}
				</div>
				<ScrollArea.Scrollbar orientation="vertical" />
			</ScrollArea.Root>
		</div>
	{/if}
</div>
