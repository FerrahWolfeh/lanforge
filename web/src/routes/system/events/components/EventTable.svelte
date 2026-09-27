<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import * as Select from "$lib/components/ui/select";
	import DataTableCard from "$lib/components/DataTableCard.svelte";
	import EventDetailDialog from "./EventDetailDialog.svelte";
	import ActivityIcon from "@lucide/svelte/icons/activity";
	import PauseIcon from "@lucide/svelte/icons/pause";
	import PlayIcon from "@lucide/svelte/icons/play";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import DownloadIcon from "@lucide/svelte/icons/download";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import { toast } from "svelte-sonner";
	import { formatEventPayload, type SseEvent } from "$lib/api/types";

	let {
		events = [],
		loading = false,
		isLive = true,
		bufferLimit = $bindable(500),
		onToggleLive = () => {},
		onClearBuffer = () => {},
		onRefreshHistory = () => {},
	}: {
		events?: SseEvent[];
		loading?: boolean;
		isLive?: boolean;
		bufferLimit?: number;
		onToggleLive?: () => void;
		onClearBuffer?: () => void;
		onRefreshHistory?: () => void;
	} = $props();

	let searchQuery = $state("");
	let selectedTopic = $state("");
	let pageIndex = $state(0);
	let pageSize = $state(50);
	let selectedEvent = $state<SseEvent | null>(null);
	let dialogOpen = $state(false);

	const TOPIC_FILTERS = [
		{ value: "", label: "All Subsystems" },
		{ value: "system", label: "System Lifecycle" },
		{ value: "device", label: "Devices & Hosts" },
		{ value: "dhcp", label: "DHCP & Leases" },
		{ value: "network", label: "Network & RA" },
		{ value: "firewall", label: "Firewall & Ports" },
		{ value: "pppoe", label: "PPPoE WAN" },
		{ value: "traffic", label: "Traffic & SQM" },
		{ value: "storage", label: "Database & Storage" },
	];

	const BUFFER_OPTIONS = [
		{ value: "100", label: "100 Events" },
		{ value: "250", label: "250 Events" },
		{ value: "500", label: "500 Events" },
		{ value: "1000", label: "1,000 Events" },
	];

	function getTopicBadgeClass(topic?: string): string {
		switch (topic?.toLowerCase()) {
			case "firewall":
				return "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20";
			case "device":
			case "dhcp":
				return "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20";
			case "pppoe":
				return "bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/20";
			case "traffic":
				return "bg-teal-500/10 text-teal-600 dark:text-teal-400 border-teal-500/20";
			case "network":
				return "bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/20";
			case "storage":
			case "db":
				return "bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border-indigo-500/20";
			case "system":
			default:
				return "bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20";
		}
	}

	function formatTime(ts: number): string {
		if (!ts) return "—";
		const date = new Date(ts);
		return date.toLocaleTimeString(undefined, {
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
			fractionalSecondDigits: 3,
			hour12: false,
		});
	}

	function formatFullDate(ts: number): string {
		if (!ts) return "—";
		return new Date(ts).toLocaleString(undefined, {
			year: "numeric",
			month: "2-digit",
			day: "2-digit",
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
			hour12: false,
		});
	}

	const filteredEvents = $derived.by(() => {
		const q = searchQuery.trim().toLowerCase();
		return events.filter((ev) => {
			if (selectedTopic) {
				const topic = (ev.topic || "system").toLowerCase();
				if (selectedTopic === "dhcp") {
					const isDhcp =
						topic === "dhcp" ||
						ev.kind.toLowerCase().includes("dhcp") ||
						ev.kind.toLowerCase().includes("lease");
					if (!isDhcp) return false;
				} else if (topic !== selectedTopic.toLowerCase()) {
					return false;
				}
			}

			if (!q) return true;

			const matchKind = ev.kind.toLowerCase().includes(q);
			const matchTopic = (ev.topic || "").toLowerCase().includes(q);
			const matchData = JSON.stringify(ev.data).toLowerCase().includes(q);
			const matchDevice = ev.device_info
				? Boolean(
						ev.device_info.hostname?.toLowerCase().includes(q) ||
						ev.device_info.ip?.toLowerCase().includes(q) ||
						ev.device_info.mac.toLowerCase().includes(q) ||
						ev.device_info.class?.toLowerCase().includes(q) ||
						ev.device_info.iface?.toLowerCase().includes(q),
					)
				: false;
			const matchIface = ev.interface_info
				? Boolean(
						ev.interface_info.name?.toLowerCase().includes(q) ||
						ev.interface_info.ipv4?.toLowerCase().includes(q),
					)
				: false;
			const matchSvc = ev.service_info
				? Boolean(
						ev.service_info.id.toLowerCase().includes(q) ||
						ev.service_info.state.toLowerCase().includes(q),
					)
				: false;
			return matchKind || matchTopic || matchData || matchDevice || matchIface || matchSvc;
		});
	});

	const paginatedEvents = $derived.by(() => {
		const start = pageIndex * pageSize;
		return filteredEvents.slice(start, start + pageSize);
	});

	function inspectEvent(ev: SseEvent) {
		selectedEvent = ev;
		dialogOpen = true;
	}

	function exportEventsJson() {
		if (events.length === 0) {
			toast.info("No events to export");
			return;
		}
		const dataStr =
			"data:text/json;charset=utf-8," +
			encodeURIComponent(JSON.stringify(events, null, 2));
		const dlAnchor = document.createElement("a");
		dlAnchor.setAttribute("href", dataStr);
		dlAnchor.setAttribute(
			"download",
			`lanforge-events-${new Date().toISOString().slice(0, 19)}.json`
		);
		dlAnchor.click();
		toast.success(`Exported ${events.length} events to JSON file`);
	}
</script>

<DataTableCard
	title="System Event Stream"
	icon={ActivityIcon}
	total={filteredEvents.length}
	itemName="events"
	searchPlaceholder="Search event kind, MAC, IP, hostname, or attributes..."
	bind:searchQuery
	{loading}
	columns={5}
	minTableWidth="min-w-[700px]"
	bind:pageIndex
	bind:pageSize
	pageSizeOptions={[25, 50, 100, 200]}
	emptyMessage="No events captured yet. Incoming events from the daemon will stream here in real-time."
	emptyFilteredMessage="No events match the selected subsystem or search criteria."
>
	{#snippet filters()}
		<!-- Subsystem Selector -->
		<Select.Root
			type="single"
			value={selectedTopic}
			onValueChange={(val) => {
				selectedTopic = val ?? "";
				pageIndex = 0;
			}}
		>
			<Select.Trigger class="h-9 w-[160px] text-xs">
				{selectedTopic
					? `Subsystem: ${TOPIC_FILTERS.find((f) => f.value === selectedTopic)?.label ?? selectedTopic}`
					: "All Subsystems"}
			</Select.Trigger>
			<Select.Content>
				{#each TOPIC_FILTERS as filter (filter.value)}
					<Select.Item value={filter.value} class="text-xs">
						{filter.label}
					</Select.Item>
				{/each}
			</Select.Content>
		</Select.Root>

		<!-- Buffer Capacity Selector -->
		<Select.Root
			type="single"
			value={String(bufferLimit)}
			onValueChange={(val) => {
				if (val) bufferLimit = Number(val);
			}}
		>
			<Select.Trigger class="h-9 w-[130px] text-xs">
				Buffer: {bufferLimit}
			</Select.Trigger>
			<Select.Content>
				{#each BUFFER_OPTIONS as opt (opt.value)}
					<Select.Item value={opt.value} class="text-xs">
						{opt.label}
					</Select.Item>
				{/each}
			</Select.Content>
		</Select.Root>
	{/snippet}

	{#snippet actions()}
		<!-- Live Stream Toggle -->
		<Button
			variant={isLive ? "outline" : "default"}
			size="sm"
			class="h-9 gap-1.5 text-xs"
			onclick={onToggleLive}
		>
			{#if isLive}
				<PauseIcon class="size-3.5 text-amber-500" />
				<span>Pause Feed</span>
			{:else}
				<PlayIcon class="size-3.5 text-emerald-500" />
				<span>Resume Live</span>
			{/if}
		</Button>

		<!-- Refresh / Reload History -->
		<Button
			variant="outline"
			size="sm"
			class="h-9 gap-1.5 text-xs"
			onclick={onRefreshHistory}
			disabled={loading}
		>
			<RefreshCwIcon class="size-3.5 {loading ? 'animate-spin' : ''}" />
			<span class="hidden sm:inline">Replay</span>
		</Button>

		<!-- Export JSON -->
		<Button
			variant="outline"
			size="sm"
			class="h-9 gap-1.5 text-xs"
			onclick={exportEventsJson}
			disabled={events.length === 0}
		>
			<DownloadIcon class="size-3.5" />
			<span class="hidden sm:inline">Export</span>
		</Button>

		<!-- Clear Buffer -->
		<Button
			variant="ghost"
			size="sm"
			class="h-9 gap-1.5 text-xs text-muted-foreground hover:text-destructive"
			onclick={onClearBuffer}
			disabled={events.length === 0}
		>
			<Trash2Icon class="size-3.5" />
			<span class="hidden sm:inline">Clear</span>
		</Button>
	{/snippet}

	{#snippet header()}
		<Table.Head class="w-[95px] sm:w-[105px] text-xs font-semibold">Time</Table.Head>
		<Table.Head class="w-[95px] sm:w-[110px] text-xs font-semibold">Subsystem</Table.Head>
		<Table.Head class="w-[140px] sm:w-[170px] text-xs font-semibold">Event Kind</Table.Head>
		<Table.Head class="text-xs font-semibold">Description / Target</Table.Head>
		<Table.Head class="w-[50px] text-right text-xs font-semibold">Inspect</Table.Head>
	{/snippet}

	{#each paginatedEvents as ev (ev.id)}
		<Table.Row class="hover:bg-muted/30 transition-colors group">
			<!-- Time Column -->
			<Table.Cell class="font-mono text-xs whitespace-nowrap w-[95px] sm:w-[105px]" title={formatFullDate(ev.ts)}>
				<div class="flex items-center gap-1.5 text-muted-foreground">
					<ClockIcon class="size-3 text-muted-foreground/60 shrink-0" />
					<span>{formatTime(ev.ts)}</span>
				</div>
			</Table.Cell>

			<!-- Subsystem Badge -->
			<Table.Cell class="whitespace-nowrap w-[95px] sm:w-[110px]">
				<Badge
					variant="outline"
					class="text-[11px] font-mono uppercase tracking-wider {getTopicBadgeClass(ev.topic)}"
				>
					{ev.topic || "system"}
				</Badge>
			</Table.Cell>

			<!-- Kind -->
			<Table.Cell class="font-mono text-xs font-medium text-foreground whitespace-nowrap w-[140px] sm:w-[170px]">
				{ev.kind}
			</Table.Cell>

			<!-- Formatted Description & Context -->
			<Table.Cell class="text-xs py-2 min-w-0">
				<div class="flex flex-col gap-1 min-w-0">
					<!-- Primary Description -->
					<span class="text-foreground font-medium break-words">
						{formatEventPayload(ev.data, ev.kind, ev.device_info, ev.interface_info, ev.service_info)}
					</span>

					<!-- Context Badges / Sub-details -->
					{#if ev.device_info}
						<div class="flex flex-wrap items-center gap-1.5 text-[11px]">
							{#if ev.device_info.hostname}
								<span class="text-foreground/90 font-medium">{ev.device_info.hostname}</span>
							{/if}
							{#if ev.device_info.ip}
								<span class="font-mono text-muted-foreground">{ev.device_info.ip}</span>
							{/if}
							<span class="font-mono text-[10px] text-muted-foreground/75 bg-muted/60 px-1 py-0.5 rounded">
								{ev.device_info.mac}
							</span>
							{#if ev.device_info.is_static}
								<Badge variant="outline" class="text-[10px] px-1 py-0 border-amber-500/30 text-amber-500 dark:text-amber-400 bg-amber-500/10">
									Static
								</Badge>
							{/if}
							{#if ev.device_info.iface}
								<Badge variant="secondary" class="text-[10px] px-1 py-0 font-mono">
									{ev.device_info.iface}
								</Badge>
							{/if}
						</div>
					{:else if ev.interface_info}
						<div class="flex flex-wrap items-center gap-1.5 text-[11px]">
							<span class="font-mono font-medium text-foreground">{ev.interface_info.name || `Index #${ev.interface_info.ifindex}`}</span>
							{#if ev.interface_info.ipv4}
								<Badge variant="secondary" class="text-[10px] font-mono px-1 py-0">
									{ev.interface_info.ipv4}
								</Badge>
							{/if}
							{#if ev.interface_info.gua}
								<span class="font-mono text-[10px] text-muted-foreground truncate max-w-[200px]" title={ev.interface_info.gua}>
									{ev.interface_info.gua}
								</span>
							{/if}
						</div>
					{:else if ev.service_info}
						<div class="flex items-center gap-1.5 text-[11px]">
							<Badge variant="secondary" class="text-[10px] px-1 py-0 font-mono">
								{ev.service_info.id}
							</Badge>
							<span class="text-muted-foreground">State: {ev.service_info.state}</span>
							{#if ev.service_info.uptime_secs > 0}
								<span class="text-muted-foreground">({Math.floor(ev.service_info.uptime_secs / 60)}m uptime)</span>
							{/if}
						</div>
					{/if}
				</div>
			</Table.Cell>

			<!-- Inspect Action -->
			<Table.Cell class="text-right w-[50px]">
				<Button
					variant="ghost"
					size="icon"
					class="size-7 text-muted-foreground hover:text-foreground"
					onclick={() => inspectEvent(ev)}
					title="Inspect raw event JSON"
				>
					<EyeIcon class="size-3.5" />
				</Button>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>

<!-- Event Inspector Dialog -->
<EventDetailDialog bind:open={dialogOpen} event={selectedEvent} />
