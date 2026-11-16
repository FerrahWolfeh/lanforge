<script lang="ts">
	import { auth } from "$lib/stores/auth.svelte";
	import * as Table from "$lib/components/ui/table";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import * as Select from "$lib/components/ui/select";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Input } from "$lib/components/ui/input";
	import * as Card from "$lib/components/ui/card";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import RadioIcon from "@lucide/svelte/icons/radio";
	import PauseIcon from "@lucide/svelte/icons/pause";
	import PlayIcon from "@lucide/svelte/icons/play";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SearchIcon from "@lucide/svelte/icons/search";
	import EyeIcon from "@lucide/svelte/icons/eye";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import SnowflakeIcon from "@lucide/svelte/icons/snowflake";
	import { toast } from "svelte-sonner";
	import { dnsBlock, dnsAllow } from "$lib/api/client";
	import type { DnsQueryLogEntry, FilterMatch } from "$lib/api/types";

	// Block, allow and rewrites need dns_write.
	const canDnsWrite = $derived(auth.can("dns_write"));

	let {
		entries = [],
		isPaused = false,
		isConnected = true,
		bufferLimit = 200,
		onTogglePause = () => {},
		onClearBuffer = () => {},
		onInspect = (entry: DnsQueryLogEntry) => {},
		onAddRewrite = (domain: string, target: string) => {},
		onBufferLimitChange = (limit: number) => {},
	}: {
		entries: DnsQueryLogEntry[];
		isPaused: boolean;
		isConnected: boolean;
		bufferLimit: number;
		onTogglePause: () => void;
		onClearBuffer: () => void;
		onInspect: (entry: DnsQueryLogEntry) => void;
		onAddRewrite: (domain: string, target: string) => void;
		onBufferLimitChange: (limit: number) => void;
	} = $props();

	let filterText = $state("");
	let isHovered = $state(false);
	let freezeOnHover = $state(true);
	let frozenEntries = $state<DnsQueryLogEntry[] | null>(null);
	let copiedItem = $state<string | null>(null);

	const typeVariants: Record<string, string> = {
		A: "bg-muted text-muted-foreground border-border",
		AAAA: "bg-muted text-muted-foreground border-border",
		CNAME: "bg-muted text-muted-foreground border-border",
		PTR: "bg-muted text-muted-foreground border-border",
		TXT: "bg-muted text-muted-foreground border-border",
		MX: "bg-muted text-muted-foreground border-border",
		NS: "bg-muted text-muted-foreground border-border",
		SOA: "bg-muted text-muted-foreground border-border",
		SRV: "bg-muted text-muted-foreground border-border",
		HTTPS: "bg-muted text-muted-foreground border-border",
		SVCB: "bg-muted text-muted-foreground border-border",
	};

	function cleanDomain(raw: string): string {
		if (!raw) return "";
		return raw.trim().replace(/\.$/, "");
	}

	function cleanAnswer(raw?: string | null): string {
		if (!raw) return "—";
		return raw
			.replace(/^"|"$/g, "")
			.replace(/^(A|AAAA|CNAME|PTR|NS)\((.*)\)$/, "$2")
			.trim()
			.replace(/\.$/, "");
	}

	function formatTime(ts: number): string {
		if (!ts) return "—";
		const ms = ts < 1e11 ? ts * 1000 : ts;
		const d = new Date(ms);
		return d.toLocaleTimeString(undefined, {
			hour12: false,
			hour: "2-digit",
			minute: "2-digit",
			second: "2-digit",
		});
	}

	function formatLatency(us: number): string {
		if (us === 0) return "0 ms";
		if (us < 1000) return `${us} µs`;
		return `${(us / 1000).toFixed(1)} ms`;
	}

	async function copyToClipboard(text: string, label: string) {
		try {
			await navigator.clipboard.writeText(text);
			copiedItem = text;
			toast.success(`Copied ${label} to clipboard`);
			setTimeout(() => {
				copiedItem = null;
			}, 2000);
		} catch {
			toast.error("Failed to copy to clipboard");
		}
	}

	async function handleQuickBlock(domain: string) {
		const target = cleanDomain(domain);
		try {
			await dnsBlock(target);
			toast.success(`Added ${target} to adblock black list`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to block domain");
		}
	}

	async function handleQuickAllow(domain: string) {
		const target = cleanDomain(domain);
		try {
			await dnsAllow(target);
			toast.success(`Added ${target} to allowlist`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to allow domain");
		}
	}

	function getResultBadge(result: string, cached: boolean, filter?: FilterMatch | null) {
		if (filter?.action === "allow") {
			return {
				label: "Allowed (@@)",
				class: "bg-success/10 text-success border-success/20",
			};
		}
		const lower = (result || "").toLowerCase();
		if (
			lower === "cachedblock" ||
			lower === "cached_block" ||
			(lower.includes("block") && cached)
		) {
			return {
				label: "Cached Block",
				class: "bg-warning/10 text-warning border-warning/20",
			};
		}
		if (lower.includes("block") || lower.includes("deny")) {
			return {
				label: "Blocked",
				class: "bg-danger/10 text-danger border-danger/20",
			};
		}
		if (lower === "rewritten" || lower.includes("rewrite")) {
			return {
				label: "Rewritten",
				class: "bg-selected text-selected-foreground border-transparent",
			};
		}
		if (lower === "local") {
			return {
				label: "Local",
				class: "bg-muted text-muted-foreground border-border",
			};
		}
		if (lower === "nxdomain") {
			return {
				label: "NXDomain",
				class: "bg-warning/10 text-warning border-warning/20",
			};
		}
		if (lower === "error") {
			return {
				label: "Error",
				class: "bg-danger/10 text-danger border-danger/20",
			};
		}
		if (cached || lower === "cached") {
			return {
				label: "Cached",
				class: "bg-success/10 text-success border-success/20",
			};
		}
		if (lower === "coalesced") {
			return {
				label: "Coalesced",
				class: "bg-info/10 text-info border-info/20",
			};
		}
		return {
			label: "Forwarded",
			class: "bg-muted text-muted-foreground border-border",
		};
	}

	function handleMouseEnter() {
		if (freezeOnHover && !isPaused) {
			isHovered = true;
			frozenEntries = [...entries];
		}
	}

	function handleMouseLeave() {
		isHovered = false;
		frozenEntries = null;
	}

	// Active dataset respects freeze on hover
	const displayEntries = $derived.by(() => {
		const source = (isHovered && frozenEntries) ? frozenEntries : entries;
		if (!filterText.trim()) return source;
		const q = filterText.toLowerCase().trim();
		return source.filter(
			(e) =>
				e.domain.toLowerCase().includes(q) ||
				e.src_ip.toLowerCase().includes(q) ||
				(e.src_hostname && e.src_hostname.toLowerCase().includes(q)) ||
				(e.src_mac && e.src_mac.toLowerCase().includes(q)) ||
				(e.answer && e.answer.toLowerCase().includes(q)),
		);
	});

	const bufferedNewCount = $derived.by(() => {
		if (isHovered && frozenEntries) {
			return Math.max(0, entries.length - frozenEntries.length);
		}
		return 0;
	});
</script>

<Card.Root class="overflow-hidden border">
	<!-- Live Control Header -->
	<Card.Header class="p-4 border-b border-border/50 bg-muted/20 space-y-3">
		<div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
			<div class="flex items-center gap-2.5">
				<div class="flex items-center gap-2">
					<RadioIcon
						class="size-4 {isConnected && !isPaused
							? 'text-success'
							: 'text-muted-foreground'}"
					/>
					<Card.Title class="text-sm font-semibold tracking-tight">
						Live Tail Feed
					</Card.Title>
				</div>
				<Badge
					variant="outline"
					class="font-mono text-xs px-2 py-0.5 {isConnected && !isPaused
						? 'border-success/30 bg-success/10 text-success'
						: 'border-border bg-secondary text-muted-foreground'}"
				>
					{isPaused ? "Paused" : isConnected ? "Streaming" : "Disconnected"}
				</Badge>

				{#if bufferedNewCount > 0}
					<Badge
						variant="secondary"
						class="font-mono text-xs bg-warning/10 text-warning border-warning/20"
					>
						+{bufferedNewCount} new buffered
					</Badge>
				{/if}
			</div>

			<div class="flex flex-wrap items-center gap-2">
				<!-- Search Filter -->
				<div class="relative w-full sm:w-56">
					<SearchIcon class="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
					<Input
						placeholder="Filter live stream..."
						class="pl-8 h-8 text-xs font-mono w-full"
						bind:value={filterText}
					/>
				</div>

				<!-- Buffer Size Selector -->
				<Select.Root
					type="single"
					value={String(bufferLimit)}
					onValueChange={(val) => onBufferLimitChange(Number(val) || 200)}
				>
					<Select.Trigger class="h-8 w-[105px] text-xs font-mono">
						Buffer: {bufferLimit}
					</Select.Trigger>
					<Select.Content>
						<Select.Item value="100" class="text-xs font-mono">100 items</Select.Item>
						<Select.Item value="200" class="text-xs font-mono">200 items</Select.Item>
						<Select.Item value="500" class="text-xs font-mono">500 items</Select.Item>
					</Select.Content>
				</Select.Root>

				<!-- Freeze on Hover Toggle Button -->
				<Button
					variant={freezeOnHover ? "secondary" : "ghost"}
					size="sm"
					class="h-8 text-xs gap-1.5 px-2.5 {isHovered ? 'border-warning/40 text-warning' : ''}"
					onclick={() => (freezeOnHover = !freezeOnHover)}
					title="Prevent incoming events from shifting the table when mouse is over rows"
				>
					<SnowflakeIcon class="size-3.5 {freezeOnHover ? 'text-primary' : 'text-muted-foreground'}" />
					<span class="hidden md:inline">Freeze on Hover</span>
				</Button>

				<!-- Pause / Resume Button -->
				<Button
					variant={isPaused ? "default" : "outline"}
					size="sm"
					class="h-8 text-xs gap-1.5 px-3"
					onclick={onTogglePause}
				>
					{#if isPaused}
						<PlayIcon class="size-3.5" />
						<span>Resume</span>
					{:else}
						<PauseIcon class="size-3.5" />
						<span>Pause</span>
					{/if}
				</Button>

				<!-- Clear Buffer Button -->
				<Button
					variant="ghost"
					size="sm"
					class="h-8 text-xs text-muted-foreground hover:text-foreground gap-1.5 px-2.5"
					onclick={onClearBuffer}
					title="Clear in-memory stream buffer"
				>
					<Trash2Icon class="size-3.5" />
					<span class="hidden sm:inline">Clear</span>
				</Button>
			</div>
		</div>
	</Card.Header>

	<!-- Live Table -->
	<div
		class="overflow-x-auto relative"
		role="region"
		aria-label="Live DNS query stream"
		onmouseenter={handleMouseEnter}
		onmouseleave={handleMouseLeave}
	>
		<Table.Root>
			<Table.Header>
				<Table.Row class="bg-muted/10 hover:bg-muted/10">
					<Table.Head class="w-[90px] text-xs">Time</Table.Head>
					<Table.Head class="w-[170px] text-xs">Client</Table.Head>
					<Table.Head class="w-[260px] text-xs">Domain Name</Table.Head>
					<Table.Head class="w-[75px] text-xs">Type</Table.Head>
					<Table.Head class="w-[110px] text-xs">Outcome</Table.Head>
					<Table.Head class="w-[90px] text-right text-xs">Latency</Table.Head>
					<Table.Head class="w-[50px] text-right text-xs">Actions</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#if displayEntries.length === 0}
					<Table.Row>
						<Table.Cell colspan={7} class="h-44 text-center">
							<div class="flex flex-col items-center justify-center gap-2 text-muted-foreground">
								<RadioIcon class="size-7 text-primary/40 animate-pulse" />
								<p class="text-sm font-medium">Listening for real-time DNS queries...</p>
								<p class="text-xs text-muted-foreground/80">
									Incoming network resolutions will stream live into this view buffer.
								</p>
							</div>
						</Table.Cell>
					</Table.Row>
				{:else}
					{#each displayEntries as entry, i (`live-${entry.timestamp}-${entry.src_ip}-${entry.domain}-${entry.qtype}-${i}`)}
						{@const domainClean = cleanDomain(entry.domain)}
						{@const answerClean = cleanAnswer(entry.answer)}
						{@const style = typeVariants[entry.qtype] || "bg-secondary text-secondary-foreground border-border"}
						{@const badgeInfo = getResultBadge(entry.result, entry.cached, entry.filter)}
						{@const isCoalesced = entry.result === "coalesced"}
						<Table.Row
							class="hover:bg-muted/50 transition-colors cursor-pointer group text-xs font-normal {entry.coalesce_id != null ? 'border-l-4 border-l-info/70' : ''}"
							onclick={() => onInspect(entry)}
						>
							<!-- Time -->
							<Table.Cell class="font-mono text-muted-foreground whitespace-nowrap">
								{formatTime(entry.timestamp)}
							</Table.Cell>

							<!-- Client -->
							<Table.Cell>
								{#if entry.src_hostname}
									<div class="flex flex-col min-w-0" title={`${entry.src_hostname} (${entry.src_ip})`}>
										<div class="flex items-center gap-1.5">
											<LaptopIcon class="size-3.5 text-primary shrink-0" />
											<span class="truncate max-w-[140px] font-medium text-foreground">
												{entry.src_hostname}
											</span>
										</div>
										<span class="text-xs font-mono text-muted-foreground truncate pl-5">
											{entry.src_ip}
										</span>
									</div>
								{:else}
									<div class="flex items-center gap-1.5" title={entry.src_ip}>
										<LaptopIcon class="size-3.5 text-muted-foreground shrink-0" />
										<span class="truncate max-w-[140px] font-mono text-foreground">
											{entry.src_ip}
										</span>
									</div>
								{/if}
							</Table.Cell>

							<!-- Domain Name -->
							<Table.Cell class="font-medium">
								<div class="flex items-center gap-1.5 {isCoalesced ? 'pl-2' : ''}">
									{#if isCoalesced}
										<span class="text-info font-mono text-xs shrink-0" title="Coalesced into in-flight query">↳</span>
									{/if}
									<span class="truncate max-w-[220px] font-mono text-foreground font-medium" title={domainClean}>
										{domainClean}
									</span>
									{#if entry.repeats > 1}
										<span
											class="shrink-0 rounded border border-border bg-muted px-1 font-mono text-xs text-muted-foreground"
											title={`${entry.repeats} identical queries from this client, folded into one line`}
										>
											×{entry.repeats}
										</span>
									{/if}
									<button
										type="button"
										onclick={(e) => {
											e.stopPropagation();
											copyToClipboard(domainClean, "domain name");
										}}
										class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded"
										title="Copy domain"
									>
										{#if copiedItem === domainClean}
											<CheckIcon class="size-3.5 text-success" />
										{:else}
											<CopyIcon class="size-3.5 text-muted-foreground" />
										{/if}
									</button>
								</div>
							</Table.Cell>

							<!-- Type -->
							<Table.Cell>
								<Badge variant="outline" class="px-2 py-0.5 text-xs font-mono border font-semibold {style}">
									{entry.qtype}
								</Badge>
							</Table.Cell>

							<!-- Outcome -->
							<Table.Cell>
								<div class="flex items-center gap-1.5 flex-wrap">
									<Badge
										variant="outline"
										class="px-2 py-0.5 text-xs font-mono border font-semibold {badgeInfo.class}"
										title={entry.filter?.rule ? `Rule: ${entry.filter.rule}` : undefined}
									>
										{badgeInfo.label}
									</Badge>
									{#if isCoalesced}
										<span class="text-xs text-info font-mono" title={`Batch #${entry.coalesce_id}`}>multiplex</span>
									{/if}
								</div>
							</Table.Cell>

							<!-- Latency -->
							<Table.Cell class="text-right font-mono text-muted-foreground">
								{formatLatency(entry.upstream_us)}
							</Table.Cell>

							<!-- Action Menu -->
							<Table.Cell class="text-right" onclick={(e) => e.stopPropagation()}>
								<DropdownMenu.Root>
									<DropdownMenu.Trigger
										class="size-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
									>
										<MoreHorizontalIcon class="size-4" />
									</DropdownMenu.Trigger>
									<DropdownMenu.Content align="end" class="w-44 text-xs">
										<DropdownMenu.Item onclick={() => onInspect(entry)} class="gap-2">
											<EyeIcon class="size-3.5 text-primary" />
											Inspect Log
										</DropdownMenu.Item>
										<DropdownMenu.Item onclick={() => copyToClipboard(domainClean, "domain")} class="gap-2">
											<CopyIcon class="size-3.5 text-muted-foreground" />
											Copy Domain
										</DropdownMenu.Item>
										<DropdownMenu.Item onclick={() => copyToClipboard(entry.src_ip, "client IP")} class="gap-2">
											<CopyIcon class="size-3.5 text-muted-foreground" />
											Copy Client IP
										</DropdownMenu.Item>
										{#if canDnsWrite}
										<DropdownMenu.Separator />
										<DropdownMenu.Item onclick={() => handleQuickBlock(domainClean)} class="gap-2 text-danger">
											<ShieldAlertIcon class="size-3.5" />
											Block Domain
										</DropdownMenu.Item>
										<DropdownMenu.Item onclick={() => handleQuickAllow(domainClean)} class="gap-2 text-success">
											<ShieldCheckIcon class="size-3.5" />
											Allow Domain
										</DropdownMenu.Item>
										<DropdownMenu.Item
											onclick={() => onAddRewrite(domainClean, answerClean !== "—" ? answerClean : "")}
											class="gap-2"
										>
											<ArrowRightLeftIcon class="size-3.5 text-warning" />
											Create Rewrite
										</DropdownMenu.Item>
										{/if}
									</DropdownMenu.Content>
								</DropdownMenu.Root>
							</Table.Cell>
						</Table.Row>
					{/each}
				{/if}
			</Table.Body>
		</Table.Root>
	</div>
</Card.Root>
