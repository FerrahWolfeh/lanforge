<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import * as DropdownMenu from "$lib/components/ui/dropdown-menu";
	import * as Empty from "$lib/components/ui/empty";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { toast } from "svelte-sonner";

	// Icons
	import ServerIcon from "@lucide/svelte/icons/server";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import MoreHorizontalIcon from "@lucide/svelte/icons/more-horizontal";
	import SearchIcon from "@lucide/svelte/icons/search";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";
	import ChevronDownIcon from "@lucide/svelte/icons/chevron-down";

	import { dnsUpstreamClear, dnsUpstreamAdd } from "$lib/api/client";
	import type { DnsUpstreamEntry } from "$lib/api/types";

	let {
		loading = true,
		upstreams = [],
		onAddUpstream = () => {},
		onRemoveUpstream = () => {},
		onOpenDigModal = () => {},
		onReloadAll = async () => {},
	}: {
		loading?: boolean;
		upstreams?: DnsUpstreamEntry[];
		onAddUpstream?: () => void;
		onRemoveUpstream?: (item: DnsUpstreamEntry) => void;
		onOpenDigModal?: () => void;
		onReloadAll?: () => Promise<void>;
	} = $props();

	let applyingPreset = $state(false);

	const PRESETS = [
		{
			id: "quad9",
			name: "Quad9 (Malware Block)",
			desc: "Swiss privacy-first resolver with malware and phishing protection",
			v4: ["9.9.9.9", "149.112.112.112"],
			v6: ["2620:fe::fe", "2620:fe::9"],
		},
		{
			id: "cloudflare",
			name: "Cloudflare 1.1.1.1",
			desc: "Ultra-fast Anycast network with strict privacy",
			v4: ["1.1.1.1", "1.0.0.1"],
			v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"],
		},
		{
			id: "google",
			name: "Google Public DNS",
			desc: "Resilient Anycast global DNS infrastructure",
			v4: ["8.8.8.8", "8.8.4.4"],
			v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"],
		},
		{
			id: "adguard",
			name: "AdGuard DNS (Adblock)",
			desc: "Upstream ad-blocking and tracker sinkholing",
			v4: ["94.140.14.14", "94.140.15.15"],
			v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
		},
	];

	function getUpstreamAddr(u: DnsUpstreamEntry): string {
		if (typeof u.addr === "string") return u.addr;
		if (u.addr && typeof u.addr === "object" && (u.addr as any).addr) {
			return (u.addr as any).addr;
		}
		if (typeof u.target === "string") return u.target;
		if (typeof u.url === "string") return u.url;
		return String(u.target ?? u.addr ?? u.url ?? "");
	}

	function getUpstreamProtocol(u: DnsUpstreamEntry): string {
		if (u.protocol) return u.protocol.toUpperCase();
		if (u.url?.startsWith("https://")) return "DOH";
		if (u.url?.startsWith("tls://")) return "DOT";
		return "UDP";
	}

	function getUpstreamLatency(u: DnsUpstreamEntry): string {
		if (u.rtt_ewma_us !== undefined && u.rtt_ewma_us !== null) {
			const ms = (u.rtt_ewma_us / 1000).toFixed(1);
			return `${ms} ms`;
		}
		if (u.latency_ms !== undefined) return `${u.latency_ms} ms`;
		return "-";
	}

	async function applyPreset(preset: typeof PRESETS[0]) {
		applyingPreset = true;
		try {
			await dnsUpstreamClear();
			for (const addr of [...preset.v4, ...preset.v6]) {
				await dnsUpstreamAdd({ addr, protocol: "udp" });
			}
			toast.success(`Applied ${preset.name} preset with 4 dual-stack upstreams`);
			await onReloadAll();
		} catch (err: any) {
			toast.error(`Failed to apply preset: ${err.message || String(err)}`);
		} finally {
			applyingPreset = false;
		}
	}

	async function clearAll() {
		if (
			!confirm(
				"Are you sure you want to clear all upstream DNS servers? Non-local queries will return REFUSED.",
			)
		)
			return;
		try {
			await dnsUpstreamClear();
			toast.success("Cleared all upstream servers");
			await onReloadAll();
		} catch (err: any) {
			toast.error(`Failed to clear upstreams: ${err.message || String(err)}`);
		}
	}

	const displayUpstreams = $derived(upstreams ?? []);
</script>

<Card.Root class="flex flex-col overflow-hidden">
	<Card.Header class="pb-3 border-b border-border/50">
		<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div class="flex items-center gap-2">
				<ServerIcon class="size-4 text-indigo-400" />
				<Card.Title class="text-base">Upstream DNS Resolvers</Card.Title>
				<Badge variant="outline" class="font-mono text-[10px]">
					{displayUpstreams.length}
				</Badge>
			</div>

			<div class="flex flex-wrap items-center gap-1.5 sm:gap-2">
				<!-- Presets Dropdown -->
				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Button
								size="sm"
								variant="outline"
								{...props}
								class="gap-1.5 text-xs h-8"
								disabled={applyingPreset}
							>
								<SparklesIcon class="size-3.5 text-amber-400" />
								<span>Presets</span>
								<ChevronDownIcon class="size-3 opacity-60" />
							</Button>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content align="end" class="w-60 text-xs">
						<DropdownMenu.Group>
							<DropdownMenu.GroupHeading>
								Dual-Stack Anycast Presets
							</DropdownMenu.GroupHeading>
							{#each PRESETS as p (p.id)}
								<DropdownMenu.Item onclick={() => applyPreset(p)} class="cursor-pointer flex flex-col items-start gap-0.5 py-1.5">
									<span class="font-semibold text-foreground">{p.name}</span>
									<span class="text-[10px] text-muted-foreground">{p.desc}</span>
								</DropdownMenu.Item>
							{/each}
						</DropdownMenu.Group>
						<DropdownMenu.Separator />
						<DropdownMenu.Item onclick={clearAll} class="text-rose-400 cursor-pointer">
							<Trash2Icon class="size-3 mr-1.5" />
							Clear All Upstreams
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>

				<!-- Interactive Dig Modal Trigger Button -->
				<Button
					size="sm"
					variant="outline"
					onclick={onOpenDigModal}
					class="text-xs h-8 gap-1.5"
				>
					<ZapIcon data-icon="inline-start" class="text-amber-400 size-3.5" />
					Dig
				</Button>

				<!-- Add Upstream Button -->
				<Button size="sm" onclick={onAddUpstream} class="text-xs h-8 gap-1.5">
					<PlusIcon data-icon="inline-start" />
					Add
				</Button>
			</div>
		</div>
	</Card.Header>

	<Card.Content class="p-0">
		{#if loading}
			<div class="flex flex-col gap-3 p-4 sm:p-6">
				{#each { length: 3 } as _, i (i)}
					<Skeleton class="h-10 w-full" />
				{/each}
			</div>
		{:else if displayUpstreams.length === 0}
			<div class="flex flex-col items-center justify-center p-6 sm:p-8 text-center">
				<ServerIcon class="size-8 text-muted-foreground/40 mb-2" />
				<p class="text-sm font-medium text-foreground">No Upstream Servers Configured</p>
				<p class="text-xs text-muted-foreground mt-1 max-w-xs">
					Queries for external domains will return REFUSED until upstream servers are added.
				</p>
				<div class="flex flex-wrap items-center justify-center gap-2 mt-4">
					<Button size="sm" variant="outline" onclick={() => applyPreset(PRESETS[0])}>
						<SparklesIcon class="size-3.5 text-amber-400 mr-1" />
						Apply Quad9 Default
					</Button>
					<Button size="sm" onclick={onAddUpstream}>
						Add Custom Upstream
					</Button>
				</div>
			</div>
		{:else}
			<div class="max-h-[380px] overflow-x-auto">
				<Table.Root class="min-w-[500px]">
					<Table.Header class="sticky top-0 z-10 bg-muted/90 backdrop-blur">
						<Table.Row class="hover:bg-transparent">
							<Table.Head>Server Address / URL</Table.Head>
							<Table.Head>Protocol</Table.Head>
							<Table.Head>Target Domain</Table.Head>
							<Table.Head>Latency</Table.Head>
							<Table.Head>Status</Table.Head>
							<Table.Head class="text-right w-[80px]">Actions</Table.Head>
						</Table.Row>
					</Table.Header>
					<Table.Body class="font-mono text-xs">
						{#each displayUpstreams as item, i (getUpstreamAddr(item) + i)}
							<Table.Row class="hover:bg-muted/30">
								<Table.Cell class="font-semibold text-foreground font-mono">
									{getUpstreamAddr(item)}
								</Table.Cell>
								<Table.Cell class="font-sans">
									<Badge
										variant="outline"
										class="text-[10px] uppercase font-mono px-1.5 py-0"
									>
										{getUpstreamProtocol(item)}
									</Badge>
								</Table.Cell>
								<Table.Cell class="text-muted-foreground font-sans">
									{item.domain || "Global (*)"}
								</Table.Cell>
								<Table.Cell class="text-emerald-400 font-medium font-mono">
									{getUpstreamLatency(item)}
								</Table.Cell>
								<Table.Cell class="font-sans">
									<div class="flex items-center gap-1.5">
										<span
											class="size-2 rounded-full bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
										></span>
										<span class="text-[11px] font-medium capitalize">
											{item.status || "Healthy"}
										</span>
									</div>
								</Table.Cell>
								<Table.Cell class="text-right font-sans">
									<DropdownMenu.Root>
										<DropdownMenu.Trigger
											class="h-7 w-7 inline-flex items-center justify-center rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors cursor-pointer"
										>
											<MoreHorizontalIcon class="h-4 w-4" />
										</DropdownMenu.Trigger>
										<DropdownMenu.Content align="end" class="w-44 text-xs">
											<DropdownMenu.Item
												onclick={onOpenDigModal}
												class="gap-2 cursor-pointer"
											>
												<SearchIcon class="h-3.5 w-3.5 text-sky-400" />
												Test Resolution (Dig)
											</DropdownMenu.Item>
											<DropdownMenu.Item
												onclick={() => {
													const addr = getUpstreamAddr(item);
													navigator.clipboard.writeText(addr);
													toast.success(`Copied upstream address ${addr}`);
												}}
												class="gap-2 cursor-pointer"
											>
												<CopyIcon class="h-3.5 w-3.5 text-muted-foreground" />
												Copy Address
											</DropdownMenu.Item>
											<DropdownMenu.Separator />
											<DropdownMenu.Item
												onclick={() => onRemoveUpstream(item)}
												class="gap-2 text-rose-500 cursor-pointer"
											>
												<Trash2Icon class="h-3.5 w-3.5" />
												Remove Upstream
											</DropdownMenu.Item>
										</DropdownMenu.Content>
									</DropdownMenu.Root>
								</Table.Cell>
							</Table.Row>
						{/each}
					</Table.Body>
				</Table.Root>
			</div>
		{/if}
	</Card.Content>
</Card.Root>
