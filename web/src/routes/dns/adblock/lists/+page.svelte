<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import ExternalLinkIcon from "@lucide/svelte/icons/external-link";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import SearchIcon from "@lucide/svelte/icons/search";
	import SparklesIcon from "@lucide/svelte/icons/sparkles";
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import { toast } from "svelte-sonner";
	import {
		dnsAdblockUrls,
		dnsAdblockUrlAdd,
		dnsAdblockUrlRemove,
		dnsAdblockReload,
	} from "$lib/api/client";
	import type { DnsAdblockUrlEntry } from "$lib/api/types";
	import DnsAdblockAddSourceDialog from "./components/DnsAdblockAddSourceDialog.svelte";

	let loading = $state(true);
	let sources = $state<DnsAdblockUrlEntry[]>([]);
	let searchQuery = $state("");
	let dialogOpen = $state(false);
	let copiedUrl = $state<string | null>(null);
	let updatingAll = $state(false);

	const PRESETS = [
		{
			title: "StevenBlack Unified",
			description: "Standard adware + malware blocking hosts list (~150k rules).",
			url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
			badge: "Recommended",
		},
		{
			title: "OISD Basic",
			description: "High-performance, false-positive resilient internet blocking (~250k rules).",
			url: "https://big.oisd.nl/domainswg",
			badge: "Popular",
		},
		{
			title: "Hägezi Multi Normal",
			description: "Balanced protection against tracker, phishing, and telemetry domains.",
			url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/multi.txt",
			badge: "Strict",
		},
		{
			title: "AdGuard Mobile & Tracking",
			description: "Curated AdGuard DNS tracking, in-app ad, and counter list.",
			url: "https://v.firebog.net/hosts/AdguardDNS.txt",
			badge: "AdGuard",
		},
		{
			title: "Windows SpyBlocker",
			description: "Disables telemetry, diagnostics, and background reporting in Windows.",
			url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt",
			badge: "Privacy",
		},
	];

	async function loadSources() {
		loading = true;
		try {
			const res = await dnsAdblockUrls();
			if (res) sources = res;
		} catch {
			toast.error("Failed to load adblock source URLs");
		} finally {
			loading = false;
		}
	}

	async function handleAddPreset(presetUrl: string, name: string) {
		const alreadyExists = sources.some((s) => s.url === presetUrl);
		if (alreadyExists) {
			toast.info(`"${name}" is already configured.`);
			return;
		}

		try {
			await dnsAdblockUrlAdd({
				url: presetUrl,
				kind: "blocklist",
			});
			toast.success(`Added preset "${name}"`);
			await loadSources();
		} catch (err: any) {
			toast.error(err?.message ?? `Failed to add "${name}"`);
		}
	}

	async function handleRemove(entry: DnsAdblockUrlEntry) {
		try {
			await dnsAdblockUrlRemove(entry);
			toast.success(`Removed list: ${entry.url}`);
			await loadSources();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to remove source URL");
		}
	}

	async function handleReload() {
		updatingAll = true;
		try {
			await dnsAdblockReload();
			toast.success("Triggered background list download & compilation");
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to update lists");
		} finally {
			setTimeout(() => {
				updatingAll = false;
			}, 1200);
		}
	}

	async function copyUrl(url: string) {
		try {
			await navigator.clipboard.writeText(url);
			copiedUrl = url;
			toast.success("Copied URL to clipboard");
			setTimeout(() => {
				copiedUrl = null;
			}, 2000);
		} catch {
			toast.error("Failed to copy URL");
		}
	}

	const filteredSources = $derived.by(() => {
		if (!searchQuery.trim()) return sources;
		const q = searchQuery.toLowerCase();
		return sources.filter(
			(s) => s.url.toLowerCase().includes(q) || s.kind.includes(q),
		);
	});

	onMount(() => {
		loadSources();
	});
</script>

<div class="space-y-6">
	<!-- Presets Showcase Section -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<SparklesIcon class="size-4 text-amber-500" />
					<Card.Title class="text-base font-semibold">
						Community Filter Presets (1-Click Install)
					</Card.Title>
				</div>
				<Badge variant="outline" class="text-xs">Pi-hole & AdGuard Ready</Badge>
			</div>
			<Card.Description class="text-xs">
				Instantly enable battle-tested community blocklists optimized for homelabs and single-board devices.
			</Card.Description>
		</Card.Header>

		<Card.Content class="p-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
			{#each PRESETS as p (p.url)}
				{@const installed = sources.some((s) => s.url === p.url)}
				<div class="flex flex-col justify-between p-3.5 rounded-lg border bg-card/60 gap-3">
					<div class="flex flex-col gap-1">
						<div class="flex items-center justify-between gap-2">
							<span class="font-semibold text-xs text-foreground">{p.title}</span>
							<Badge variant="secondary" class="text-[10px] px-1.5 py-0">
								{p.badge}
							</Badge>
						</div>
						<p class="text-[11px] text-muted-foreground line-clamp-2">
							{p.description}
						</p>
					</div>

					<div class="flex items-center justify-between pt-1 border-t border-border/40">
						<span class="text-[10px] font-mono text-muted-foreground truncate max-w-[170px]" title={p.url}>
							{p.url.replace(/^https?:\/\//, "")}
						</span>

						{#if installed}
							<Badge variant="outline" class="text-[10px] bg-emerald-500/10 text-emerald-600 border-emerald-500/20 gap-1">
								<CheckIcon class="size-3" />
								Active
							</Badge>
						{:else}
							<Button
								variant="outline"
								size="sm"
								class="h-7 text-xs px-2.5"
								onclick={() => handleAddPreset(p.url, p.title)}
							>
								<PlusIcon class="size-3" />
								Add List
							</Button>
						{/if}
					</div>
				</div>
			{/each}
		</Card.Content>
	</Card.Root>

	<!-- Configured Source Lists Table -->
	<Card.Root>
		<Card.Header class="pb-3 border-b border-border/50">
			<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
				<div>
					<div class="flex items-center gap-2">
						<ShieldIcon class="size-4 text-primary" />
						<Card.Title class="text-base font-semibold">
							Configured Source Lists ({sources.length})
						</Card.Title>
					</div>
					<Card.Description class="text-xs">
						Remote lists fetched periodically and compiled into your local memory-mapped FST blocklist.
					</Card.Description>
				</div>

				<div class="flex items-center gap-2">
					<div class="relative w-48 sm:w-60">
						<SearchIcon class="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
						<Input
							type="text"
							placeholder="Search sources..."
							class="pl-8 h-8 text-xs font-mono"
							bind:value={searchQuery}
						/>
					</div>

					<Button
						variant="outline"
						size="sm"
						onclick={handleReload}
						disabled={updatingAll}
						class="h-8 gap-1.5 text-xs"
					>
						<RefreshCwIcon class="size-3.5 {updatingAll ? 'animate-spin' : ''}" />
						Update All
					</Button>

					<Button
						size="sm"
						onclick={() => (dialogOpen = true)}
						class="h-8 gap-1.5 text-xs"
					>
						<PlusIcon class="size-3.5" />
						Add Source
					</Button>
				</div>
			</div>
		</Card.Header>

		<Card.Content class="p-0">
			<Table.Root>
				<Table.Header>
					<Table.Row class="hover:bg-transparent">
						<Table.Head class="w-[60%]">Source List URL</Table.Head>
						<Table.Head class="w-[15%]">Type</Table.Head>
						<Table.Head class="w-[15%]">Status</Table.Head>
						<Table.Head class="w-[10%] text-right">Actions</Table.Head>
					</Table.Row>
				</Table.Header>

				<Table.Body>
					{#if loading && sources.length === 0}
						{#each Array(4) as _}
							<Table.Row>
								<Table.Cell><Skeleton class="h-4 w-72" /></Table.Cell>
								<Table.Cell><Skeleton class="h-4 w-16" /></Table.Cell>
								<Table.Cell><Skeleton class="h-4 w-16" /></Table.Cell>
								<Table.Cell class="text-right"><Skeleton class="h-4 w-12 ml-auto" /></Table.Cell>
							</Table.Row>
						{/each}
					{:else if filteredSources.length === 0}
						<Table.Row>
							<Table.Cell colspan={4} class="h-32 text-center text-muted-foreground text-xs">
								{#if searchQuery}
									No source lists match your search query.
								{:else}
									No adblock lists configured yet. Click "Add Source" or select a preset above.
								{/if}
							</Table.Cell>
						</Table.Row>
					{:else}
						{#each filteredSources as source, idx (source.url + idx)}
							<Table.Row class="hover:bg-muted/40 transition-colors group">
								<!-- URL -->
								<Table.Cell class="font-mono text-xs">
									<div class="flex items-center gap-2 max-w-[500px]">
										<span class="truncate text-foreground font-medium" title={source.url}>
											{source.url}
										</span>
										<button
											type="button"
											onclick={() => copyUrl(source.url)}
											class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded text-muted-foreground"
											title="Copy URL"
										>
											{#if copiedUrl === source.url}
												<CheckIcon class="size-3.5 text-emerald-500" />
											{:else}
												<CopyIcon class="size-3.5" />
											{/if}
										</button>
									</div>
								</Table.Cell>

								<!-- Type -->
								<Table.Cell>
									{#if source.kind === "blocklist"}
										<Badge variant="outline" class="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20 text-[11px] font-mono">
											Blocklist
										</Badge>
									{:else}
										<Badge variant="outline" class="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 text-[11px] font-mono">
											Allowlist
										</Badge>
									{/if}
								</Table.Cell>

								<!-- Status -->
								<Table.Cell>
									<Badge variant="outline" class="gap-1 font-mono text-[11px]">
										<span class="size-1.5 rounded-full bg-emerald-500"></span>
										Active
									</Badge>
								</Table.Cell>

								<!-- Actions -->
								<Table.Cell class="text-right">
									<div class="flex items-center justify-end gap-1">
										<a
											href={source.url}
											target="_blank"
											rel="noopener noreferrer"
											class="p-1.5 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
											title="Open URL in new tab"
										>
											<ExternalLinkIcon class="size-3.5" />
										</a>

										<Button
											variant="ghost"
											size="sm"
											onclick={() => handleRemove(source)}
											class="size-7 p-0 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
											title="Remove list"
										>
											<Trash2Icon class="size-3.5" />
										</Button>
									</div>
								</Table.Cell>
							</Table.Row>
						{/each}
					{/if}
				</Table.Body>
			</Table.Root>
		</Card.Content>
	</Card.Root>
</div>

<!-- Add Custom Source Dialog -->
<DnsAdblockAddSourceDialog
	bind:open={dialogOpen}
	onAdded={() => loadSources()}
/>
