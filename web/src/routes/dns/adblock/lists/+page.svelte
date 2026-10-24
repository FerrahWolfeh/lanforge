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
	import ShieldIcon from "@lucide/svelte/icons/shield";
	import AlertCircleIcon from "@lucide/svelte/icons/alert-circle";
	import { toast } from "svelte-sonner";
	import {
		dnsAdblockUrls,
		dnsAdblockSources,
		dnsAdblockUrlAdd,
		dnsAdblockUrlRemove,
		dnsAdblockReload,
	} from "$lib/api/client";
	import type {
		AdblockSourceFormat,
		AdblockSourceStatus,
		DnsAdblockUrlEntry,
	} from "$lib/api/types";
	import DnsAdblockAddSourceDialog from "./components/DnsAdblockAddSourceDialog.svelte";
	import DnsAdblockPresetsPopover from "./components/DnsAdblockPresetsPopover.svelte";

	interface MergedSource {
		id?: number | null;
		source_id?: number;
		name?: string | null;
		url: string;
		kind: "blocklist" | "allowlist";
		format: AdblockSourceFormat;
		format_detected?: AdblockSourceFormat | null;
		rules_count: number;
		exceptions_count: number;
		unsupported_count: number;
		last_success?: number | null;
		consecutive_failures: number;
		last_error?: string | null;
	}

	let loading = $state(true);
	let rawUrls = $state<DnsAdblockUrlEntry[]>([]);
	let sources = $state<MergedSource[]>([]);
	let searchQuery = $state("");
	let dialogOpen = $state(false);
	let copiedUrl = $state<string | null>(null);
	let updatingAll = $state(false);

	function formatTimestamp(ts?: number | null): string {
		if (!ts) return "Pending";
		const ms = ts < 1e11 ? ts * 1000 : ts;
		const date = new Date(ms);
		return date.toLocaleDateString(undefined, {
			month: "short",
			day: "numeric",
			hour: "2-digit",
			minute: "2-digit",
		});
	}

	async function loadSources() {
		loading = true;
		try {
			const [urlsRes, statusRes] = await Promise.allSettled([
				dnsAdblockUrls(),
				dnsAdblockSources(),
			]);

			const urls = urlsRes.status === "fulfilled" ? urlsRes.value : [];
			const statuses =
				statusRes.status === "fulfilled" && statusRes.value?.sources
					? statusRes.value.sources
					: [];

			rawUrls = urls;

			const statusMap = new Map<string, AdblockSourceStatus>();
			for (const st of statuses) {
				statusMap.set(st.url, st);
			}

			sources = urls.map((u) => {
				const st = statusMap.get(u.url);
				return {
					id: u.id,
					source_id: st?.source_id,
					name: u.name ?? st?.name ?? null,
					url: u.url,
					kind: u.kind,
					format: u.format ?? st?.format ?? "auto",
					format_detected: st?.format_detected,
					rules_count: st?.rules_count ?? 0,
					exceptions_count: st?.exceptions_count ?? 0,
					unsupported_count: st?.unsupported_count ?? 0,
					last_success: st?.last_success,
					consecutive_failures: st?.consecutive_failures ?? 0,
					last_error: st?.last_error,
				};
			});
		} catch {
			toast.error("Failed to load adblock source lists");
		} finally {
			loading = false;
		}
	}

	async function handleAddPreset(
		presetUrl: string,
		name: string,
		format?: AdblockSourceFormat,
	) {
		const alreadyExists = sources.some((s) => s.url === presetUrl);
		if (alreadyExists) {
			toast.info(`"${name}" is already configured.`);
			return;
		}

		try {
			await dnsAdblockUrlAdd({
				name,
				url: presetUrl,
				kind: "blocklist",
				format: format ?? "auto",
			});
			toast.success(`Added preset "${name}". Compiling rules in background...`);
			await loadSources();
			dnsAdblockReload().then(() => {
				setTimeout(loadSources, 1500);
				setTimeout(loadSources, 3500);
			}).catch(() => {});
		} catch (err: any) {
			toast.error(err?.message ?? `Failed to add "${name}"`);
		}
	}

	async function handleRemove(entry: MergedSource) {
		try {
			await dnsAdblockUrlRemove({
				id: entry.id,
				url: entry.url,
				kind: entry.kind,
				format: entry.format,
			});
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
			setTimeout(async () => {
				await loadSources();
			}, 1500);
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
			(s) =>
				(s.name && s.name.toLowerCase().includes(q)) ||
				s.url.toLowerCase().includes(q) ||
				s.kind.includes(q) ||
				s.format.toLowerCase().includes(q) ||
				(s.format_detected && s.format_detected.toLowerCase().includes(q)),
		);
	});

	onMount(() => {
		loadSources();
	});
</script>

<div class="space-y-6">
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
						Remote lists fetched periodically with HTTP caching and compiled into your zero-copy FST blocklist.
					</Card.Description>
				</div>

				<div class="flex flex-wrap items-center gap-2">
					<div class="relative w-full sm:w-52">
						<SearchIcon class="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
						<Input
							type="text"
							placeholder="Search sources..."
							class="pl-8 h-8 text-xs font-mono"
							bind:value={searchQuery}
						/>
					</div>

					<DnsAdblockPresetsPopover sources={rawUrls} onAdd={handleAddPreset} />

					<Button
						variant="outline"
						size="sm"
						onclick={handleReload}
						disabled={updatingAll}
						class="h-8 gap-1.5 text-xs"
					>
						<RefreshCwIcon class="size-3.5 {updatingAll ? 'animate-spin' : ''}" />
						<span class="hidden sm:inline">Update All</span>
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
						<Table.Head class="w-[40%]">Source List URL</Table.Head>
						<Table.Head class="w-[12%]">Purpose</Table.Head>
						<Table.Head class="w-[14%]">Format</Table.Head>
						<Table.Head class="w-[16%]">Rules</Table.Head>
						<Table.Head class="w-[10%]">Status</Table.Head>
						<Table.Head class="w-[8%] text-right">Actions</Table.Head>
					</Table.Row>
				</Table.Header>

				<Table.Body>
					{#if loading && sources.length === 0}
						{#each Array(4) as _}
							<Table.Row>
								<Table.Cell><Skeleton class="h-4 w-72" /></Table.Cell>
								<Table.Cell><Skeleton class="h-4 w-16" /></Table.Cell>
								<Table.Cell><Skeleton class="h-4 w-16" /></Table.Cell>
								<Table.Cell><Skeleton class="h-4 w-20" /></Table.Cell>
								<Table.Cell><Skeleton class="h-4 w-16" /></Table.Cell>
								<Table.Cell class="text-right"><Skeleton class="h-4 w-12 ml-auto" /></Table.Cell>
							</Table.Row>
						{/each}
					{:else if filteredSources.length === 0}
						<Table.Row>
							<Table.Cell colspan={6} class="h-32 text-center text-muted-foreground text-xs">
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
								<!-- Name & URL -->
								<Table.Cell class="text-xs">
									<div class="flex flex-col gap-0.5 max-w-[380px]">
										{#if source.name}
											<span class="text-foreground font-semibold text-xs tracking-tight truncate">
												{source.name}
											</span>
										{/if}
										<div class="flex items-center gap-2">
											<span class="truncate font-mono {source.name ? 'text-[11px] text-muted-foreground' : 'text-foreground font-medium'}" title={source.url}>
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
									</div>
								</Table.Cell>

								<!-- Type / Purpose -->
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

								<!-- Format -->
								<Table.Cell>
									<div class="flex items-center gap-1.5 flex-wrap">
										<Badge variant="secondary" class="font-mono text-[10px] uppercase">
											{source.format}
										</Badge>
										{#if source.format_detected && source.format_detected !== source.format}
											<span class="text-[10px] text-muted-foreground font-mono">
												→ {source.format_detected}
											</span>
										{/if}
									</div>
								</Table.Cell>

								<!-- Rules Counts -->
								<Table.Cell>
									<div class="flex flex-col text-xs">
										{#if source.rules_count === 0 && !source.last_success}
											<span class="font-mono text-[11px] text-muted-foreground animate-pulse">
												Pending download...
											</span>
										{:else if source.kind === "allowlist"}
											<span class="font-mono font-medium text-emerald-600 dark:text-emerald-400">
												{source.rules_count.toLocaleString()} allowed
											</span>
										{:else}
											<span class="font-mono font-medium text-foreground">
												{source.rules_count.toLocaleString()} blocked
											</span>
										{/if}
										{#if source.exceptions_count > 0}
											<span class="text-[10px] font-mono text-emerald-600 dark:text-emerald-400">
												+{source.exceptions_count.toLocaleString()} exceptions
											</span>
										{/if}
										{#if source.unsupported_count > 0}
											<span class="text-[10px] font-mono text-amber-600 dark:text-amber-400" title="{source.unsupported_count} unsupported modifiers/syntax rules ignored">
												{source.unsupported_count.toLocaleString()} unsupported
											</span>
										{/if}
									</div>
								</Table.Cell>

								<!-- Status -->
								<Table.Cell>
									{#if source.consecutive_failures > 0}
										<Badge
											variant="outline"
											class="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20 gap-1 font-mono text-[10px]"
											title={source.last_error ?? "Fetch failed"}
										>
											<AlertCircleIcon class="size-3 text-rose-500" />
											Fail ({source.consecutive_failures})
										</Badge>
									{:else if source.last_success}
										<Badge
											variant="outline"
											class="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 gap-1 font-mono text-[10px]"
											title="Last successful update: {formatTimestamp(source.last_success)}"
										>
											<span class="size-1.5 rounded-full bg-emerald-500"></span>
											OK
										</Badge>
									{:else}
										<Badge variant="outline" class="gap-1 font-mono text-[10px] text-amber-600 dark:text-amber-400 border-amber-500/20 bg-amber-500/10">
											<span class="size-1.5 rounded-full bg-amber-500 animate-pulse"></span>
											Pending
										</Badge>
									{/if}
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
