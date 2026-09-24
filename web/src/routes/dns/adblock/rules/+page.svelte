<script lang="ts">
	import { onMount } from "svelte";
	import * as Card from "$lib/components/ui/card";
	import * as Table from "$lib/components/ui/table";
	import * as Tabs from "$lib/components/ui/tabs";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import { Input } from "$lib/components/ui/input";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import ShieldAlertIcon from "@lucide/svelte/icons/shield-alert";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import SearchIcon from "@lucide/svelte/icons/search";
	import FileTextIcon from "@lucide/svelte/icons/file-text";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import PowerIcon from "@lucide/svelte/icons/power";
	import { toast } from "svelte-sonner";
	import {
		dnsAdblockAllowlist,
		dnsAllow,
		dnsUnallow,
		dnsAdblockRules,
		dnsAdblockRuleAdd,
		dnsAdblockRuleRemove,
		dnsAdblockRuleStatus,
	} from "$lib/api/client";
	import type { AllowlistEntry, AdblockRuleEntry } from "$lib/api/types";
	import DnsAdblockImportRulesDialog from "./components/DnsAdblockImportRulesDialog.svelte";

	let activeTab = $state<"allow" | "block">("allow");
	let loading = $state(true);
	let allowlist = $state<AllowlistEntry[]>([]);
	let customRules = $state<AdblockRuleEntry[]>([]);
	let newDomain = $state("");
	let searchQuery = $state("");
	let adding = $state(false);
	let importDialogOpen = $state(false);
	let copiedDomain = $state<string | null>(null);

	async function loadAll() {
		loading = true;
		try {
			const [allowRes, rulesRes] = await Promise.allSettled([
				dnsAdblockAllowlist(),
				dnsAdblockRules(),
			]);
			if (allowRes.status === "fulfilled" && allowRes.value) {
				allowlist = allowRes.value;
			}
			if (rulesRes.status === "fulfilled" && rulesRes.value) {
				customRules = rulesRes.value;
			}
		} catch {
			toast.error("Failed to load DNS rules");
		} finally {
			loading = false;
		}
	}

	async function handleAddDomain(e: Event) {
		e.preventDefault();
		const domain = newDomain.trim().toLowerCase().replace(/\.$/, "");
		if (!domain) {
			toast.error("Please enter a domain name");
			return;
		}

		adding = true;
		try {
			if (activeTab === "allow") {
				await dnsAllow(domain);
				toast.success(`Domain "${domain}" added to Allowlist`);
			} else {
				await dnsAdblockRuleAdd(domain, "block");
				toast.success(`Domain "${domain}" added to Blacklist`);
			}
			newDomain = "";
			await loadAll();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to save domain");
		} finally {
			adding = false;
		}
	}

	async function handleRemoveAllow(target: string) {
		try {
			await dnsUnallow(target);
			toast.success(`Removed "${target}" from allowlist`);
			await loadAll();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to remove domain");
		}
	}

	async function handleRemoveBlock(rule: AdblockRuleEntry) {
		if (rule.id === undefined) return;
		try {
			await dnsAdblockRuleRemove(rule.id);
			toast.success(`Removed "${rule.domain}" from blacklist`);
			await loadAll();
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to remove domain");
		}
	}

	async function handleToggleStatus(rule: AdblockRuleEntry) {
		if (rule.id === undefined) return;
		try {
			await dnsAdblockRuleStatus(rule.id, !rule.enabled);
			rule.enabled = !rule.enabled;
			toast.success(`Rule "${rule.domain}" ${rule.enabled ? "enabled" : "disabled"}`);
		} catch (err: any) {
			toast.error(err?.message ?? "Failed to toggle rule status");
		}
	}

	async function copyText(text: string) {
		try {
			await navigator.clipboard.writeText(text);
			copiedDomain = text;
			toast.success("Copied to clipboard");
			setTimeout(() => {
				copiedDomain = null;
			}, 2000);
		} catch {
			toast.error("Failed to copy domain");
		}
	}

	const filteredAllowlist = $derived.by(() => {
		if (!searchQuery.trim()) return allowlist;
		const q = searchQuery.toLowerCase();
		return allowlist.filter((e) => e.domain.toLowerCase().includes(q));
	});

	const customBlocks = $derived.by(() => {
		return customRules.filter((r) => r.action === "block");
	});

	const filteredCustomBlocks = $derived.by(() => {
		if (!searchQuery.trim()) return customBlocks;
		const q = searchQuery.toLowerCase();
		return customBlocks.filter((e) => e.domain.toLowerCase().includes(q));
	});

	onMount(() => {
		loadAll();
	});
</script>

<div class="space-y-6">
	<!-- Tabbed Rules View -->
	<Tabs.Root bind:value={activeTab} class="space-y-4">
		<div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
			<div class="overflow-x-auto no-scrollbar w-full sm:w-auto -mx-1 px-1 py-0.5">
				<Tabs.List class="inline-flex w-max h-9 p-1">
					<Tabs.Trigger value="allow" class="gap-1.5 text-xs shrink-0">
						<ShieldCheckIcon class="size-3.5 text-emerald-500" />
						<span class="hidden sm:inline">Allowlist (Whitelist)</span>
						<span class="sm:hidden">Allowlist</span>
						<Badge variant="secondary" class="ml-1 px-1.5 py-0 text-[10px] font-mono">
							{allowlist.length}
						</Badge>
					</Tabs.Trigger>
					<Tabs.Trigger value="block" class="gap-1.5 text-xs shrink-0">
						<ShieldAlertIcon class="size-3.5 text-rose-500" />
						<span class="hidden sm:inline">Custom Blocklist (Blacklist)</span>
						<span class="sm:hidden">Custom Blocklist</span>
						<Badge variant="secondary" class="ml-1 px-1.5 py-0 text-[10px] font-mono">
							{customBlocks.length}
						</Badge>
					</Tabs.Trigger>
				</Tabs.List>
			</div>

			<div class="flex items-center gap-2 w-full sm:w-auto">
				<div class="relative flex-1 sm:w-60 sm:flex-initial">
					<SearchIcon class="absolute left-2.5 top-2.5 size-3.5 text-muted-foreground" />
					<Input
						type="text"
						placeholder="Search rules..."
						class="pl-8 h-8 text-xs font-mono w-full"
						bind:value={searchQuery}
					/>
				</div>

				<Button
					variant="outline"
					size="sm"
					class="h-8 gap-1.5 text-xs shrink-0"
					onclick={() => (importDialogOpen = true)}
				>
					<FileTextIcon class="size-3.5" />
					<span>Bulk Import</span>
				</Button>
			</div>
		</div>

		<!-- Add Domain Inline Form -->
		<Card.Root class="p-3">
			<form onsubmit={handleAddDomain} class="flex items-center gap-2">
				<Input
					placeholder={activeTab === "allow"
						? "Enter domain to always permit (e.g. tracking-exception.com)..."
						: "Enter domain to block manually (e.g. bad-tracker.net)..."}
					class="h-9 text-xs font-mono flex-1"
					bind:value={newDomain}
					required
				/>
				<Button type="submit" size="sm" class="h-9 gap-1.5 text-xs shrink-0" disabled={adding}>
					<PlusIcon class="size-3.5" />
					{activeTab === "allow" ? "Add to Allowlist" : "Add to Blocklist"}
				</Button>
			</form>
		</Card.Root>

		<!-- Allowlist Tab Content -->
		<Tabs.Content value="allow" class="m-0">
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<Card.Title class="text-sm font-semibold">
						Explicit Whitelist Exceptions ({allowlist.length})
					</Card.Title>
					<Card.Description class="text-xs">
						Domains on the allowlist always bypass blocklists, regex rules, and sinkhole policies.
					</Card.Description>
				</Card.Header>

				<Card.Content class="p-0">
					<Table.Root>
						<Table.Header>
							<Table.Row class="hover:bg-transparent">
								<Table.Head class="w-[70%]">Domain</Table.Head>
								<Table.Head class="w-[15%]">Precedence</Table.Head>
								<Table.Head class="w-[15%] text-right">Action</Table.Head>
							</Table.Row>
						</Table.Header>

						<Table.Body>
							{#if loading && allowlist.length === 0}
								{#each Array(3) as _}
									<Table.Row>
										<Table.Cell><Skeleton class="h-4 w-60" /></Table.Cell>
										<Table.Cell><Skeleton class="h-4 w-16" /></Table.Cell>
										<Table.Cell class="text-right"><Skeleton class="h-4 w-10 ml-auto" /></Table.Cell>
									</Table.Row>
								{/each}
							{:else if filteredAllowlist.length === 0}
								<Table.Row>
									<Table.Cell colspan={3} class="h-28 text-center text-muted-foreground text-xs">
										{#if searchQuery}
											No allowlist entries match your search.
										{:else}
											No whitelist exceptions added yet.
										{/if}
									</Table.Cell>
								</Table.Row>
							{:else}
								{#each filteredAllowlist as entry (entry.id ?? entry.domain)}
									<Table.Row class="hover:bg-muted/40 transition-colors group">
										<Table.Cell class="font-mono text-xs">
											<div class="flex items-center gap-2">
												<span class="font-medium text-foreground">{entry.domain}</span>
												<button
													type="button"
													onclick={() => copyText(entry.domain)}
													class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded text-muted-foreground"
													title="Copy domain"
												>
													{#if copiedDomain === entry.domain}
														<CheckIcon class="size-3 text-emerald-500" />
													{:else}
														<CopyIcon class="size-3" />
													{/if}
												</button>
											</div>
										</Table.Cell>

										<Table.Cell>
											<Badge variant="outline" class="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20 text-[10px] font-mono">
												High Priority
											</Badge>
										</Table.Cell>

										<Table.Cell class="text-right">
											<Button
												variant="ghost"
												size="sm"
												onclick={() => handleRemoveAllow(entry.domain)}
												class="size-7 p-0 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
												title="Remove from allowlist"
											>
												<Trash2Icon class="size-3.5" />
											</Button>
										</Table.Cell>
									</Table.Row>
								{/each}
							{/if}
						</Table.Body>
					</Table.Root>
				</Card.Content>
			</Card.Root>
		</Tabs.Content>

		<!-- Custom Blocklist Tab Content -->
		<Tabs.Content value="block" class="m-0">
			<Card.Root>
				<Card.Header class="pb-3 border-b border-border/50">
					<Card.Title class="text-sm font-semibold">
						Custom Domain Blacklist ({customBlocks.length})
					</Card.Title>
					<Card.Description class="text-xs">
						User-defined domain blocks enforced alongside remote list subscriptions.
					</Card.Description>
				</Card.Header>

				<Card.Content class="p-0">
					<Table.Root>
						<Table.Header>
							<Table.Row class="hover:bg-transparent">
								<Table.Head class="w-[70%]">Domain</Table.Head>
								<Table.Head class="w-[15%]">Status</Table.Head>
								<Table.Head class="w-[15%] text-right">Action</Table.Head>
							</Table.Row>
						</Table.Header>

						<Table.Body>
							{#if filteredCustomBlocks.length === 0}
								<Table.Row>
									<Table.Cell colspan={3} class="h-28 text-center text-muted-foreground text-xs">
										{#if searchQuery}
											No custom blocks match your search.
										{:else}
											No manual domain blocks added yet.
										{/if}
									</Table.Cell>
								</Table.Row>
							{:else}
								{#each filteredCustomBlocks as entry (entry.id)}
									<Table.Row class="hover:bg-muted/40 transition-colors group">
										<Table.Cell class="font-mono text-xs">
											<div class="flex items-center gap-2">
												<span class="font-medium text-foreground">{entry.domain}</span>
												<button
													type="button"
													onclick={() => copyText(entry.domain)}
													class="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:text-primary rounded text-muted-foreground"
													title="Copy domain"
												>
													{#if copiedDomain === entry.domain}
														<CheckIcon class="size-3 text-emerald-500" />
													{:else}
														<CopyIcon class="size-3" />
													{/if}
												</button>
											</div>
										</Table.Cell>

										<Table.Cell>
											<button
												type="button"
												onclick={() => handleToggleStatus(entry)}
												class="transition-transform active:scale-95"
												title="Click to toggle rule status"
											>
												{#if entry.enabled}
													<Badge variant="outline" class="bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20 text-[10px] font-mono cursor-pointer hover:bg-rose-500/20">
														Blocked
													</Badge>
												{:else}
													<Badge variant="outline" class="bg-muted text-muted-foreground border-border text-[10px] font-mono cursor-pointer hover:bg-muted/80">
														Disabled
													</Badge>
												{/if}
											</button>
										</Table.Cell>

										<Table.Cell class="text-right">
											<Button
												variant="ghost"
												size="sm"
												onclick={() => handleRemoveBlock(entry)}
												class="size-7 p-0 text-muted-foreground hover:text-destructive hover:bg-destructive/10"
												title="Remove custom block"
											>
												<Trash2Icon class="size-3.5" />
											</Button>
										</Table.Cell>
									</Table.Row>
								{/each}
							{/if}
						</Table.Body>
					</Table.Root>
				</Card.Content>
			</Card.Root>
		</Tabs.Content>
	</Tabs.Root>
</div>

<!-- Bulk Import Dialog -->
<DnsAdblockImportRulesDialog
	bind:open={importDialogOpen}
	action={activeTab}
	onImported={() => {
		loadAll();
	}}
/>
