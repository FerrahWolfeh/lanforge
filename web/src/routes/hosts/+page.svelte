<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import * as Dialog from "$lib/components/ui/dialog";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import { Label } from "$lib/components/ui/label";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import { hostList, hostAdd, hostRemove } from "$lib/api/client";
	import type { HostConfigEntry } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import SearchIcon from "@lucide/svelte/icons/search";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import ServerIcon from "@lucide/svelte/icons/server";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";

	let hosts = $state<HostConfigEntry[]>([]);
	let loading = $state(true);
	let searchQuery = $state("");

	// Add Host Modal state
	let dialogOpen = $state(false);
	let submitting = $state(false);

	let formMac = $state("");
	let formHostname = $state("");
	let formV4 = $state("");
	let formV6Suffix = $state("");

	async function loadHosts() {
		loading = true;
		try {
			hosts = await hostList();
		} catch {
			toast.error("Failed to load static host configurations");
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		formMac = "";
		formHostname = "";
		formV4 = "";
		formV6Suffix = "";
	}

	function openAddModal() {
		resetForm();
		dialogOpen = true;
	}

	async function handleAddHost(e: Event) {
		e.preventDefault();
		if (!formMac.trim()) {
			toast.error("MAC Address is required");
			return;
		}

		submitting = true;
		try {
			const entry: HostConfigEntry = {
				mac: formMac.trim(),
				hostname: formHostname.trim(),
				v4_fixed: formV4.trim() || undefined,
				v6_suffix: formV6Suffix.trim() || undefined,
				origin: "Static",
			};
			await hostAdd(entry);
			toast.success(`Static host rule added for ${entry.mac}`);
			dialogOpen = false;
			await loadHosts();
		} catch (err: any) {
			toast.error(err?.message || "Failed to add static host rule");
		} finally {
			submitting = false;
		}
	}

	async function handleRemoveHost(mac: string) {
		try {
			await hostRemove(mac);
			toast.success(`Removed static host ${mac}`);
			await loadHosts();
		} catch {
			toast.error(`Failed to remove static host ${mac}`);
		}
	}

	onMount(loadHosts);

	const filteredHosts = $derived.by(() => {
		if (!searchQuery.trim()) return hosts;
		const q = searchQuery.toLowerCase().trim();
		return hosts.filter((h) => {
			const macMatch = h.mac?.toLowerCase().includes(q);
			const hostMatch = h.hostname?.toLowerCase().includes(q);
			const v4Match = (h.v4_fixed || h.v4 || "").toLowerCase().includes(q);
			const v6Match = (h.v6_suffix || "").toLowerCase().includes(q);
			return macMatch || hostMatch || v4Match || v6Match;
		});
	});
</script>

<svelte:head>
	<title>Static Hosts — Lanforge</title>
</svelte:head>

<div class="flex flex-col gap-6">
	<!-- Page Header -->
	<div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-foreground text-2xl font-bold tracking-tight">
				Static Hosts
			</h1>
			<p class="text-muted-foreground text-sm">
				Fixed IP address assignments and custom DNS hostname overrides
			</p>
		</div>
		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={loadHosts}
				disabled={loading}
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={loading ? "animate-spin" : ""}
				/>
				Refresh
			</Button>
			<Button size="sm" onclick={openAddModal}>
				<PlusIcon data-icon="inline-start" />
				Add Static Host
			</Button>
		</div>
	</div>

	<!-- Controls & Search Bar -->
	<Card.Root>
		<Card.Content class="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
			<div class="relative flex-1 max-w-sm">
				<SearchIcon class="text-muted-foreground absolute left-3 top-1/2 size-4 -translate-y-1/2" />
				<Input
					type="search"
					placeholder="Search static hosts by MAC, name, or IP..."
					class="pl-9"
					bind:value={searchQuery}
				/>
			</div>

			<Badge variant="outline" class="font-mono text-xs self-start sm:self-auto">
				{hosts.length} Configured Rule{hosts.length === 1 ? "" : "s"}
			</Badge>
		</Card.Content>
	</Card.Root>

	<!-- Static Hosts Table -->
	<Card.Root class="overflow-hidden">
		<Card.Content class="p-0">
			{#if loading}
				<div class="flex flex-col gap-3 p-6">
					{#each { length: 4 } as _, i (i)}
						<div class="flex items-center justify-between gap-4">
							<Skeleton class="h-5 w-32" />
							<Skeleton class="h-5 w-40" />
							<Skeleton class="h-5 w-24" />
							<Skeleton class="h-8 w-16 rounded-md" />
						</div>
					{/each}
				</div>
			{:else if filteredHosts.length === 0}
				<div class="text-muted-foreground flex flex-col items-center justify-center gap-2 py-16 text-sm">
					<ServerIcon class="size-8 opacity-30" />
					<span>No static host rules configured</span>
				</div>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full text-left text-xs border-collapse">
						<thead>
							<tr class="border-b border-border/60 bg-muted/30 text-muted-foreground font-semibold uppercase tracking-wider text-[10px]">
								<th class="py-3 px-4">Hostname</th>
								<th class="py-3 px-4">Target MAC</th>
								<th class="py-3 px-4">Fixed IPv4</th>
								<th class="py-3 px-4">IPv6 Suffix / Addr</th>
								<th class="py-3 px-4">Origin</th>
								<th class="py-3 px-4 text-right">Actions</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-border/40 font-mono">
							{#each filteredHosts as host (host.mac)}
								<tr class="transition-colors hover:bg-muted/30">
									<!-- Hostname -->
									<td class="py-3.5 px-4 font-sans font-semibold text-foreground">
										{host.hostname || "—"}
									</td>

									<!-- MAC -->
									<td class="py-3.5 px-4 text-muted-foreground">
										{host.mac}
									</td>

									<!-- Fixed IPv4 -->
									<td class="py-3.5 px-4 text-emerald-400 font-medium">
										{host.v4_fixed || host.v4 || "—"}
									</td>

									<!-- IPv6 Suffix -->
									<td class="py-3.5 px-4 text-sky-400">
										{host.v6_suffix || "—"}
									</td>

									<!-- Origin -->
									<td class="py-3.5 px-4 font-sans">
										<Badge variant="outline" class="text-[10px] uppercase font-mono">
											{host.origin || "Config"}
										</Badge>
									</td>

									<!-- Actions -->
									<td class="py-3.5 px-4 text-right font-sans">
										<Button
											variant="ghost"
											size="icon-sm"
											title="Delete Host Rule"
											onclick={() => handleRemoveHost(host.mac)}
										>
											<Trash2Icon class="size-4 text-rose-400" />
										</Button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</Card.Content>
	</Card.Root>
</div>

<!-- Add Static Host Modal -->
<Dialog.Root bind:open={dialogOpen}>
	<Dialog.Content class="sm:max-w-md">
		<Dialog.Header>
			<Dialog.Title class="flex items-center gap-2">
				<PlusIcon class="size-5 text-amber-400" />
				<span>Add Static Host Rule</span>
			</Dialog.Title>
		</Dialog.Header>

		<form onsubmit={handleAddHost} class="flex flex-col gap-4 py-2">
			<div class="flex flex-col gap-1.5">
				<Label for="mac">MAC Address *</Label>
				<Input
					id="mac"
					placeholder="e.g. AA:BB:CC:DD:EE:FF"
					class="font-mono text-xs"
					bind:value={formMac}
					required
				/>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="hostname">Hostname</Label>
				<Input
					id="hostname"
					placeholder="e.g. desktop-workstation"
					class="text-xs"
					bind:value={formHostname}
				/>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v4">Fixed IPv4 Address</Label>
				<Input
					id="v4"
					placeholder="e.g. 192.168.1.100"
					class="font-mono text-xs"
					bind:value={formV4}
				/>
			</div>

			<div class="flex flex-col gap-1.5">
				<Label for="v6">IPv6 Suffix or Address</Label>
				<Input
					id="v6"
					placeholder="e.g. ::100 or ::1a2b:3c4d"
					class="font-mono text-xs"
					bind:value={formV6Suffix}
				/>
			</div>

			<div class="flex items-center justify-end gap-2 mt-2">
				<Button
					type="button"
					variant="outline"
					size="sm"
					onclick={() => (dialogOpen = false)}
				>
					Cancel
				</Button>
				<Button type="submit" size="sm" disabled={submitting}>
					{#if submitting}
						<span class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent mr-1"></span>
					{/if}
					Save Rule
				</Button>
			</div>
		</form>
	</Dialog.Content>
</Dialog.Root>
