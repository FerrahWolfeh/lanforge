<script lang="ts">
	import * as Table from "$lib/components/ui/table";
	import * as AlertDialog from "$lib/components/ui/alert-dialog";
	import { Button } from "$lib/components/ui/button";
	import { Badge } from "$lib/components/ui/badge";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import RotateCwIcon from "@lucide/svelte/icons/rotate-cw";
	import Trash2Icon from "@lucide/svelte/icons/trash-2";
	import CopyIcon from "@lucide/svelte/icons/copy";
	import CheckIcon from "@lucide/svelte/icons/check";
	import Loader2Icon from "@lucide/svelte/icons/loader-2";
	import { deleteToken, renewToken } from "$lib/api/client";
	import { copyToClipboard } from "$lib/utils";
	import type { AuthToken } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import DataTableCard from "$lib/components/DataTableCard.svelte";

	let {
		tokens = [],
		isLoading = false,
		onRefresh,
		onOpenCreate,
		onRenewed
	}: {
		tokens: AuthToken[];
		isLoading: boolean;
		onRefresh: () => Promise<void> | void;
		onOpenCreate: () => void;
		onRenewed: (token: AuthToken) => void;
	} = $props();

	let searchQuery = $state("");
	let scopeFilter = $state<string>("all");
	let copiedTokenId = $state<string | number | null>(null);

	// Revoke confirmation dialog
	let isRevokeOpen = $state(false);
	let tokenToRevoke = $state<AuthToken | null>(null);
	let isRevoking = $state(false);

	// Renew confirmation dialog
	let isRenewOpen = $state(false);
	let tokenToRenew = $state<AuthToken | null>(null);
	let isRenewing = $state(false);

	function isExpired(t: AuthToken): boolean {
		if (!t.expires_at) return false;
		const nowSecs = Math.floor(Date.now() / 1000);
		const expSecs = t.expires_at > 1e11 ? Math.floor(t.expires_at / 1000) : t.expires_at;
		return expSecs < nowSecs;
	}

	function formatDate(ts: number | null | undefined): string {
		if (!ts) return "Never";
		const ms = ts > 1e11 ? ts : ts * 1000;
		const d = new Date(ms);
		return d.toLocaleDateString(undefined, {
			year: "numeric",
			month: "short",
			day: "2-digit",
			hour: "2-digit",
			minute: "2-digit"
		});
	}

	function formatRelative(ts: number | null | undefined): string {
		if (!ts) return "Never used";
		const ms = ts > 1e11 ? ts : ts * 1000;
		const diffSecs = Math.round((Date.now() - ms) / 1000);
		if (diffSecs < 60) return "Just now";
		if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
		if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
		return `${Math.floor(diffSecs / 86400)}d ago`;
	}

	function confirmRevoke(token: AuthToken) {
		tokenToRevoke = token;
		isRevokeOpen = true;
	}

	async function handleRevokeToken() {
		if (!tokenToRevoke) return;
		isRevoking = true;
		try {
			await deleteToken(tokenToRevoke.id);
			toast.success(`Key '${tokenToRevoke.name}' successfully revoked.`);
			isRevokeOpen = false;
			tokenToRevoke = null;
			await onRefresh();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to revoke key.";
			toast.error(msg);
		} finally {
			isRevoking = false;
		}
	}

	function confirmRenew(token: AuthToken) {
		tokenToRenew = token;
		isRenewOpen = true;
	}

	async function handleRenewToken() {
		if (!tokenToRenew) return;
		isRenewing = true;
		try {
			const renewed = await renewToken(tokenToRenew.id);
			toast.success(`Key '${tokenToRenew.name}' renewed! New secret generated.`);
			isRenewOpen = false;
			tokenToRenew = null;
			onRenewed(renewed);
			await onRefresh();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to renew key.";
			toast.error(msg);
		} finally {
			isRenewing = false;
		}
	}

	const filteredTokens = $derived(
		tokens.filter((t) => {
			const query = searchQuery.trim().toLowerCase();
			const matchesSearch =
				!query ||
				t.name.toLowerCase().includes(query) ||
				String(t.id).toLowerCase().includes(query);
			const matchesScope = scopeFilter === "all" || t.scopes.includes(scopeFilter);
			return matchesSearch && matchesScope;
		})
	);
</script>

<DataTableCard
	title="API Access Tokens"
	icon={KeyRoundIcon}
	description="Generated tokens can be passed via the Authorization: Bearer lf_ak_... header."
	total={filteredTokens.length}
	itemName="tokens"
	searchPlaceholder="Search token name or ID..."
	bind:searchQuery
	showPagination={false}
	containerHeight="h-auto"
	minTableWidth="min-w-[700px]"
	columns={6}
	loading={isLoading}
	isEmpty={filteredTokens.length === 0}
	emptyMessage="No API access tokens configured yet. Create a token to integrate Lanforge with programmatic tools."
	emptyFilteredMessage="No API keys match the search and scope criteria."
>
	{#snippet filters()}
		<select
			bind:value={scopeFilter}
			class="h-9 text-xs rounded-md bg-background border border-input px-2.5 text-foreground outline-none focus-visible:ring-1 focus-visible:ring-ring cursor-pointer"
			aria-label="Filter by scope"
		>
			<option value="all">All Scopes</option>
			<option value="admin">Admin</option>
			<option value="monitoring">Monitoring</option>
			<option value="device_write">Device Write</option>
			<option value="dns_query">DNS Query</option>
			<option value="upstream_write">Upstream Write</option>
			<option value="config_write">Config Write</option>
		</select>
	{/snippet}

	{#snippet actions()}
		<Button
			size="sm"
			class="h-8 text-xs gap-1.5 cursor-pointer"
			onclick={onOpenCreate}
		>
			<PlusIcon class="size-3.5" />
			<span>Generate Key</span>
		</Button>
	{/snippet}

	{#snippet emptyAction()}
		<Button
			size="sm"
			class="h-8 text-xs gap-1.5 cursor-pointer"
			onclick={onOpenCreate}
		>
			<PlusIcon class="size-3.5" />
			<span>Generate First Key</span>
		</Button>
	{/snippet}

	{#snippet header()}
		<Table.Head>Name &amp; ID</Table.Head>
		<Table.Head>Access Scopes</Table.Head>
		<Table.Head>Created</Table.Head>
		<Table.Head>Last Used</Table.Head>
		<Table.Head>Status / Expiration</Table.Head>
		<Table.Head class="text-right w-[180px]">Actions</Table.Head>
	{/snippet}

	{#each filteredTokens as token (token.id)}
		{@const expired = isExpired(token)}
		<Table.Row class="hover:bg-muted/30 transition-colors font-mono text-xs">
			<!-- Name & ID -->
			<Table.Cell class="py-3 font-sans">
				<div class="flex items-center gap-2.5">
					<div class="size-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary shrink-0">
						<KeyRoundIcon class="size-4" />
					</div>
					<div class="flex flex-col gap-0.5">
						<span class="text-xs font-bold text-foreground">{token.name}</span>
						<div class="flex items-center gap-1.5">
							<span class="text-[11px] font-mono text-muted-foreground">
								ID: #{token.id}
							</span>
							<button
								type="button"
								class="text-muted-foreground hover:text-foreground transition-colors cursor-pointer p-0.5"
								title="Copy ID"
								onclick={async () => {
									const ok = await copyToClipboard(String(token.id), "Token ID");
									if (ok) {
										copiedTokenId = token.id;
										setTimeout(() => (copiedTokenId = null), 2000);
									}
								}}
							>
								{#if copiedTokenId === token.id}
									<CheckIcon class="size-3 text-emerald-500" />
								{:else}
									<CopyIcon class="size-3" />
								{/if}
							</button>
						</div>
					</div>
				</div>
			</Table.Cell>

			<!-- Scopes -->
			<Table.Cell class="py-3 font-sans">
				<div class="flex flex-wrap gap-1 max-w-xs">
					{#each token.scopes as sc}
						{#if sc === "admin"}
							<Badge variant="default" class="text-[10px] px-1.5 py-0 font-mono">
								admin
							</Badge>
						{:else if sc === "monitoring"}
							<Badge variant="secondary" class="text-[10px] px-1.5 py-0 font-mono">
								monitoring
							</Badge>
						{:else}
							<Badge variant="outline" class="text-[10px] px-1.5 py-0 font-mono text-muted-foreground">
								{sc}
							</Badge>
						{/if}
					{/each}
				</div>
			</Table.Cell>

			<!-- Created At -->
			<Table.Cell class="py-3 font-sans text-xs text-muted-foreground whitespace-nowrap">
				{formatDate(token.created_at)}
			</Table.Cell>

			<!-- Last Used -->
			<Table.Cell class="py-3 font-sans whitespace-nowrap">
				<span class="text-xs text-muted-foreground" title={formatDate(token.last_used)}>
					{formatRelative(token.last_used)}
				</span>
			</Table.Cell>

			<!-- Status / Expiration -->
			<Table.Cell class="py-3 font-sans whitespace-nowrap">
				{#if expired}
					<Badge variant="destructive" class="text-[10px] px-1.5 py-0 font-medium">
						Expired
					</Badge>
					<p class="text-[10px] text-destructive/80 mt-0.5">
						{formatDate(token.expires_at)}
					</p>
				{:else if token.expires_at}
					<Badge variant="outline" class="text-[10px] px-1.5 py-0 font-medium text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
						Active
					</Badge>
					<p class="text-[10px] text-muted-foreground mt-0.5">
						Expires on {formatDate(token.expires_at)}
					</p>
				{:else}
					<Badge variant="outline" class="text-[10px] px-1.5 py-0 font-medium text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10">
						Active (Permanent)
					</Badge>
				{/if}
			</Table.Cell>

			<!-- Actions -->
			<Table.Cell class="py-3 text-right whitespace-nowrap font-sans">
				<div class="flex items-center justify-end gap-1.5">
					<Button
						variant="outline"
						size="sm"
						class="cursor-pointer text-xs h-8 px-2.5"
						title="Renew key (generates new secret token)"
						onclick={() => confirmRenew(token)}
					>
						<RotateCwIcon class="size-3.5 mr-1" />
						Renew
					</Button>

					<Button
						variant="outline"
						size="sm"
						class="cursor-pointer text-xs h-8 px-2.5 text-destructive hover:bg-destructive/10 border-destructive/30"
						title="Revoke and delete token"
						onclick={() => confirmRevoke(token)}
					>
						<Trash2Icon class="size-3.5 mr-1" />
						Revoke
					</Button>
				</div>
			</Table.Cell>
		</Table.Row>
	{/each}
</DataTableCard>

<!-- AlertDialog for Revoke -->
<AlertDialog.Root bind:open={isRevokeOpen}>
	<AlertDialog.Content class="rounded-xl">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold text-foreground">
				Revoke API Key?
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Are you sure you want to permanently revoke key <strong>{tokenToRevoke?.name}</strong> (ID #{tokenToRevoke?.id})? Any automation or client relying on this token will lose access immediately.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="cursor-pointer text-xs">
				Cancel
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="cursor-pointer text-xs bg-destructive text-destructive-foreground hover:bg-destructive/90"
				onclick={handleRevokeToken}
				disabled={isRevoking}
			>
				{#if isRevoking}
					<Loader2Icon class="size-3.5 mr-1 animate-spin" />
					Revoking...
				{:else}
					Yes, Revoke Key
				{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>

<!-- AlertDialog for Renew -->
<AlertDialog.Root bind:open={isRenewOpen}>
	<AlertDialog.Content class="rounded-xl">
		<AlertDialog.Header>
			<AlertDialog.Title class="text-base font-bold text-foreground">
				Renew API Key?
			</AlertDialog.Title>
			<AlertDialog.Description class="text-xs">
				Renewing key <strong>{tokenToRenew?.name}</strong> will immediately invalidate the previous secret and generate a new token with the same scopes and expiration period.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel class="cursor-pointer text-xs">
				Cancel
			</AlertDialog.Cancel>
			<AlertDialog.Action
				class="cursor-pointer text-xs bg-primary text-primary-foreground hover:bg-primary/90 shadow-xs"
				onclick={handleRenewToken}
				disabled={isRenewing}
			>
				{#if isRenewing}
					<Loader2Icon class="size-3.5 mr-1 animate-spin" />
					Renewing...
				{:else}
					Confirm and Renew
				{/if}
			</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
