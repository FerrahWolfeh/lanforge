<script lang="ts">
	import { Button } from "$lib/components/ui/button";
	import KeyRoundIcon from "@lucide/svelte/icons/key-round";
	import PlusIcon from "@lucide/svelte/icons/plus";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";

	import { listTokens } from "$lib/api/client";
	import type { AuthToken } from "$lib/api/types";
	import { toast } from "svelte-sonner";
	import { onMount } from "svelte";
	import TokenTable from "./components/TokenTable.svelte";
	import TokenValidatorCard from "./components/TokenValidatorCard.svelte";
	import TokenCreateDialog from "./components/TokenCreateDialog.svelte";
	import TokenSecretModal from "./components/TokenSecretModal.svelte";
	import NavTabs from "$lib/components/NavTabs.svelte";
	import { accessTabs } from "../tabs";
	import PageHeader from "$lib/components/PageHeader.svelte";

	let tokens = $state<AuthToken[]>([]);
	let isLoading = $state(true);
	let isRefreshing = $state(false);

	let isCreateOpen = $state(false);
	let isSecretModalOpen = $state(false);
	let newlyCreatedToken = $state<AuthToken | null>(null);

	async function loadTokens(showSpinner = true) {
		if (showSpinner) isRefreshing = true;
		try {
			tokens = await listTokens();
		} catch (err: unknown) {
			const msg = err instanceof Error ? err.message : "Failed to list tokens.";
			toast.error(msg);
		} finally {
			isLoading = false;
			if (showSpinner) isRefreshing = false;
		}
	}

	onMount(() => {
		loadTokens(false);
	});

	function handleTokenCreatedOrRenewed(token: AuthToken) {
		newlyCreatedToken = token;
		isSecretModalOpen = true;
	}
</script>

<div class="flex flex-col gap-6 w-full pb-12">
	<!-- Top Header -->
	<PageHeader
		title="API Tokens"
		description="Long-lived tokens for scripts and other programs that use the API."
		icon={KeyRoundIcon}
	>
		{#snippet actions()}
			<Button
				variant="outline"
				size="sm"
				class="rounded-md cursor-pointer text-xs"
				onclick={() => loadTokens(true)}
				disabled={isRefreshing}
			>
				<RefreshCwIcon
					data-icon="inline-start"
					class={isRefreshing ? "animate-spin" : ""}
				/>
				Refresh
			</Button>

			<Button
				size="sm"
				class="rounded-md cursor-pointer text-xs font-medium bg-primary text-primary-foreground hover:bg-primary/90"
				onclick={() => (isCreateOpen = true)}
			>
				<PlusIcon data-icon="inline-start" />
				New API Key
			</Button>
		{/snippet}
	</PageHeader>

	<!-- Access Control Sub-Navigation Tabs -->
	<NavTabs tabs={accessTabs} ariaLabel="Access and authentication navigation" />


	<!-- Main List Section -->
	<TokenTable
		{tokens}
		{isLoading}
		onRefresh={() => loadTokens(false)}
		onOpenCreate={() => (isCreateOpen = true)}
		onRenewed={handleTokenCreatedOrRenewed}
	/>

	<!-- Quick Integration Guides & Token Validator -->
	<TokenValidatorCard />
</div>

<!-- Create New Token Dialog -->
<TokenCreateDialog
	bind:open={isCreateOpen}
	onCreated={(token) => {
		handleTokenCreatedOrRenewed(token);
		loadTokens(false);
	}}
/>

<!-- Token Secret Display Dialog -->
<TokenSecretModal
	bind:open={isSecretModalOpen}
	token={newlyCreatedToken}
/>
