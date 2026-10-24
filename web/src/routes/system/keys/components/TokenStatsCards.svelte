<script lang="ts">
	import KeyIcon from "@lucide/svelte/icons/key";
	import CheckCircle2Icon from "@lucide/svelte/icons/check-circle-2";
	import ClockIcon from "@lucide/svelte/icons/clock";
	import ShieldCheckIcon from "@lucide/svelte/icons/shield-check";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import type { AuthToken } from "$lib/api/types";

	let {
		tokens = [],
		isLoading = false
	}: {
		tokens: AuthToken[];
		isLoading: boolean;
	} = $props();

	function isExpired(t: AuthToken): boolean {
		if (!t.expires_at) return false;
		const nowSecs = Math.floor(Date.now() / 1000);
		const expSecs = t.expires_at > 1e11 ? Math.floor(t.expires_at / 1000) : t.expires_at;
		return expSecs < nowSecs;
	}

	const totalCount = $derived(tokens.length);
	const activeCount = $derived(tokens.filter((t) => !isExpired(t)).length);
	const expiredCount = $derived(tokens.filter((t) => isExpired(t)).length);
	const adminCount = $derived(tokens.filter((t) => t.scopes.includes("admin")).length);
</script>

<StatCardGrid cols={2}>
	<!-- Card 1: Active Tokens -->
	<StatCard
		label="Active API Tokens"
		value={activeCount}
		icon={KeyIcon}
		color="primary"
		badge={{
			text: expiredCount > 0 ? `${expiredCount} Expired` : "All Valid",
			variant: expiredCount > 0 ? "warning" : "online",
			showDot: true
		}}
		subtext={`${totalCount} total registered key${totalCount === 1 ? '' : 's'}${expiredCount > 0 ? ` (${expiredCount} expired)` : ''}`}
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Authentication Scheme" value="Bearer Token" />
			<StatCardFooterItem
				label="Status"
				value={expiredCount > 0 ? `${expiredCount} need renewal` : "All tokens valid"}
				color={expiredCount > 0 ? "text-amber-500" : "text-emerald-500"}
			/>
		{/snippet}
	</StatCard>

	<!-- Card 2: Privileged Scope -->
	<StatCard
		label="Administrative Tokens"
		value={adminCount}
		icon={ShieldCheckIcon}
		color="violet"
		badge={{
			text: `${adminCount} Admin`,
			variant: adminCount > 0 ? "indigo" : "zinc",
			showDot: adminCount > 0
		}}
		subtext="Bearer keys with full administrative privileges"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Security Scope" value="Unrestricted" />
			<StatCardFooterItem label="Persistence" value="Embedded redb" />
		{/snippet}
	</StatCard>
</StatCardGrid>
