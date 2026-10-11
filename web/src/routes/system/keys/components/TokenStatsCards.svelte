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

<StatCardGrid cols={4}>
	<!-- Total Tokens -->
	<StatCard
		label="Total Keys"
		value={totalCount}
		icon={KeyIcon}
		color="primary"
		subtext="Registered database tokens"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Storage" value="Embedded redb" />
			<StatCardFooterItem label="Scheme" value="Bearer Token" />
		{/snippet}
	</StatCard>

	<!-- Active Tokens -->
	<StatCard
		label="Active Tokens"
		value={activeCount}
		icon={CheckCircle2Icon}
		color="emerald"
		badge={{
			text: "Valid",
			variant: "online",
			showDot: true
		}}
		subtext="Within validity period"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Validation"
				value="Passing"
				color="text-emerald-500"
			/>
			<StatCardFooterItem
				label="Active Ratio"
				value={`${Math.round((activeCount / (totalCount || 1)) * 100)}%`}
			/>
		{/snippet}
	</StatCard>

	<!-- Expired Tokens -->
	<StatCard
		label="Expired Tokens"
		value={expiredCount}
		icon={ClockIcon}
		color={expiredCount > 0 ? "amber" : "zinc"}
		badge={expiredCount > 0 ? {
			text: "Expired",
			variant: "warning",
			showDot: true
		} : {
			text: "0 Expired",
			variant: "online",
			showDot: true
		}}
		subtext={expiredCount > 0 ? "Require renewal or removal" : "All tokens within validity window"}
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem
				label="Expired"
				value={expiredCount}
				color={expiredCount > 0 ? "text-amber-500" : "text-muted-foreground"}
			/>
			<StatCardFooterItem
				label="Action"
				value={expiredCount > 0 ? "Needs Review" : "Healthy"}
				color={expiredCount > 0 ? "text-amber-500" : "text-emerald-500"}
			/>
		{/snippet}
	</StatCard>

	<!-- Admin Scope -->
	<StatCard
		label="Admin Privilege"
		value={adminCount}
		icon={ShieldCheckIcon}
		color="violet"
		subtext="Full administrative scope"
		loading={isLoading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Security Level" value="Root / Admin" />
			<StatCardFooterItem label="Scopes" value={`${adminCount} admin`} />
		{/snippet}
	</StatCard>
</StatCardGrid>
