<script lang="ts">
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import ServerIcon from "@lucide/svelte/icons/server";
	import StatCard from "$lib/components/StatCard.svelte";
	import StatCardGrid from "$lib/components/StatCardGrid.svelte";
	import StatCardFooterItem from "$lib/components/StatCardFooterItem.svelte";
	import { type RewriteRule, formatRewriteAnswer } from "$lib/api/types";

	let {
		loading = false,
		rules = [],
	}: {
		loading?: boolean;
		rules?: RewriteRule[];
	} = $props();

	const totalCount = $derived(rules.length);

	const deviceCount = $derived(
		rules.filter((r) => formatRewriteAnswer(r.answer).startsWith("dev:")).length
	);

	const srvCount = $derived(
		rules.filter(
			(r) =>
				r.rtype === "SRV" ||
				formatRewriteAnswer(r.answer).startsWith("srv:")
		).length
	);

	const staticCount = $derived(
		rules.filter((r) => {
			const ans = formatRewriteAnswer(r.answer);
			return (
				!ans.startsWith("dev:") &&
				!ans.startsWith("srv:") &&
				r.rtype !== "SRV"
			);
		}).length
	);
</script>

<StatCardGrid cols={4}>
	<!-- Card 1: Total Active Rewrites -->
	<StatCard
		label="Total Rewrites"
		value={totalCount}
		icon={ArrowRightLeftIcon}
		color="emerald"
		subtext="Active DNS response overrides"
		{loading}
		badge={{
			text: "Ruleset",
			variant: "online",
			showDot: true
		}}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Override Scope" value="Authoritative" />
			<StatCardFooterItem label="Execution" value="Zero-RTT Cache" />
		{/snippet}
	</StatCard>

	<!-- Card 2: Static Overrides -->
	<StatCard
		label="Static Overrides"
		value={staticCount}
		icon={GlobeIcon}
		color="sky"
		subtext="Standard A / AAAA / CNAME targets"
		{loading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Record Types" value="A / AAAA / TXT" />
			<StatCardFooterItem label="Wildcards" value="Supported" />
		{/snippet}
	</StatCard>

	<!-- Card 3: Dynamic Device Bindings -->
	<StatCard
		label="Device Bindings"
		value={deviceCount}
		icon={LaptopIcon}
		color="indigo"
		subtext="Dynamic dev: host bindings"
		{loading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Binding Target" value="LAN Inventory" />
			<StatCardFooterItem label="Sync Mode" value="Live IP Tracking" />
		{/snippet}
	</StatCard>

	<!-- Card 4: SRV Service Records -->
	<StatCard
		label="SRV Service Rules"
		value={srvCount}
		icon={ServerIcon}
		color="amber"
		subtext="Dynamic srv: service mappings"
		{loading}
	>
		{#snippet footer()}
			<StatCardFooterItem label="Discovery" value="RFC 2782 SRV" />
			<StatCardFooterItem label="Routing" value="Port & Priority" />
		{/snippet}
	</StatCard>
</StatCardGrid>
