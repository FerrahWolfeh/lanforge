<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Skeleton } from "$lib/components/ui/skeleton";
	import ArrowRightLeftIcon from "@lucide/svelte/icons/arrow-right-left";
	import GlobeIcon from "@lucide/svelte/icons/globe";
	import LaptopIcon from "@lucide/svelte/icons/laptop";
	import ServerIcon from "@lucide/svelte/icons/server";
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
		rules.filter((r) => formatRewriteAnswer(r.answer).startsWith("dev:"))
			.length,
	);

	const srvCount = $derived(
		rules.filter(
			(r) =>
				r.rtype === "SRV" ||
				formatRewriteAnswer(r.answer).startsWith("srv:"),
		).length,
	);

	const staticCount = $derived(
		rules.filter((r) => {
			const ans = formatRewriteAnswer(r.answer);
			return (
				!ans.startsWith("dev:") &&
				!ans.startsWith("srv:") &&
				r.rtype !== "SRV"
			);
		}).length,
	);
</script>

<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
	<!-- Total Active Rewrites -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Total Rewrites</Card.Title>
			<ArrowRightLeftIcon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-24 mb-1" />
				<Skeleton class="h-3 w-32" />
			{:else}
				<div class="text-2xl font-bold">
					{totalCount.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Active DNS response overrides
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Static Overrides -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Static Overrides</Card.Title
			>
			<GlobeIcon class="h-4 w-4 text-muted-foreground" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-20 mb-1" />
				<Skeleton class="h-3 w-28" />
			{:else}
				<div class="text-2xl font-bold">
					{staticCount.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Standard A / AAAA / CNAME targets
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- Dynamic Device Bindings -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium">Device Bindings</Card.Title>
			<LaptopIcon class="h-4 w-4 text-blue-500" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-20 mb-1" />
				<Skeleton class="h-3 w-28" />
			{:else}
				<div
					class="text-2xl font-bold text-blue-600 dark:text-blue-400"
				>
					{deviceCount.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Dynamic <code
						class="font-mono text-[11px] bg-muted px-1 rounded"
						>dev:</code
					> targets
				</p>
			{/if}
		</Card.Content>
	</Card.Root>

	<!-- SRV Service Records -->
	<Card.Root class="relative overflow-hidden">
		<Card.Header
			class="flex flex-row items-center justify-between pb-2 space-y-0"
		>
			<Card.Title class="text-sm font-medium"
				>SRV Service Rules</Card.Title
			>
			<ServerIcon class="h-4 w-4 text-amber-500" />
		</Card.Header>
		<Card.Content>
			{#if loading}
				<Skeleton class="h-8 w-20 mb-1" />
				<Skeleton class="h-3 w-28" />
			{:else}
				<div
					class="text-2xl font-bold text-amber-600 dark:text-amber-400"
				>
					{srvCount.toLocaleString()}
				</div>
				<p class="text-xs text-muted-foreground mt-1">
					Dynamic <code
						class="font-mono text-[11px] bg-muted px-1 rounded"
						>srv:</code
					> service mappings
				</p>
			{/if}
		</Card.Content>
	</Card.Root>
</div>
