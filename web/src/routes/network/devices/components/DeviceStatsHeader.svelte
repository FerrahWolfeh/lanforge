<script lang="ts">
	import * as Card from "$lib/components/ui/card";
	import { Button } from "$lib/components/ui/button";
	import { Input } from "$lib/components/ui/input";
	import RefreshCwIcon from "@lucide/svelte/icons/refresh-cw";
	import ZapIcon from "@lucide/svelte/icons/zap";
	import SearchIcon from "@lucide/svelte/icons/search";

	let {
		loading = false,
		scanning = false,
		totalCount = 0,
		onlineCount = 0,
		searchQuery = $bindable(""),
		statusFilter = $bindable("all" as "all" | "online" | "offline"),
		onRefresh = () => {},
		onScan = () => {},
	}: {
		loading?: boolean;
		scanning?: boolean;
		totalCount?: number;
		onlineCount?: number;
		searchQuery?: string;
		statusFilter?: "all" | "online" | "offline";
		onRefresh?: () => void;
		onScan?: () => void;
	} = $props();

	const offlineCount = $derived(Math.max(0, totalCount - onlineCount));
</script>

<div class="flex flex-col gap-4">
	<!-- Title & Action Bar -->
	<div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h1 class="text-foreground text-2xl font-bold tracking-tight">
				Network Devices
			</h1>
			<p class="text-muted-foreground text-xs sm:text-sm">
				Discovered LAN endpoints tracked via ARP, NDP, and DHCP
			</p>
		</div>
		<div class="flex items-center gap-2">
			<Button
				variant="outline"
				size="sm"
				onclick={onRefresh}
				disabled={loading}
				class="h-8 text-xs gap-1.5"
			>
				<RefreshCwIcon class="size-3.5 {loading ? 'animate-spin' : ''}" />
				<span>Refresh</span>
			</Button>
			<Button
				size="sm"
				onclick={onScan}
				disabled={scanning}
				class="h-8 text-xs gap-1.5"
			>
				{#if scanning}
					<span class="size-3.5 animate-spin rounded-full border-2 border-current border-t-transparent"></span>
				{:else}
					<ZapIcon class="size-3.5 text-amber-300" />
				{/if}
				<span>Scan Network</span>
			</Button>
		</div>
	</div>

	<!-- Controls & Filter Bar -->
	<Card.Root>
		<Card.Content class="flex flex-col gap-3 p-3 sm:flex-row sm:items-center sm:justify-between">
			<!-- Search input -->
			<div class="relative flex-1 max-w-sm">
				<SearchIcon class="text-muted-foreground absolute left-3 top-1/2 size-3.5 -translate-y-1/2" />
				<Input
					type="search"
					placeholder="Search hostname, MAC, or IP..."
					class="pl-8 text-xs h-8"
					bind:value={searchQuery}
				/>
			</div>

			<!-- Status Filter Pills -->
			<div class="flex items-center gap-1 rounded-lg border border-border/80 bg-muted/40 p-1">
				<button
					class={[
						"rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
						statusFilter === "all"
							? "bg-background text-foreground shadow-sm"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (statusFilter = "all")}
				>
					All ({totalCount})
				</button>
				<button
					class={[
						"rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
						statusFilter === "online"
							? "bg-background text-emerald-400 shadow-sm"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (statusFilter = "online")}
				>
					Online ({onlineCount})
				</button>
				<button
					class={[
						"rounded-md px-2.5 py-1 text-xs font-medium transition-colors",
						statusFilter === "offline"
							? "bg-background text-rose-400 shadow-sm"
							: "text-muted-foreground hover:text-foreground",
					].join(" ")}
					onclick={() => (statusFilter = "offline")}
				>
					Offline ({offlineCount})
				</button>
			</div>
		</Card.Content>
	</Card.Root>
</div>
