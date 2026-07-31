<script lang="ts">
	import * as Sidebar from "$lib/components/ui/sidebar";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import { auth } from "$lib/stores/auth.svelte";
	import { eventFeed } from "$lib/stores/events.svelte";
	import { goto } from "$app/navigation";
	import SunIcon from "@lucide/svelte/icons/sun";
	import MoonIcon from "@lucide/svelte/icons/moon";
	import LogOutIcon from "@lucide/svelte/icons/log-out";
	import UserIcon from "@lucide/svelte/icons/user";
	import { mode, toggleMode } from "mode-watcher";

	let { uptime = $bindable(0) }: { uptime?: number } = $props();

	const isDark = $derived(mode.current === 'dark');

	function formatUptime(secs: number): string {
		if (secs < 60) return `${secs}s`;
		if (secs < 3600) return `${Math.floor(secs / 60)}m`;
		const h = Math.floor(secs / 3600);
		const m = Math.floor((secs % 3600) / 60);
		return m > 0 ? `${h}h ${m}m` : `${h}h`;
	}

	function handleLogout() {
		auth.clear();
		goto("/login");
	}
</script>

<header
	class="bg-background/80 border-border sticky top-0 z-10 flex h-14 items-center gap-3 border-b px-4 backdrop-blur-sm"
>
	<!-- Sidebar toggle -->
	<Sidebar.Trigger class="-ml-1" />

	<!-- Separator -->
	<div class="bg-border h-5 w-px" aria-hidden="true"></div>

	<!-- SSE connection indicator -->
	<Tooltip.Provider>
		<Tooltip.Root>
			<Tooltip.Trigger>
				<div class="flex items-center gap-1.5">
					<span
						class={[
							"size-2 rounded-full",
							eventFeed.connected
								? "bg-green-500 shadow-[0_0_6px_theme(colors.green.500)]"
								: "bg-muted-foreground",
						].join(" ")}
					></span>
					<span class="text-muted-foreground hidden text-xs sm:block">
						{eventFeed.connected ? "Live" : "Offline"}
					</span>
				</div>
			</Tooltip.Trigger>
			<Tooltip.Content>
				<p class="text-xs">
					{eventFeed.connected
						? "Event stream connected"
						: "Event stream disconnected"}
				</p>
			</Tooltip.Content>
		</Tooltip.Root>
	</Tooltip.Provider>

	<!-- Uptime -->
	{#if uptime > 0}
		<span class="text-muted-foreground hidden text-xs sm:block">
			up {formatUptime(uptime)}
		</span>
	{/if}

	<!-- Spacer -->
	<div class="flex-1"></div>

	<!-- Theme toggle -->
	<Tooltip.Provider>
		<Tooltip.Root>
			<Tooltip.Trigger>
				<Button
					variant="ghost"
					size="icon"
					onclick={toggleMode}
					class="size-8"
				>
					{#if isDark}
						<SunIcon />
					{:else}
						<MoonIcon />
					{/if}
				</Button>
			</Tooltip.Trigger>
			<Tooltip.Content>
				<p class="text-xs">Toggle theme</p>
			</Tooltip.Content>
		</Tooltip.Root>
	</Tooltip.Provider>

	<!-- Auth indicator -->
	{#if auth.authenticated}
		<div class="flex items-center gap-2">
			<div class="hidden flex-col items-end sm:flex">
				<span class="text-foreground text-sm font-medium"
					>{auth.user?.username ?? "—"}</span
				>
				<Badge
					variant="secondary"
					class="h-4 px-1.5 py-0 text-[10px] capitalize"
				>
					{auth.user?.role ?? "…"}
				</Badge>
			</div>
			<Tooltip.Provider>
				<Tooltip.Root>
					<Tooltip.Trigger>
						<Button
							variant="ghost"
							size="icon"
							onclick={handleLogout}
							class="size-8"
						>
							<LogOutIcon />
						</Button>
					</Tooltip.Trigger>
					<Tooltip.Content>
						<p class="text-xs">Sign out</p>
					</Tooltip.Content>
				</Tooltip.Root>
			</Tooltip.Provider>
		</div>
	{:else}
		<Button variant="ghost" size="sm" href="/login">
			<UserIcon data-icon="inline-start" />
			Sign in
		</Button>
	{/if}
</header>
