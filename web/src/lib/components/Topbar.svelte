<script lang="ts">
	import * as Sidebar from "$lib/components/ui/sidebar";
	import { Badge } from "$lib/components/ui/badge";
	import { Button } from "$lib/components/ui/button";
	import * as Tooltip from "$lib/components/ui/tooltip";
	import { auth } from "$lib/stores/auth.svelte";
	import { goto } from "$app/navigation";
	import SunIcon from "@lucide/svelte/icons/sun";
	import MoonIcon from "@lucide/svelte/icons/moon";
	import LogOutIcon from "@lucide/svelte/icons/log-out";
	import UserIcon from "@lucide/svelte/icons/user";
	import { mode, toggleMode } from "mode-watcher";

	let { uptime = $bindable(0) }: { uptime?: number } = $props();

	const isDark = $derived(mode.current === "dark");

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

	<!-- Daemon Status Indicator -->
	<Tooltip.Provider>
		<Tooltip.Root>
			<Tooltip.Trigger>
				<div class="flex items-center gap-1.5">
					<span
						class={[
							"size-2 rounded-full",
							uptime > 0
								? "bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]"
								: "bg-zinc-600",
						].join(" ")}
					></span>
					<span class="text-muted-foreground hidden text-xs sm:block">
						{uptime > 0 ? "Live" : "Offline"}
					</span>
				</div>
			</Tooltip.Trigger>
			<Tooltip.Content>
				<p class="text-xs">
					{uptime > 0
						? "Daemon active & connected"
						: "Daemon offline"}
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

	<!-- Right utilities -->
	<div class="ml-auto flex items-center gap-2">
		<!-- Dark mode toggle -->
		<Button variant="ghost" size="icon" onclick={toggleMode}>
			{#if isDark}
				<SunIcon class="size-4" />
			{:else}
				<MoonIcon class="size-4" />
			{/if}
			<span class="sr-only">Toggle theme</span>
		</Button>

		<!-- User badge / logout dropdown placeholder -->
		<div class="flex items-center gap-2 pl-2">
			<div
				class="bg-primary/10 flex size-7 items-center justify-center rounded-full"
			>
				<UserIcon class="text-primary size-4" />
			</div>
			<div class="hidden flex-col sm:flex">
				<span class="text-xs font-semibold leading-tight"
					>{auth.user?.username ?? "ferrahwolfeh"}</span
				>
				<span class="text-muted-foreground text-[10px] uppercase"
					>{auth.user?.role ?? "Admin"}</span
				>
			</div>

			<Button
				variant="ghost"
				size="icon"
				onclick={handleLogout}
				title="Log out"
			>
				<LogOutIcon class="size-4" />
			</Button>
		</div>
	</div>
</header>
