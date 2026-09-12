<script lang="ts">
	import "./layout.css";
	import favicon from "$lib/assets/favicon.svg";
	import AppSidebar from "$lib/components/AppSidebar.svelte";
	import Topbar from "$lib/components/Topbar.svelte";
	import * as Sidebar from "$lib/components/ui/sidebar";
	import { Toaster } from "$lib/components/ui/sonner";
	import { ModeWatcher } from "mode-watcher";
	import { auth } from "$lib/stores/auth.svelte";
	import { status } from "$lib/api/client";
	import { onMount } from "svelte";
	import { page } from "$app/stores";

	let { children } = $props();
	let uptime = $state(0);

	const isAuthPage = $derived($page.url.pathname === "/login" || $page.url.pathname === "/setup");

	$effect(() => {
		if (isAuthPage) return;

		let active = true;
		async function pollStatus() {
			try {
				const s = await status();
				if (active) uptime = s.uptime_secs;
			} catch {
				// daemon unreachable — leave uptime as-is
			}
		}

		pollStatus();
		const interval = setInterval(pollStatus, 30_000);
		return () => {
			active = false;
			clearInterval(interval);
		};
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Lanforge</title>
</svelte:head>

<ModeWatcher defaultMode="system" />

{#if isAuthPage}
	{@render children()}
{:else}
	<Sidebar.Provider>
		<AppSidebar />
		<Sidebar.Inset>
			<Topbar {uptime} />
			<main class="flex flex-1 flex-col gap-4 sm:gap-6 p-3 sm:p-6 w-full max-w-full min-w-0 overflow-x-hidden">
				{@render children()}
			</main>
		</Sidebar.Inset>
	</Sidebar.Provider>
{/if}

<Toaster richColors />
